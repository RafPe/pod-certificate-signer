package authority

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
)

// failureCount reads the reload failure streak under the health mutex, so tests
// can poll it without racing the watch loop.
func (ca *CertificateAuthority) failureCount() int {
	ca.healthMu.Lock()
	defer ca.healthMu.Unlock()

	return ca.reloadFailures
}

// startWatchLoop runs the watch loop with channels that never fire, which
// isolates the periodic reconciliation completely: nothing but the ticker can
// start a reload. It returns the notification channel and a stop function that
// cancels the loop and waits for it to return.
func startWatchLoop(t *testing.T, ca *CertificateAuthority) (chan struct{}, chan error, func()) {
	t.Helper()

	events := make(chan fsnotify.Event) // open, never sends
	errs := make(chan error)            // open, never sends
	notify := make(chan struct{}, 1)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ca.watchLoop(ctx, log.FromContext(ctx), events, errs, notify) }()

	return notify, errs, func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("watchLoop() = %v, want nil on context cancellation", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("watchLoop did not return after context cancellation")
		}
	}
}

// The reload burst a rotation produces is consumed before the retries run, so
// when those retries are exhausted no further filesystem event is coming: the
// CA is stuck on the old material until the process restarts. The periodic
// reconciliation is what recovers it. This is the direct regression test for
// the defect, and it can only be written at the watchLoop seam, because writing
// a good CA to disk is itself an event everywhere else.
func TestReconcileTickRecoversAFailedReloadWithoutAnEvent(t *testing.T) {
	clock := newFakeClock()
	ca, dir := newTestCA(t, clock)
	ca.reloadAttempts = 3
	ca.reloadBackoff = time.Millisecond
	ca.reconcileInterval = 20 * time.Millisecond

	// Spend the whole retry budget on unloadable material, exactly as the event
	// path would have, and let the failure streak cross into NotReady.
	nonCA, err := testutil.NewNonCA("not-a-ca.example.org", time.Hour)
	if err != nil {
		t.Fatalf("generate non-CA: %v", err)
	}
	if _, _, err := nonCA.WriteFiles(dir); err != nil {
		t.Fatalf("write non-CA files: %v", err)
	}

	ctx := context.Background()
	if _, err := ca.reloadWithRetry(ctx, log.FromContext(ctx)); err == nil {
		t.Fatal("reloadWithRetry() = nil, want error for a permanently unloadable CA")
	}
	clock.advance(reloadFailureGracePeriod)
	if err := ca.Healthy(); err == nil {
		t.Fatal("Healthy() = nil after an exhausted retry budget past the grace period, want an error")
	}

	// Good material lands on disk before the loop starts, so no event of any
	// kind is delivered for it.
	rotated := writeCA(t, dir, "recovered-ca.example.org", 24*time.Hour)

	notify, _, stop := startWatchLoop(t, ca)
	defer stop()

	select {
	case <-notify:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the periodic reconciliation to reload the CA")
	}

	if got := parseChain(t, ca.TrustBundlePEM()); !got[0].Equal(rotated.Cert) {
		t.Error("the current CA must be the recovered certificate after a reconcile tick")
	}
	// The streak is cleared by a successful reload, so the replica rejoins the
	// Service without needing a restart. The clock is still well past the grace
	// period, so this can only be the streak resetting.
	if err := ca.Healthy(); err != nil {
		t.Errorf("Healthy() after a successful reconcile tick = %v, want nil", err)
	}
}

// A tick must notify consumers when, and only when, the CA material actually
// changed: an unchanged tick that notified would republish the
// ClusterTrustBundle every interval for nothing, and a changed tick that stayed
// quiet would leave pods trusting a bundle without the signing CA.
func TestReconcileTickNotifiesOnlyWhenTheCAChanges(t *testing.T) {
	clock := newFakeClock()
	ca, dir := newTestCA(t, clock)
	ca.reconcileInterval = 20 * time.Millisecond

	notify, _, stop := startWatchLoop(t, ca)
	defer stop()

	// Several intervals over unchanged material must produce nothing.
	select {
	case <-notify:
		t.Fatal("a reconcile tick over unchanged CA material must not notify")
	case <-time.After(300 * time.Millisecond):
	}

	// Rotating the material must produce exactly one notification. This also
	// proves the ticker was live throughout the quiet period above, rather than
	// silent because it had stopped.
	rotated := writeCA(t, dir, "ca-2.example.org", 24*time.Hour)
	select {
	case <-notify:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the reconcile tick to notify on a changed CA")
	}
	if got := parseChain(t, ca.TrustBundlePEM()); !got[0].Equal(rotated.Cert) {
		t.Fatal("the current CA must be the rotated certificate after a reconcile tick")
	}

	// Every later tick re-reads the same material, and must stay quiet.
	select {
	case <-notify:
		t.Fatal("a reconcile tick must not notify again once the CA has settled")
	case <-time.After(300 * time.Millisecond):
	}
}

// An fsnotify error (an inotify queue overflow, say) is exactly the case where
// events are being dropped, so the ticker must keep running after one rather
// than the loop being wedged by it.
func TestReconcileTickSurvivesAWatcherError(t *testing.T) {
	clock := newFakeClock()
	ca, dir := newTestCA(t, clock)
	ca.reconcileInterval = 20 * time.Millisecond

	notify, errs, stop := startWatchLoop(t, ca)
	defer stop()

	select {
	case errs <- errors.New("inotify: queue or buffer overflow"):
	case <-time.After(5 * time.Second):
		t.Fatal("the watch loop did not consume the watcher error")
	}

	rotated := writeCA(t, dir, "ca-2.example.org", 24*time.Hour)
	select {
	case <-notify:
	case <-time.After(10 * time.Second):
		t.Fatal("the reconcile tick stopped running after a watcher error")
	}
	if got := parseChain(t, ca.TrustBundlePEM()); !got[0].Equal(rotated.Cert) {
		t.Error("the current CA must be the rotated certificate after a reconcile tick")
	}
}

// The ticker must not outlive the loop: cancelling the context has to return
// promptly and stop reloading.
func TestWatchLoopStopsTheReconcileTickerOnContextCancel(t *testing.T) {
	clock := newFakeClock()
	ca, _ := newTestCA(t, clock)
	ca.reconcileInterval = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan fsnotify.Event) // open, never sends
	errs := make(chan error)            // open, never sends

	done := make(chan error, 1)
	go func() { done <- ca.watchLoop(ctx, log.FromContext(ctx), events, errs, nil) }()

	// Let at least one tick land, so cancellation races a running ticker rather
	// than a loop that has not started yet.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("watchLoop() = %v, want nil on context cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchLoop did not return promptly after context cancellation")
	}
}

// A tick makes a single reload attempt, not a full retry burst: retries exist to
// ride out the torn state a rotation briefly leaves on disk, which a tick is not
// correlated with, and the next tick is itself the retry. Pinning it keeps the
// failure accounting honest (one tick, one failure) and bounds the log stream on
// a permanently bad CA.
func TestReconcileOnceRecordsASingleFailure(t *testing.T) {
	clock := newFakeClock()
	ca, dir := newTestCA(t, clock)
	if ca.reloadAttempts < 2 {
		t.Fatalf("reloadAttempts = %d, the test needs a retry budget greater than one", ca.reloadAttempts)
	}

	nonCA, err := testutil.NewNonCA("not-a-ca.example.org", time.Hour)
	if err != nil {
		t.Fatalf("generate non-CA: %v", err)
	}
	if _, _, err := nonCA.WriteFiles(dir); err != nil {
		t.Fatalf("write non-CA files: %v", err)
	}

	ctx := context.Background()
	ca.reconcileOnce(log.FromContext(ctx), nil, "test")

	if got := ca.failureCount(); got != 1 {
		t.Errorf("reload failures after one reconcile pass = %d, want 1 (a single attempt, not a retry burst)", got)
	}
}

// The readiness contract must hold on tick-only failures too: a CA that stays
// unloadable with no filesystem event ever arriving must still cross the
// threshold and fail readiness once the grace period elapses.
func TestTickOnlyFailuresCrossTheReadinessThreshold(t *testing.T) {
	clock := newFakeClock()
	ca, dir := newTestCA(t, clock)
	ca.reconcileInterval = 20 * time.Millisecond

	nonCA, err := testutil.NewNonCA("not-a-ca.example.org", time.Hour)
	if err != nil {
		t.Fatalf("generate non-CA: %v", err)
	}
	if _, _, err := nonCA.WriteFiles(dir); err != nil {
		t.Fatalf("write non-CA files: %v", err)
	}

	_, _, stop := startWatchLoop(t, ca)
	defer stop()

	deadline := time.After(10 * time.Second)
	for ca.failureCount() < reloadFailureThreshold {
		select {
		case <-deadline:
			t.Fatalf("reload failures reached %d on ticks alone, want at least %d",
				ca.failureCount(), reloadFailureThreshold)
		case <-time.After(5 * time.Millisecond):
		}
	}

	// Inside the grace period the last-good CA keeps signing, so the replica
	// stays ready; past it, readiness must fail.
	if err := ca.Healthy(); err != nil {
		t.Errorf("Healthy() inside the grace period = %v, want nil", err)
	}
	clock.advance(reloadFailureGracePeriod)
	if err := ca.Healthy(); err == nil {
		t.Error("Healthy() = nil after tick-only failures past the grace period, want an error")
	}
}

// A rotation landing between New's initial load and the watch being registered
// produces no observable event, so Watch reconciles once on startup. Without it
// the stale CA would persist until the first tick.
func TestWatchReconcilesOnStartup(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "ca-1.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Rotate before the watcher exists, so no event can ever be delivered for
	// it, and leave the reconcile interval at its production value so only the
	// startup pass can observe the change.
	rotated := writeCA(t, dir, "ca-2.example.org", 24*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	notify := make(chan struct{}, 1)
	watchDone := make(chan error, 1)
	go func() { watchDone <- ca.Watch(ctx, notify) }()

	select {
	case <-notify:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the startup reconciliation to reload the CA")
	}
	if got := parseChain(t, ca.TrustBundlePEM()); !got[0].Equal(rotated.Cert) {
		t.Error("the current CA must be the rotated certificate after the startup reconciliation")
	}

	cancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not return after context cancellation")
	}
}
