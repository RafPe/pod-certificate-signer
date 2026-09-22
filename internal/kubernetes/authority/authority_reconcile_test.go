package authority

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
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

// The reload burst a rotation produces is consumed before the retries run, so
// when those retries are exhausted no further filesystem event is coming: the
// CA is stuck on the old material until the process restarts. The periodic
// reconciliation is what recovers it. This is the direct regression test for
// the defect, and it can only be written at the watchLoop seam, because writing
// a good CA to disk is itself an event everywhere else.
func TestReconcileTickRecoversAFailedReloadWithoutAnEvent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clock := newFakeClock()
		ca, dir := newTestCA(t, clock)
		ca.reloadAttempts = 3

		// Spend the whole retry budget on unloadable material, exactly as the
		// event path would have, and let the failure streak cross into NotReady.
		nonCA, err := testutil.NewNonCA("not-a-ca.example.org", time.Hour)
		if err != nil {
			t.Fatalf("generate non-CA: %v", err)
		}
		if _, _, err := nonCA.WriteFiles(dir); err != nil {
			t.Fatalf("write non-CA files: %v", err)
		}
		if _, err := ca.reloadWithRetry(t.Context(), log.FromContext(t.Context())); err == nil {
			t.Fatal("reloadWithRetry() = nil, want error for a permanently unloadable CA")
		}
		// The health clock is the CA's own nowFunc, not bubble time, so the
		// grace period is crossed by advancing it rather than by sleeping.
		// Sleeping here would also fire ticks and add failures.
		clock.advance(reloadFailureGracePeriod)
		if err := ca.Healthy(); err == nil {
			t.Fatal("Healthy() = nil after an exhausted retry budget past the grace period, want an error")
		}

		// Good material lands on disk before the loop starts, so no event of
		// any kind is delivered for it.
		rotated := writeCA(t, dir, "recovered-ca.example.org", 24*time.Hour)

		notify, _, stop := runWatchLoop(t, ca)
		defer stop()

		// Past the first production tick (the half interval keeps a tick that
		// lands at the same fake instant as the sleep unambiguously before
		// it): the tick must have reloaded.
		time.Sleep(ca.reconcileInterval + ca.reconcileInterval/2)
		synctest.Wait()
		select {
		case <-notify:
		default:
			t.Fatal("the periodic reconciliation did not reload the CA within one interval")
		}

		if got := parseChain(t, ca.TrustBundlePEM()); !got[0].Equal(rotated.Cert) {
			t.Error("the current CA must be the recovered certificate after a reconcile tick")
		}
		// The streak is cleared by a successful reload, so the replica rejoins
		// the Service without needing a restart. The clock is still well past
		// the grace period, so this can only be the streak resetting.
		if err := ca.Healthy(); err != nil {
			t.Errorf("Healthy() after a successful reconcile tick = %v, want nil", err)
		}
	})
}

// A tick must notify consumers when, and only when, the CA material actually
// changed: an unchanged tick that notified would republish the
// ClusterTrustBundle every interval for nothing, and a changed tick that stayed
// quiet would leave pods trusting a bundle without the signing CA.
func TestReconcileTickNotifiesOnlyWhenTheCAChanges(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ca, dir := newTestCA(t, newFakeClock())
		interval := ca.reconcileInterval

		notify, _, stop := runWatchLoop(t, ca)
		defer stop()

		// Ten whole ticks over unchanged material must produce nothing. The
		// half interval added here offsets the phase for the rest of the test,
		// so the whole-interval sleeps below land between ticks rather than
		// exactly on one.
		time.Sleep(10*interval + interval/2)
		synctest.Wait()
		select {
		case <-notify:
			t.Fatal("a reconcile tick over unchanged CA material must not notify")
		default:
		}

		// Rotating the material must produce exactly one notification on the
		// next tick. This also proves the ticker was live throughout the quiet
		// period above, rather than silent because it had stopped.
		rotated := writeCA(t, dir, "ca-2.example.org", 24*time.Hour)
		time.Sleep(interval)
		synctest.Wait()
		select {
		case <-notify:
		default:
			t.Fatal("the reconcile tick did not notify on a changed CA")
		}
		if got := parseChain(t, ca.TrustBundlePEM()); !got[0].Equal(rotated.Cert) {
			t.Fatal("the current CA must be the rotated certificate after a reconcile tick")
		}

		// Every later tick re-reads the same material, and must stay quiet.
		time.Sleep(10 * interval)
		synctest.Wait()
		select {
		case <-notify:
			t.Fatal("a reconcile tick must not notify again once the CA has settled")
		default:
		}
	})
}

// An fsnotify error (an inotify queue overflow, say) is exactly the case where
// events are being dropped, so the ticker must keep running after one rather
// than the loop being wedged by it.
func TestReconcileTickSurvivesAWatcherError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ca, dir := newTestCA(t, newFakeClock())

		notify, errs, stop := runWatchLoop(t, ca)
		defer stop()

		// The loop is the only receiver, so the send completing proves the
		// error was consumed. Bounded on fake time so a loop that stopped
		// reading errs fails the test instead of hanging while the ticker
		// keeps fake time moving.
		select {
		case errs <- errors.New("inotify: queue or buffer overflow"):
		case <-time.After(time.Second):
			t.Fatal("the watch loop did not consume the watcher error")
		}

		rotated := writeCA(t, dir, "ca-2.example.org", 24*time.Hour)
		time.Sleep(ca.reconcileInterval + ca.reconcileInterval/2)
		synctest.Wait()
		select {
		case <-notify:
		default:
			t.Fatal("the reconcile tick stopped running after a watcher error")
		}
		if got := parseChain(t, ca.TrustBundlePEM()); !got[0].Equal(rotated.Cert) {
			t.Error("the current CA must be the rotated certificate after a reconcile tick")
		}
	})
}

// The ticker must not outlive the loop: cancelling the context has to return
// promptly and stop reloading.
func TestWatchLoopStopsTheReconcileTickerOnContextCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ca, _ := newTestCA(t, newFakeClock())

		ctx, cancel := context.WithCancel(t.Context())
		events := make(chan fsnotify.Event) // open, never sends
		errs := make(chan error)            // open, never sends
		done := make(chan error, 1)
		go func() { done <- ca.watchLoop(ctx, log.FromContext(ctx), events, errs, nil) }()

		// Let one tick land, so cancellation races a running ticker rather
		// than a loop that has not started yet.
		time.Sleep(ca.reconcileInterval + ca.reconcileInterval/2)
		synctest.Wait()
		cancel()

		// A bound well under one interval: a loop that ignored cancellation
		// would otherwise keep ticking on fake time forever, and the bubble
		// would happily advance through every tick. Fake time makes this
		// deadline exact, not a guess about machine speed.
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("watchLoop() = %v, want nil on context cancellation", err)
			}
		case <-time.After(time.Second):
			t.Fatal("watchLoop did not return within a second of context cancellation")
		}
	})
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
	synctest.Test(t, func(t *testing.T) {
		clock := newFakeClock()
		ca, dir := newTestCA(t, clock)

		nonCA, err := testutil.NewNonCA("not-a-ca.example.org", time.Hour)
		if err != nil {
			t.Fatalf("generate non-CA: %v", err)
		}
		if _, _, err := nonCA.WriteFiles(dir); err != nil {
			t.Fatalf("write non-CA files: %v", err)
		}

		_, _, stop := runWatchLoop(t, ca)
		defer stop()

		// Exactly reloadFailureThreshold ticks, one failure each.
		time.Sleep(time.Duration(reloadFailureThreshold)*ca.reconcileInterval + ca.reconcileInterval/2)
		synctest.Wait()
		if got := ca.failureCount(); got != reloadFailureThreshold {
			t.Fatalf("reload failures after %d ticks = %d, want %d (one failure per tick)",
				reloadFailureThreshold, got, reloadFailureThreshold)
		}

		// Inside the grace period the last-good CA keeps signing, so the
		// replica stays ready; past it, readiness must fail. The health clock
		// is advanced rather than slept on: bubble time would fire more ticks
		// and break the exact failure count above.
		if err := ca.Healthy(); err != nil {
			t.Errorf("Healthy() inside the grace period = %v, want nil", err)
		}
		clock.advance(reloadFailureGracePeriod)
		if err := ca.Healthy(); err == nil {
			t.Error("Healthy() = nil after tick-only failures past the grace period, want an error")
		}
	})
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
