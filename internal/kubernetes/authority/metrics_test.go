package authority

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/go-logr/logr"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/metrics"
)

// Every reload pass must land on exactly one of the three results the callers
// already branch on, so the counter cannot disagree with the logs.
func TestReconcileOnceCountsReloadResults(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "ca.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A pass over material that has not moved.
	before := reloadCounts()
	ca.reconcileOnce(logr.Discard(), nil, "test")
	assertReloadDelta(t, before, map[string]float64{metrics.ResultUnchanged: 1})

	// A rotation.
	writeCA(t, dir, "ca-rotated.example.org", 24*time.Hour)
	before = reloadCounts()
	ca.reconcileOnce(logr.Discard(), nil, "test")
	assertReloadDelta(t, before, map[string]float64{metrics.ResultChanged: 1})

	// Material that cannot be loaded at all.
	if err := os.WriteFile(dir+"/tls.crt", []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatalf("write bad cert: %v", err)
	}
	before = reloadCounts()
	ca.reconcileOnce(logr.Discard(), nil, "test")
	assertReloadDelta(t, before, map[string]float64{metrics.ResultFailed: 1})
}

// reloadWithRetry records every attempt, not just the burst, because a CA that
// stays unloadable must be able to cross the readiness threshold without
// another filesystem event. The counter is named _attempts_ for exactly this
// reason, and this pins it.
func TestReloadWithRetryCountsEveryAttempt(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "ca.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ca.reloadAttempts = 3
	ca.reloadBackoff = time.Millisecond

	if err := os.WriteFile(dir+"/tls.crt", []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatalf("write bad cert: %v", err)
	}

	before := reloadCounts()
	if _, err := ca.reloadWithRetry(context.Background(), logr.Discard()); err == nil {
		t.Fatal("reloadWithRetry() error = nil, want the reload to fail")
	}
	assertReloadDelta(t, before, map[string]float64{metrics.ResultFailed: 3})
}

// The last-success clock must be seeded by the load in New. Nothing else
// records a success until the watch startup reconcile, which runs after the
// manager starts and never at all if the watcher cannot be established - so an
// unseeded clock would make the "reloads have stopped" alert fire on every
// process start, and an alert that fires on every start gets silenced.
func TestNewSeedsTheLastSuccessClock(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "ca.example.org", 24*time.Hour)

	start := time.Now()
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	failures, lastSuccess := ca.ReloadHealth()
	if failures != 0 {
		t.Errorf("consecutive failures = %d on a fresh CA, want 0", failures)
	}
	if lastSuccess.Before(start) {
		t.Errorf("last success = %v, want a time at or after construction (%v)", lastSuccess, start)
	}
}

// The streak the readiness probe uses is the streak the gauge reports; they
// must not be two counts that can disagree.
func TestReloadHealthTracksTheFailureStreak(t *testing.T) {
	clock := newFakeClock()
	ca, dir := newTestCA(t, clock)

	if err := os.WriteFile(dir+"/tls.crt", []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatalf("write bad cert: %v", err)
	}
	ca.reconcileOnce(logr.Discard(), nil, "test")
	ca.reconcileOnce(logr.Discard(), nil, "test")

	failures, _ := ca.ReloadHealth()
	if failures != 2 {
		t.Errorf("consecutive failures = %d, want 2", failures)
	}

	// Recovering must clear the streak and move the clock, without a restart.
	writeCA(t, dir, "ca.example.org", 24*time.Hour)
	clock.advance(time.Minute)
	ca.reconcileOnce(logr.Discard(), nil, "test")

	failures, lastSuccess := ca.ReloadHealth()
	if failures != 0 {
		t.Errorf("consecutive failures = %d after a good reload, want 0", failures)
	}
	if !lastSuccess.Equal(clock.Now()) {
		t.Errorf("last success = %v, want the recovery time %v", lastSuccess, clock.Now())
	}
}

// The trust bundle gauge must count what the signer would publish: the current
// CA plus every retained previous one.
func TestTrustBundleSizeCountsRetainedCAs(t *testing.T) {
	dir := t.TempDir()
	kp := writeCA(t, dir, "ca.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key", WithMaxPreviousCertificates(2))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := ca.TrustBundleSize(); got != 1 {
		t.Errorf("trust bundle size = %d before any rotation, want 1", got)
	}
	if got := ca.CertificateNotAfter(); !got.Equal(kp.Cert.NotAfter) {
		t.Errorf("expiry = %v, want the loaded CA's NotAfter %v", got, kp.Cert.NotAfter)
	}

	rotated := writeCA(t, dir, "ca-rotated.example.org", 48*time.Hour)
	ca.reconcileOnce(logr.Discard(), nil, "test")

	if got := ca.TrustBundleSize(); got != 2 {
		t.Errorf("trust bundle size = %d after one rotation, want 2 (current plus the retained previous CA)", got)
	}
	if got := ca.CertificateNotAfter(); !got.Equal(rotated.Cert.NotAfter) {
		t.Errorf("expiry = %v, want the rotated CA's NotAfter %v", got, rotated.Cert.NotAfter)
	}
}

// reloadCounts snapshots the reload attempt counter for each result.
func reloadCounts() map[string]float64 {
	counts := make(map[string]float64, 3)
	for _, result := range []string{metrics.ResultChanged, metrics.ResultUnchanged, metrics.ResultFailed} {
		counts[result] = promtestutil.ToFloat64(metrics.CAReloadAttempts.WithLabelValues(result))
	}

	return counts
}

// assertReloadDelta checks how far each result moved since before, treating an
// unnamed result as expected not to have moved at all.
func assertReloadDelta(t *testing.T, before map[string]float64, want map[string]float64) {
	t.Helper()

	for result, gotAfter := range reloadCounts() {
		if got := gotAfter - before[result]; got != want[result] {
			t.Errorf("ca_reload_attempts_total{result=%q} moved by %v, want %v", result, got, want[result])
		}
	}
}
