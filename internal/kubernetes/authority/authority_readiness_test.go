package authority

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
)

// fakeClock is a manually advanced clock, so the readiness grace period can be
// exercised without sleeping. Its Now method is safe for concurrent use.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

// newTestCA returns a CA backed by freshly generated material on disk, wired to
// the given clock for its health bookkeeping, along with the directory holding
// that material so tests can rewrite it.
func newTestCA(t *testing.T, clock *fakeClock) (*CertificateAuthority, string) {
	t.Helper()

	dir := t.TempDir()
	writeCA(t, dir, "ca.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ca.nowFunc = clock.Now

	return ca, dir
}

// Readiness must tolerate a transient CA reload failure: the last-good CA is
// retained and signing keeps working, so pulling the replica out of the Service
// on the first blip only causes flapping. Readiness fails only once the CA has
// been unloadable persistently, which is both at least 3 consecutive failed
// reload attempts and at least 10 minutes since the first of them.
func TestHealthyGracePeriodForReloadFailures(t *testing.T) {
	reloadErr := errors.New("failed to load key pair")

	tests := []struct {
		name         string
		failures     int
		elapsed      time.Duration
		thenSucceeds bool
		wantHealthy  bool
	}{
		{
			name:        "single transient failure stays ready",
			failures:    1,
			wantHealthy: true,
		},
		{
			name:        "single failure long past the grace period stays ready",
			failures:    1,
			elapsed:     30 * time.Minute,
			wantHealthy: true,
		},
		{
			name:        "threshold reached within the grace period stays ready",
			failures:    3,
			elapsed:     5 * time.Minute,
			wantHealthy: true,
		},
		{
			name:        "threshold reached and grace period elapsed fails readiness",
			failures:    3,
			elapsed:     10 * time.Minute,
			wantHealthy: false,
		},
		{
			name:        "sustained failures well past the grace period fail readiness",
			failures:    5,
			elapsed:     30 * time.Minute,
			wantHealthy: false,
		},
		{
			name:         "successful reload resets the failure streak",
			failures:     5,
			elapsed:      30 * time.Minute,
			thenSucceeds: true,
			wantHealthy:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newFakeClock()
			ca, _ := newTestCA(t, clock)

			// Record the first failure, let the clock run, then record the
			// remaining ones: the elapsed guard must be measured from the
			// first failure and must not be reset by later failures.
			if tt.failures > 0 {
				ca.recordReloadResult(reloadErr)
				clock.advance(tt.elapsed)
				for i := 1; i < tt.failures; i++ {
					ca.recordReloadResult(reloadErr)
				}
			}
			if tt.thenSucceeds {
				ca.recordReloadResult(nil)
			}

			err := ca.Healthy()
			if gotHealthy := err == nil; gotHealthy != tt.wantHealthy {
				t.Errorf("Healthy() after %d failure(s) over %v = %v, want healthy = %t",
					tt.failures, tt.elapsed, err, tt.wantHealthy)
			}
		})
	}
}

// The grace period must be reachable in production, not just by poking the
// health bookkeeping directly: a CA that stays unloadable across a full retry
// budget must eventually fail readiness once the grace period elapses.
func TestPersistentlyUnloadableCAEventuallyFailsReadiness(t *testing.T) {
	clock := newFakeClock()
	ca, dir := newTestCA(t, clock)
	ca.reloadAttempts = 3
	ca.reloadBackoff = time.Millisecond

	// Permanently bad material on disk: a non-CA certificate.
	nonCA, err := testutil.NewNonCA("not-a-ca.example.org", time.Hour)
	if err != nil {
		t.Fatalf("generate non-CA: %v", err)
	}
	if _, _, err := nonCA.WriteFiles(dir); err != nil {
		t.Fatalf("write non-CA files: %v", err)
	}

	ctx := context.Background()
	if err := ca.reloadWithRetry(ctx, log.FromContext(ctx)); err == nil {
		t.Fatal("reloadWithRetry() = nil, want error for a permanently unloadable CA")
	}

	// Still inside the grace window: the last-good CA keeps signing, so the
	// replica must stay ready.
	if err := ca.Healthy(); err != nil {
		t.Errorf("Healthy() immediately after a failed reload = %v, want nil", err)
	}

	clock.advance(10 * time.Minute)
	if err := ca.Healthy(); err == nil {
		t.Error("Healthy() = nil after the grace period elapsed, want an error")
	}
}

// A dead watcher is a real failure rather than a transient file blip: the CA
// can no longer observe rotations at all, so readiness must fail immediately
// without waiting out the reload grace period.
func TestHealthyFailsImmediatelyOnWatcherExit(t *testing.T) {
	clock := newFakeClock()
	ca, _ := newTestCA(t, clock)

	events := make(chan fsnotify.Event)
	errs := make(chan error) // open, never sends
	close(events)

	ctx := context.Background()
	done := make(chan error, 1)
	go func() { done <- ca.watchLoop(ctx, log.FromContext(ctx), events, errs, nil) }()

	select {
	case err := <-done:
		if !errors.Is(err, errWatchChannelClosed) {
			t.Fatalf("watchLoop() = %v, want %v", err, errWatchChannelClosed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchLoop did not return after the events channel closed")
	}

	// No clock advance: the watcher error is not subject to the grace period.
	if err := ca.Healthy(); !errors.Is(err, errWatchChannelClosed) {
		t.Errorf("Healthy() after the watcher exited = %v, want %v", err, errWatchChannelClosed)
	}
}
