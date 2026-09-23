package authority

import (
	"context"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// runWatchLoop starts watchLoop inside the caller's synctest bubble with event
// and error channels that never fire on their own, so only the reconcile ticker
// (or a send by the test on errs) can start a reload. The returned stop
// function cancels the loop and asserts that it returned nil within a fake
// second; it is the only check on the loop's return value, so defer it.
//
// Only call this from inside synctest.Test: outside a bubble the production
// reconcile interval makes every tick a real minute.
func runWatchLoop(t *testing.T, ca *CertificateAuthority) (chan struct{}, chan error, func()) {
	t.Helper()

	events := make(chan fsnotify.Event) // open, never sends
	errs := make(chan error)            // open unless the test sends
	notify := make(chan struct{}, 1)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- ca.watchLoop(ctx, log.FromContext(ctx), events, errs, notify) }()

	return notify, errs, func() {
		t.Helper()
		cancel()
		// Bounded on fake time: a loop that ignored cancellation would keep
		// ticking and the bubble would advance through every tick forever
		// instead of reporting a deadlock. One fake second is deterministic and
		// far shorter than a reconcile interval.
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("watchLoop() = %v, want nil on context cancellation", err)
			}
		case <-time.After(time.Second):
			t.Error("watchLoop did not return within a fake second of context cancellation")
		}
	}
}
