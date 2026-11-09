package authority

import (
	"context"
	"fmt"
)

// Watcher is the manager runnable that keeps the in-memory CA in step with
// its files: it runs [CertificateAuthority.Watch] until the manager stops. It
// runs on every replica, independent of leader election, so that a standby
// keeps its CA current and never signs or publishes with stale material
// immediately after being promoted to leader.
type Watcher struct {
	ca     *CertificateAuthority
	notify chan<- struct{}
}

// NewWatcher returns the runnable that watches ca's files, sending on notify
// (non-blocking; nil for none) whenever a reload changed the material.
func NewWatcher(ca *CertificateAuthority, notify chan<- struct{}) *Watcher {
	return &Watcher{ca: ca, notify: notify}
}

// Start blocks watching the CA files until ctx is canceled. A failed watch is
// fatal: without it CA rotations would silently never be observed.
func (w *Watcher) Start(ctx context.Context) error {
	if err := w.ca.Watch(ctx, w.notify); err != nil {
		return fmt.Errorf("ca-watcher: %w", err)
	}
	return nil
}

// NeedLeaderElection reports false so the CA watcher runs on every replica.
func (*Watcher) NeedLeaderElection() bool { return false }
