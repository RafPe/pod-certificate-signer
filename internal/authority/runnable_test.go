package authority

import (
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// Compile-time guarantees that the watcher opts into controller-runtime's
// leader-election routing explicitly, rather than relying on the implicit
// "not a LeaderElectionRunnable ⇒ leader-gated" fallback.
var (
	_ manager.Runnable               = (*Watcher)(nil)
	_ manager.LeaderElectionRunnable = (*Watcher)(nil)
)

// The CA watcher runs on every replica, so a standby keeps its in-memory CA
// current and never signs or publishes with a stale CA after promotion.
// controller-runtime confines a runnable to the leader unless it reports
// NeedLeaderElection() == false.
func TestWatcherRunsOnEveryReplica(t *testing.T) {
	if NewWatcher(nil, nil).NeedLeaderElection() {
		t.Error("Watcher is leader-gated; want it to run on every replica so standby CAs stay current")
	}
}
