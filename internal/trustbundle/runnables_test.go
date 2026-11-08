package trustbundle

import (
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// Compile-time guarantees that both runnables opt into controller-runtime's
// leader-election routing explicitly, rather than relying on the implicit
// "not a LeaderElectionRunnable ⇒ leader-gated" fallback.
var (
	_ manager.Runnable               = (*CAWatcher)(nil)
	_ manager.Runnable               = (*Publisher)(nil)
	_ manager.LeaderElectionRunnable = (*CAWatcher)(nil)
	_ manager.LeaderElectionRunnable = (*Publisher)(nil)
)

// leaderGated mirrors how controller-runtime's runnable group routes a
// Runnable: a runnable that does not implement LeaderElectionRunnable, or that
// reports NeedLeaderElection() == true, is confined to the leader-election
// group. Encoding the real rule here means the test guards the behaviour, not
// just a literal return value.
func leaderGated(r manager.Runnable) bool {
	ler, ok := r.(manager.LeaderElectionRunnable)
	return !ok || ler.NeedLeaderElection()
}

// The CA file watcher runs on every replica (so standby replicas keep their
// in-memory CA current and never sign or publish with a stale CA after
// promotion), while the ClusterTrustBundle publisher remains restricted to the
// elected leader.
func TestRunnablesLeaderElection(t *testing.T) {
	watcher, publisher := NewRunnables(nil, "example.org/signer", nil)

	if leaderGated(watcher) {
		t.Error("CAWatcher is leader-gated; want it to run on every replica so standby CAs stay current")
	}
	if !leaderGated(publisher) {
		t.Error("Publisher is not leader-gated; want ClusterTrustBundle writes confined to the leader")
	}
}
