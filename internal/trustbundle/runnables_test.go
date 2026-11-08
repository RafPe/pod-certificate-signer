package trustbundle

import (
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// Compile-time guarantees that the publisher opts into controller-runtime's
// leader-election routing explicitly, rather than relying on the implicit
// "not a LeaderElectionRunnable ⇒ leader-gated" fallback.
var (
	_ manager.Runnable               = (*Publisher)(nil)
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

// The ClusterTrustBundle publisher is restricted to the elected leader, so
// exactly one replica writes the shared resource.
func TestPublisherIsLeaderGated(t *testing.T) {
	if !leaderGated(NewPublisher(nil, "example.org/signer", nil)) {
		t.Error("Publisher is not leader-gated; want ClusterTrustBundle writes confined to the leader")
	}
}
