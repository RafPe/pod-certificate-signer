---
status: accepted
date: 2026-10-12
decision-makers: RafPe
---

# Release the leader Lease on a voluntary shutdown

## Context and Problem Statement

The manager was built without `LeaderElectionReleaseOnCancel`, so a leader
shutting down left its Lease behind. A follower cannot acquire a Lease it still
sees held, so it waits out controller-runtime's default `LeaseDuration` of 15
seconds and then observes the expiry on its own jittered `RetryPeriod`.

Two runnables are leader-gated, not one. The ClusterTrustBundle publisher
reports `NeedLeaderElection() == true` explicitly
(`cmd/podcertificate-signer/main.go`), and the `PodCertificateRequest`
reconciler is leader-gated by default — `SetupWithManager` never sets
`NeedLeaderElection` and controller-runtime resolves a nil value to true. So the
15 second window is a window in which **no replica signs certificates**, not
merely one without a trust-bundle publisher. Requests raised in it are served
late rather than failed, so the cost is issuance latency on the critical path of
every rolling upgrade.

Measured on a two-replica Kind deployment, installed the way
`test/e2e/ha_test.go` installs it, with a separate image tag per arm so each ran
its own binary:

| | Off (previous) | On |
| --- | --- | --- |
| Pod-delete handover, median of 4 trials | 16.3s (14.4–16.9s) | 1.2s (1.0–1.7s) |
| Rolling restart, cumulative time with no live holder | ~15.2s | ~1.9s |

The distributions do not overlap. The ~1.2s floor is client-go's `RetryPeriod`
polling, which this project does not control. Every trial of the on arm showed
client-go's release signature (`holderIdentity: ""`,
`leaseDurationSeconds: 1`); no trial of the off arm did.

The hazard the option carries is named by client-go: *"you must ensure all code
guarded by this lease has successfully completed prior to cancelling the
context, or you may have two processes simultaneously acting on the critical
path."* controller-runtime defers `leaderElectionCancel()` until every
`runnables.*.StopAndWait` has returned, and `mgr.Start` is the last statement in
`main()`, so the binary meets that — but only within `GracefulShutdownTimeout`
(30 second default). Past that deadline the deferred release fires with
leader-gated code possibly still live.

One leader-gated path did not derive its duration from a context deadline. The
publisher retried through `retry.OnError`, whose predicate returned true for
every error and whose sleeps are a bare `time.Sleep`, so a publish in flight at
SIGTERM retried `context.Canceled` through the whole backoff: measured at 5
attempts over 7.6–8.1s. With the option off that delay was invisible, spent
inside a 15 second window a follower was waiting out anyway. With the option on
it becomes the dominant term in the shutdown path, and the only thing that can
push against the 30 second precondition.

## Decision

Set `LeaderElectionReleaseOnCancel: true` in `managerOptions`, and make the
publisher's retry predicate stop on a canceled context
(`!errors.Is(err, context.Canceled)`, and `context.DeadlineExceeded`).

Two preconditions come with it, and they are the durable part of this record:

**`mgr.Start` stays the last statement in `main()`.** The release is only safe
if the process exits as soon as the manager stops.

**Every leader-gated runnable's shutdown is bounded by its context.** The
guarantee that the Lease is released only after all runnables return holds only
within `GracefulShutdownTimeout`. An unbounded retry added to a leader-gated
runnable would break this silently — no test fails, the Lease is just released
while the old leader is still writing.

The predicate is the narrower of the two available fixes; switching to
`wait.ExponentialBackoffWithContext` would also interrupt a sleep already in
progress. It was not needed: stopping before the next sleep collapses the
measured ~8s to ~0.

## Consequences

**Positive.** Voluntary handover drops from ~16s to ~1.2s, and a rolling upgrade
spends ~1.9s rather than ~15.2s with no leader signing. The e2e handoff bound
moves from 90s to 30s, so a regression in handover is caught rather than hidden.

**Neutral.** Involuntary loss is unchanged: node failure, SIGKILL and OOM still
fall back to `LeaseDuration` expiry, because only a voluntary shutdown releases
the Lease. Nothing about issuance, the identity model or the trust boundary
moves. A publish abandoned at shutdown still counts as `{result="failed"}` on
M6, unchanged from before this record; an alert on that counter should be
rate-based rather than a threshold on the total.

**Negative.** The binary now depends on a precondition that a future change can
break without any test noticing, which is why it is written next to the option
and recorded here. A released Lease also transiently reads an empty
`holderIdentity`, which e2e helpers see; their `Eventually` absorbs it as one
more poll.

## Verification

`TestManagerOptionsReleasesLeaseOnCancel` pins the option, which nothing did
before — the previous `false` was not just undocumented but unpinned.
`TestReconcileStopsRetryingOnCancel` runs inside a `testing/synctest` bubble
with the production backoff and asserts the publisher's reconcile returns well
inside the first backoff step after cancellation, so a predicate that retried
the context error again would fail it.

## Alternatives Considered

**Leave it off.** Rejected. The cost is paid on every rolling upgrade, and it is
signing latency rather than housekeeping.

**Shorten `LeaseDuration` instead.** Rejected: it trades the same window for
more renewal traffic and a higher chance of a spurious failover under API
latency, and it does nothing for the voluntary case specifically.

**Turn the option on without fixing the retry.** Rejected. It would still have
been a net win — ~8s beats ~16s — but it leaves the one leader-guarded path
whose duration is not derived from a context deadline, and it worsens exactly
when the API server is degraded, which is when fast handover matters most.

## More Information

- Issue [#122](https://github.com/rafpe/pod-certificate-signer/issues/122)
  carries the full measurement, including per-trial numbers and the shutdown-log
  ordering that confirms the release lands after the last runnable returns.
- controller-runtime v0.25.1 `pkg/manager/internal.go` (`engageStopProcedure`)
  for the deferral; `k8s.io/client-go/tools/leaderelection` for the hazard
  comment and `tryRelease`.
