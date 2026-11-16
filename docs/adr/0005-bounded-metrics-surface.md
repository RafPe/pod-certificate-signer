---
status: accepted
date: 2026-08-19
decision-makers: RafPe
---

# Expose a bounded metrics surface, and never label a metric with a per-request identity

## Context and Problem Statement

The signer exposes one custom metric: `ctb_publish_failures_total`
(`cmd/podcertificate-signer/main.go:407`, registered at `:90`). It carries no
application prefix, and being failure-only its `== 0` is ambiguous between
healthy, never-been-leader, and wedged. Everything else on `/metrics` comes from
controller-runtime.

The consequence is that the operationally interesting states are visible only in
logs. Two of them are outages an operator cannot see coming:

- **A CA that can no longer sign.** `Sign` refuses when
  `now + requestedDuration > ca.NotAfter` (`authority.go:275-277`) and the
  reconciler requeues silently and forever (`controller.go:318-320`). Pods sit
  in `ContainerCreating` with nothing on the request explaining why. #108 adds
  an event. Nothing makes the *approaching* condition alertable.
- **A reload loop that stopped.** `caReloadInterval` exists so a rotation the
  event path missed still converges (`authority.go:89-105`). A wedged ticker
  produces no failures, so any failure-based signal stays at zero forever.

It also produced a test failure. The e2e suite has no machine-readable
observable for CA state, so it greps controller logs in six places. When #104
changed the emission condition of one log line, the nightly tier went red — a
log-level change breaking a behavioural test. That is the wrong coupling.

The transport already exists: #82 built SecureServing with TokenReview and
SubjectAccessReview, the `metrics-reader` ClusterRole, and `metrics.insecure:
false` by default. What is missing is signal, not plumbing.

The hazard to avoid is equally clear. This signer issues **one
`PodCertificateRequest` per pod**, short-lived and garbage-collected. Prior art
on exactly this object shape is consistent: SPIRE puts no identity in any label;
Kubernetes' own CSR signing controller ships no custom metrics at all; and
cert-manager, which does label per object, has a public record of the results —
a stale series that kept an alert firing after a rename, a `path` label that
added two series per issuance, and a free-form `reason` label that emitted a
truncated HTTP response body as a label value.

## Decision

Expose **nine metric families, 18 time series per replica**, under the prefix
`podcertificatesigner_`. The count does not move with cluster size — not with
pods, namespaces, or request rate.

| # | Metric | Type | Labels (bound) | The question it answers |
|---|--------|------|----------------|-------------------------|
| M1 | `podcertificaterequests_total` | Counter | `outcome`(3) × `reason`(4) — 4 live series | Are we denying or failing requests, and is the rate rising? Carries the SLI. |
| M1b | `podcertificaterequest_requeues_total` | Counter | `reason`(2) | Is something retrying forever? Isolates the silent-hang case. |
| M1c | `podcertificaterequest_drops_total` | Counter | `reason`(1) | Are requests outliving their pods? |
| M2 | `ca_reload_attempts_total` | Counter | `result`(3) | Did the CA rotate, and are reloads failing? |
| M3 | `ca_reload_consecutive_failures` | Gauge | none | Is this replica about to leave the Service? |
| M4 | `ca_reload_last_success_timestamp_seconds` | Gauge | none | Are reloads happening at all? |
| M5 | `ca_expiration_timestamp_seconds` | Gauge | none | Will the signer stop being able to sign, and when? |
| M6 | `clustertrustbundle_publish_attempts_total` | Counter | `result`(4) | Is the leader still publishing — and is somebody else editing the bundle? |
| M7 | `trust_bundle_certificates` | Gauge | none | How many anchors are we publishing? |

`reason` values are the existing `const Reason` block
(`podcertificaterequest_controller.go:54-73`) and stay in the API's CamelCase, so
a value seen on a graph greps identically against
`kubectl get podcertificaterequest -o yaml`.

Four rules follow, and they are the durable part of this record:

**No per-request identity in any label.** Not pod name, UID, namespace, SPIFFE
ID, nor CA fingerprint, subject or serial. A label whose values churn with
workloads produces series that outlive the object and can keep an alert firing
after the cause is fixed.

**A `reason` label is a closed enum we compute**, never a passthrough of an error
string. Where the underlying detail is unbounded — `crypto/tls` parse errors, for
instance — it stays in the log and out of the label.

**Terminal outcomes, requeues and drops are separate metrics, not one metric
with a label.** A requeue is not an outcome. Mixing them makes the SLI
meaningless. A drop writes no status (`controller.go:355-359`), so the request
never becomes immutable and the same one can be counted again after a restart —
its counter must not be read as a count of distinct requests.

**A metric records what happened; an event explains it to whoever owns the
workload; a condition is the durable verdict.** Where an event already carries
the explanation, the metric adds only the count.

### What is deliberately excluded

The exclusion list is longer than the surface, which is the intended ratio.

- **An issuance-latency histogram** — not for bucket cost, but because
  `controller_runtime_reconcile_time_seconds` already covers the same span with
  40 buckets, free.
- **`namespace` as a label**, and any per-pod identity. See the rule above.
- **CA fingerprint, subject or serial** on the expiry gauge — rotation would
  leave the old series behind at its stale value.
- **A histogram of issued certificate lifetimes**, a `pending_requests` gauge, a
  build-info gauge, a reload-duration histogram, leader-election state, and a
  counter duplicating the `DefaultSANSkipped` event.

M7 is the weakest row. It reports the in-memory bundle the signer *would*
publish, not a read of the ClusterTrustBundle object, and its `Help` text must
say so since M6 names the API object and M7 does not.

## Consequences

**Positive.** Two silent outages become alertable before they bite: M5 answers
"the signer is about to be unable to issue anything" (`expiry - time() <
default certificate duration`), and M3 crosses its threshold roughly five
minutes before readiness flips, which is the only lead time in the set. M4
catches a stopped reload loop, which no failure-based signal can. M6's `updated`
result is a free drift detector — `publishOnce` already computes
`CreateOrPatch`'s `OperationResult`, and `updated` on a drift-repair tick with no
rotation means somebody edited the cluster's trust anchors and we overwrote them.

**Negative.** `ctb_publish_failures_total` is renamed under the new prefix. Any
existing alert on it breaks. A metric name is effectively permanent once
published, which is precisely why this is worth doing before v1 rather than
after.

**Neutral.** The surface is additive to controller-runtime's, and does not change
issuance, the identity model, or the trust boundary. It does not supersede
[ADR-0001](0001-verified-identity-allowlist-boundary.md).

## Implementation Plan

Sequenced so each step is independently reviewable. This ADR ships alone; work
starts once it merges.

1. **Registry and prefix.** Introduce an `internal/metrics` package holding the
   declarations and a `Register` call, wired to the existing controller-runtime
   registry. Rename `ctb_publish_failures_total` into M6, keeping the failure
   count as `{result="failed"}`.
2. **Issuance counters (M1, M1b, M1c).** Increment at the existing outcome sites
   in `podcertificaterequest_controller.go`. Pre-initialise **only the valid
   `outcome`/`reason` pairs** — hand-curated, not derived from the `const Reason`
   block, because the reasons do not form a cross product (at the time of
   writing one, `ReasonAssociatedPodNotFound`, was declared and never used. It
   has since been deleted) and deriving the table would ship a permanent zero
   series for an impossible outcome.
3. **CA reload counters and gauges (M2, M3, M4).** M2 increments in
   `reloadOnce` and the event path, whose three results map to the existing
   `changed`/`unchanged`/`failed` branches. M3 and M4 read state already held
   under `healthMu`.
4. **CA expiry and trust bundle (M5, M6, M7).** M5 and M7 are computed at scrape
   time from the loaded CA rather than written on reload, so they cannot go stale
   relative to the reload loop. M6 increments in `publishOnce`.
5. **e2e migration.** Replace the two log-greps a metric covers cleanly
   (`caReloadSucceededLine`, `transientRequeueLine`). This needs scrape plumbing
   that does not exist — `getMetricsOutput()` reads a one-shot curl pod — and
   counters reset on `restartController()`, so assertions must be deltas within
   a single controller lifetime.

**Not migrating, deliberately:** `caReloadFailedLine` keeps its grep because the
suite asserts on classification and detail needles that are unbounded std-lib
error strings; `caBootstrapLine` runs before `mgr.Start`, so a gauge proves the
outcome but not the provenance; and the immutability grep keys on the request
name, the exact unbounded value this ADR forbids as a label. Metrics reduce the
log coupling. They do not remove it.

### Verification

Unit tests assert the registered surface against an expected set, so a metric
added without an ADR amendment fails the build, and pre-initialised series are
pinned by name and label pair. A cardinality test asserts the series count is
unchanged by the number of requests processed.

## Alternatives Considered

**Per-`PodCertificateRequest` series.** Rejected. cert-manager's maintainers
flagged this exact object shape as a Prometheus hazard on their own
`CertificateRequest` and never shipped it. SPIRE, which issues per workload at
higher rate, puts no identity in any label.

**A per-object collector generating series on scrape from the informer cache** —
cert-manager's fix for its stale-series bug. Correct for their problem, but it
still produces O(objects) series. Our objects are per-pod.

**One outcome counter with a `result` label covering requeues.** Rejected: it
makes the issued/total SLI meaningless, since a single request can requeue many
times.

**Seconds-until-expiry instead of an absolute timestamp for M5.** Rejected: a
gauge that must be re-written continuously to stay accurate goes stale when the
writer stops, which is the failure mode M4 exists to catch.

**Doing nothing.** The status quo is that the two silent outages above are
diagnosable only by reading controller logs, and that a log-level change can
turn the e2e suite red.

## More Information

- Prior art surveyed: cert-manager (`internal/collectors/`, issues #7301, #7883,
  PRs #7856, #8109), SPIRE `doc/telemetry/telemetry.md`, Kubernetes
  `clustertrustbundlepublisher/metrics.go` and
  `apiserver_client_certificate_expiration_seconds`, step-ca, Vault PKI.
  Citations are recorded in the design proposal. A reviewer quoting them should
  follow the links rather than take them second-hand.
- Related: [ADR-0001](0001-verified-identity-allowlist-boundary.md).
  [ADR-0006](0006-release-leader-lease-on-cancel.md) discusses how M6 counts a
  publish abandoned at shutdown.
- Implementation:
  [`internal/metrics/metrics.go`](../../internal/metrics/metrics.go) (M1, M1b,
  M1c, M2, M6) and
  [`internal/metrics/ca_collector.go`](../../internal/metrics/ca_collector.go)
  (M3, M4, M5, M7). `TestRegisteredSurfaceMatchesADR0005` in
  [`internal/metrics/metrics_test.go`](../../internal/metrics/metrics_test.go)
  pins the surface.
- Alert expressions and dashboard notes: [`docs/operations.md`](../operations.md).

### Status update (2026-11-16)

This note records the state of the code at release 3.1.0. The decision above is
unchanged.

- Status changed from `proposed` to `accepted` on 2026-11-16. The metric
  surface shipped in release 2.4.0 (PRs
  [#115](https://github.com/RafPe/pod-certificate-signer/pull/115),
  [#116](https://github.com/RafPe/pod-certificate-signer/pull/116),
  [#117](https://github.com/RafPe/pod-certificate-signer/pull/117) and
  [#118](https://github.com/RafPe/pod-certificate-signer/pull/118), CHANGELOG
  2.4.0).
- The Context section describes the code before this decision.
  `ctb_publish_failures_total` no longer exists. All `file:line` references in
  the Context and Decision sections are out of date.
- The nine families and 18 series match the code: 14 counter series that
  `preInitialize` in `internal/metrics/metrics.go` creates, plus the four
  gauges in `ca_collector.go`.
- The `reason` values now come from `internal/outcome/outcome.go`, not from a
  `const Reason` block in the controller. The terminal reasons are the
  certificates API constants, so a label value still matches the condition
  reason on the PodCertificateRequest.
- `reloadOnce` no longer exists. Since release 3.1.0 (PR
  [#184](https://github.com/RafPe/pod-certificate-signer/pull/184)), one reload
  path in `internal/authority/watch.go` increments M2. `healthMu` now exists
  only in `internal/trustbundle/publisher.go`.
- Step 5 (e2e migration) shipped in release 2.4.0. `test/e2e/metrics_scrape_test.go` holds the
  scrape helpers. `caReloadSucceededLine` and `transientRequeueLine` no longer
  exist. `caReloadFailedLine` and `caBootstrapLine` stay in
  `test/e2e/ca_lifecycle_test.go`, as this record decided.
- The cardinality test is in `internal/controller/metrics_test.go`.
- The Positive consequence says that M3 "crosses its threshold roughly five
  minutes before readiness flips". The code gives a longer lead time. Readiness
  fails only after at least 3 consecutive failed attempts and at least 10
  minutes from the first failure (`internal/authority/health.go`). An
  event-driven reload makes up to 5 attempts within a few seconds. The
  periodic reload makes one attempt every 60 seconds. Thus M3 reaches 3 about
  8 to 10 minutes before readiness fails. An alert on M3 `>= 3` with `for: 5m`
  gives about 3 to 5 minutes of warning.
  [`docs/operations.md`](../operations.md) gives this alert and the same 3 to 5
  minute figure.
- The "design proposal" is the pull request that added this ADR:
  [#114](https://github.com/RafPe/pod-certificate-signer/pull/114). The
  repository has no separate proposal document.
