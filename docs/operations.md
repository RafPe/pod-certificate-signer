# Operations

Day-2 tasks: rotating the CA, understanding leader election and readiness, how
the `ClusterTrustBundle` is published, upgrades and troubleshooting. For the
component model behind these behaviours see [Architecture](./architecture.md).

## Rotating the signing CA

> [!CAUTION]
> **The sample CA that used to ship with this repository is not a secret.**
> `examples/ca_tls_secret.yaml` carried a CA private key in plain sight. It is
> removed from `HEAD` by [#37](https://github.com/rafpe/pod-certificate-signer/pull/37),
> which replaces it with an ephemeral CA generated at install time — but deleting
> a file does not unpublish a key, and it remains readable in git history. Anyone
> can recover it and mint certificates your workloads would trust. If that CA was
> ever loaded into a cluster that matters, treat it as compromised: rotate now,
> and treat every certificate issued under it as untrusted.

Rotation is a Secret update — there is nothing to restart:

```sh
kubectl create secret tls podcertificate-signer-ca \
  --namespace pcs-system \
  --cert=new-ca.pem \
  --key=new-ca-key.pem \
  --dry-run=client -o yaml | kubectl apply -f -
```

What happens next:

1. **The controller hot-reloads.** Every replica watches the mounted CA files
   (fsnotify) and reloads them in place, so new certificates are signed by the
   new CA without a rollout. Kubelet refreshes a mounted Secret on its sync
   period (up to ~1 minute), so allow a short delay — and mount the Secret as a
   plain volume, since a `subPath` mount is **never** updated after the pod
   starts.
2. **The old CA stays trusted.** The elected leader republishes the
   `ClusterTrustBundle` with the new CA followed by the previous ones, keeping up
   to `--max-previous-ca-certs` (default `2`). Workloads that mount the bundle
   keep verifying peers still holding a certificate from the old CA.
3. **Certificates drain on their own.** Already-issued certificates stay valid
   until they expire — at most the request's `duration` (default `24h`, capped by
   `maxExpirationSeconds`) — and kubelet then requests a fresh one from the new
   CA.

> [!IMPORTANT]
> Leave **at least one full certificate lifetime** between rotations. Rotating
> more than `--max-previous-ca-certs` times inside that window drops the oldest CA
> out of the published bundle while certificates signed by it are still in use,
> and those workloads will fail peer verification. If you must rotate faster,
> raise `--max-previous-ca-certs` first.

The retained history survives a restart: on startup the controller reseeds it
from the `ClusterTrustBundle` it already published, so a rotation performed while
the controller was down still keeps the previous CA trusted. If that history
cannot be **read** on startup, the controller **fails closed** (refuses to start)
rather than publish an empty bundle and drop previously-trusted CAs.

The bundle is not private controller state, so what is read back from it is
bounded and validated rather than adopted: entries that are not usable signing
CAs, entries that have expired, duplicates, and anything beyond
`--max-previous-ca-certs` are dropped and logged. A hand-edited bundle is
repaired by the next publish instead of becoming permanent history
([ADR-0004](./adr/0004-bootstrapped-previous-ca-history.md)).

> [!IMPORTANT]
> **Set `signer.require_ca_history: true` once the signer has published its
> bundle.** A bundle that has never existed and one that was *deleted* look
> identical to the controller, so by default a missing bundle starts an empty
> history — which is right for a first install and, after one, means the retained
> CAs are gone for good the next time the controller restarts. With the flag on,
> a missing bundle fails startup instead, so the loss is caught before the
> controller republishes without it.

### Rotation runbook

Rotation is one `kubectl apply`, but it is not instant and it is not atomic. The
four things below are what decides whether it lands quietly or takes a fleet
down.

**Budget up to ~6 minutes for the new CA to reach running workloads.** Our own
e2e measured a full rotation reaching mounted `ca.crt` files at **5m13s** and
**5m26s** on two runs. The delay is not the controller — it reloads and
republishes within seconds. It is kubelet: a `ClusterTrustBundle` projection is
served from a normalization cache with a **hard-coded 5-minute TTL**, and the
refreshed value then has to wait for the next pod sync (`--sync-frequency`,
default 1 minute). **No flag shortens this.** Plan the maintenance window
around six minutes rather than around the apply.

**Rotate with an overlap window, never as a swap.** For those six minutes some
pods hold a certificate from the old CA and some from the new one, and both
directions have to verify. That is what `signer.max_previous_ca_certs` (default
`2`) is for: the published bundle carries the new CA *and* its predecessors, so
a peer on either side of the propagation front is still trusted. Rotate to a new
CA, let the old certificates drain, and only then consider retiring the old
anchor.

> [!TIP]
> **Do not reach for rolling the workloads first.** Restarting every pod to pick
> up the new CA trades a six-minute wait for a fleet-wide restart, and the
> restarted pods still read their anchors through the same cache. The overlap
> window exists precisely so nothing has to restart.

**Applications must re-read the file.** Kubelet rewrites `ca.crt` underneath a
running container and signals nothing — no signal, no restart, no event. An
application that loads its trust anchors once at startup keeps using the old set
until it is restarted, which turns a rotation that propagated perfectly into a
verification failure some hours later. Reload the anchors on a timer, on a file
watch, or per connection.

> [!WARNING]
> **A stuck credential freezes the trust anchors too.** Kubelet builds a
> projected volume in a single pass and skips the write entirely if any source
> fails, so a pod whose `podCertificate` refresh is denied or failed silently
> stops receiving `ca.crt` updates as well. The pod keeps running with the
> anchors it already had, and a rotation never reaches it. Do not assume the
> anchors in a running pod are current: alert on the request's condition, and on
> the `CASignerUnusable` warning event the controller emits while a CA cannot
> cover a request.

```sh
# Requests that are stuck rather than issued, across the cluster.
kubectl get events -A --field-selector reason=CASignerUnusable
```

## Leader election and replicas

The chart runs `replicaCount: 2` with `leader_election.enabled: true`. Work is
split deliberately between every-replica and leader-only duties:

- **CA watching and signing run on every replica.** A standby keeps its
  in-memory CA current, so it never signs with stale material immediately after
  being promoted.
- **`ClusterTrustBundle` publication is leader-gated.** Only the elected leader
  writes the shared resource, so replicas cannot fight over it.

Autoscaling (`autoscaling.enabled`) is of limited use for a leader-elected
controller — extra replicas are warm standbys, not additional throughput.

## Readiness and health

The controller serves two endpoints (default port `:8081`):

- **`/healthz`** — liveness; a simple ping.
- **`/readyz`** — readiness, gated on two signals:
  - **CA health** — a replica whose CA watcher has died, or whose reloads have
    been failing persistently, is pulled from readiness so it is not relied upon
    to sign or publish with stale material. A *transient* reload failure keeps the
    replica ready, because the last-good CA is retained and signing still works.
  - **ClusterTrustBundle publisher** — a leader whose publishes keep failing after
    retries is pulled from readiness, so the failure is visible and leadership can
    move elsewhere.

## ClusterTrustBundle publication

The publisher reconciles the signer's `ClusterTrustBundle` towards the current
CA. It publishes on startup (so a newly-elected leader publishes from the current
in-memory CA), on every CA reload event, and on a periodic **drift-repair tick**
(every 10 minutes) that re-publishes even without a reload — repairing a manual
edit or a lost event. Publishes are single-flight and retried with exponential
backoff; failures after the retry budget increment
`podcertificatesigner_clustertrustbundle_publish_attempts_total{result="failed"}`
and fail the leader's readiness. Every attempt is counted, so
`{result="unchanged"}` standing still is how you see a leader that stopped
publishing, and `{result="updated"}` on a drift-repair tick with no CA rotation
to explain it means somebody edited the bundle and the signer overwrote them.

Inspect the published bundle:

```sh
kubectl get clustertrustbundle
kubectl get clustertrustbundle <name> -o jsonpath='{.spec.trustBundle}' \
  | openssl crl2pkcs7 -nocrl -certfile /dev/stdin | openssl pkcs7 -print_certs -noout
```

## Metrics

The signer exposes nine custom metric families under the
`podcertificatesigner_` prefix, on the same authenticated endpoint as
controller-runtime's (see [ADR-0005](adr/0005-bounded-metrics-surface.md)).
**No label carries a pod, namespace, request or certificate identity**, so the
number of time series is the same on a 10-pod cluster as on a 10,000-pod one.

| Metric | Type | Labels | What it answers |
| --- | --- | --- | --- |
| `podcertificaterequests_total` | counter | `outcome`, `reason` | Are we denying or failing requests? Carries the SLI. |
| `podcertificaterequest_requeues_total` | counter | `reason` | Is something retrying forever? |
| `podcertificaterequest_drops_total` | counter | `reason` | Are requests outliving their pods? |
| `ca_reload_attempts_total` | counter | `result` | Did the CA rotate, and are reloads failing? |
| `ca_reload_consecutive_failures` | gauge | — | Is this replica about to leave the Service? |
| `ca_reload_last_success_timestamp_seconds` | gauge | — | Are reloads happening at all? |
| `ca_expiration_timestamp_seconds` | gauge | — | Will the signer stop being able to sign, and when? |
| `clustertrustbundle_publish_attempts_total` | counter | `result` | Is the leader still publishing — and is somebody else editing the bundle? |
| `trust_bundle_certificates` | gauge | — | How many anchors are we publishing? |

The two outages an operator cannot otherwise see coming, and the expressions
that catch them:

```promql
# The signer is about to be unable to issue a default-duration (24h)
# certificate. Past this point requests requeue silently and pods sit in
# ContainerCreating with nothing on the request explaining why.
podcertificatesigner_ca_expiration_timestamp_seconds - time() < 86400

# The reload loop has stopped. It reloads every 60s regardless of events, so
# nothing failing is not the same as everything working: a dropped watch or a
# wedged ticker produces no failures at all.
time() - podcertificatesigner_ca_reload_last_success_timestamp_seconds > 300
```

Two more worth having. The first buys roughly five minutes' warning before
readiness flips; the second says somebody edited the cluster's trust anchors
and the signer overwrote them:

```promql
podcertificatesigner_ca_reload_consecutive_failures >= 3   # for: 5m

increase(podcertificatesigner_clustertrustbundle_publish_attempts_total{result="updated"}[1h]) > 0
  unless
increase(podcertificatesigner_ca_reload_attempts_total{result="changed"}[1h]) > 0
```

Two things to know when reading these. `ca_reload_attempts_total` counts
*attempts*: one failing burst retries up to five times, so the counter can rise
by five where the log rose by one. And `trust_bundle_certificates` reports the
in-memory bundle the signer *would* publish, not a read of the
`ClusterTrustBundle` object, so it does not detect drift in what is published.

## Upgrades

> [!IMPORTANT]
> **Roll the chart and image out together.** The controller's RBAC grants `pods`
> as **`get` only** — it reads the associated pod directly (uncached) and does not
> `list`/`watch` pods. A previous binary relied on a cached pod informer
> (`list`/`watch`), so upgrading the chart ahead of the image would leave an old
> controller without the permissions it needs. The chart `appVersion` pins the
> image tag so they ship as a unit; a normal `helm upgrade` to a released chart
> version keeps them aligned.

## Troubleshooting

**Signer name mismatch** — the most common issue. Ensure the `--signer-name`
(Helm `signer.name`) matches the `signerName` in every workload's projected
volume exactly.

**CA failures** — verify the CA is a valid CA (`isCA`), the private key matches,
and it is not expiring too soon.

**Configuration errors** — a `Denied` condition with reason
`InvalidUnverifiedUserAnnotations` carries the exact error in its message:

```sh
kubectl describe podcertificaterequest -n <namespace>
```

Narrow it down by changing the configuration incrementally, and watch the
controller logs alongside.

### Logs

```sh
kubectl logs -n pcs-system deployment/pod-certificate-signer
```

Adjust verbosity with `log.level` (`info`, `error`, `debug`, `panic`) and
`log.encoder` (`console` or `json`) in the chart values.
