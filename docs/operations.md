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
cannot be read on startup, the controller **fails closed** (refuses to start)
rather than publish an empty bundle and drop previously-trusted CAs.

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
backoff; failures after the retry budget increment the
`ctb_publish_failures_total` metric and fail the leader's readiness.

Inspect the published bundle:

```sh
kubectl get clustertrustbundle
kubectl get clustertrustbundle <name> -o jsonpath='{.spec.trustBundle}' \
  | openssl crl2pkcs7 -nocrl -certfile /dev/stdin | openssl pkcs7 -print_certs -noout
```

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
