# podcertificate-signer (Helm chart)

Deploys the **pod-certificate-signer** controller — a signer for the built-in
`certificates.k8s.io/v1beta1` `PodCertificateRequest` API that issues short-lived
pod certificates and publishes its CA as a `ClusterTrustBundle`.

For what the signer does and how workloads consume it, see the [repository
README](../../README.md).

## Prerequisites

- Kubernetes **≥ 1.35** with the `PodCertificateRequest` feature gate and the
  `certificates.k8s.io/v1beta1` runtime config enabled (`kubeVersion: ">= 1.35.0"`).
- A **CA key pair** made available to the controller as a mounted secret. You
  provide your own CA — the chart does **not** ship one. Create it, then point
  the chart's `volumes`/`volumeMounts` at it so the files land at
  `signer.ca_cert_path` / `signer.ca_key_path` (defaults under `/app/signer/ca`).

```bash
kubectl create secret tls podcertificate-signer-ca \
  --cert=ca.crt --key=ca.key -n <namespace>
```

## Install

`signer.name` is **required** — there is no default, so it must be set explicitly:

```bash
helm install pcs oci://ghcr.io/rafpe/charts/podcertificate-signer \
  -n pcs-system --create-namespace \
  --set signer.name=example.org/signer \
  -f my-values.yaml     # must mount the CA secret via volumes/volumeMounts
```

## Values

| Key | Description | Default |
| --- | --- | --- |
| `replicaCount` | Replicas (leader-elected; extras are warm standbys). | `2` |
| `image.repository` / `image.tag` | Image; a `sha256:`-prefixed tag is treated as a digest. | `ghcr.io/rafpe/pod-certificate-signer` / chart `appVersion` |
| `leader_election.enabled` | Enable leader election. | `true` |
| `health.bind_address` | Health/readiness bind address; rendered as both the container port **and** the `--health-probe-bind-address` flag. | `":8081"` |
| `metrics.enable_scraping` | Expose the metrics port and Prometheus scrape annotations. | `true` |
| `metrics.bind_address` | Metrics server bind address. | `":9090"` |
| `log.level` / `log.encoder` / `log.time_encoding` | zap logging config. | `info` / `console` / `rfc3339` |
| **`signer.name`** | **Required.** Signer name this controller claims (`spec.signerName`). Empty makes the controller fail fast at startup. | `""` |
| **`signer.cluster_fqdn`** | Cluster FQDN used to build the default certificate DNS names (`<pod>.<ns>.pod.<fqdn>` / `<pod>.<ns>.svc.<fqdn>`); rendered as `--cluster-fqdn`. | `cluster.local` |
| `signer.ca_cert_path` / `signer.ca_key_path` | Mounted CA cert / key paths. | `/app/signer/ca/tls.crt` / `.../tls.key` |
| `signer.max_previous_ca_certs` | Previous CAs retained in the ClusterTrustBundle across rotation. | `2` |
| `signer.enable_annotation_interpolation` | Allow `${...}` placeholders in `cn`/`san`/`uris`, resolved from verified request fields. | `false` |
| `signer.honor_csr_sans` | Honor SANs from the kubelet PKCS#10 CSR (forward-compat; kubelet emits empty CSRs today). | `false` |
| **`signer.allow_unverified_identities`** | **Security escape hatch.** When `false`, annotation `cn`/`san`/`ip-san`/`uris` values must resolve to the pod's verified identity, and IP SANs are denied. See [Identity constraints](#identity-constraints-security). | `false` |
| `manager.max_concurrent_reconciles` | Concurrent reconciles. | `5` |
| `manager.reconcile_timeout` | Per-reconcile timeout. | `"5m"` |
| `resources` | Container resource requests/limits (unset by default — set them in production). | `{}` |
| `serviceAccount.create` / `serviceAccount.automount` | ServiceAccount management. | `true` / `true` |
| `volumes` / `volumeMounts` | Mount the CA secret at `signer.ca_*_path` (required). | `[]` |
| `podSecurityContext` / `securityContext` | PSS-restricted defaults (non-root, seccomp `RuntimeDefault`, read-only rootfs, drop `ALL`). | see `values.yaml` |
| `autoscaling.enabled` | HPA (of limited use for a leader-elected controller). | `false` |

## Identity constraints (security)

By default (`signer.allow_unverified_identities: false`) the controller issues
certificates **only for the requesting pod's own verified identity**. Annotation
`cn`/`san`/`uris` values are accepted only when they resolve to an identity
derived from the apiserver-verified request fields (the pod name, its canonical
`*.pod`/`*.svc` DNS forms, its SPIFFE ID, and its service account); anything else
is **Denied**. `ip-san` values are denied (no verified derivation), and the
default extended key usage is `serverAuth` only.

Set `signer.allow_unverified_identities: true` **only** if you intentionally trust
pod authors to request arbitrary identities — ideally alongside a
`ValidatingAdmissionPolicy` that restricts which `userAnnotations` workloads may
set. Enabling it renders `--allow-unverified-identities` on the controller.

> [!WARNING]
> **Breaking change.** Literal identity values and `clientAuth` in the default
> EKU are no longer granted by default. To keep the old behaviour set
> `signer.allow_unverified_identities: true` and add the `eku: server,client`
> annotation; prefer migrating to `${...}` interpolation. See the
> [repository README](../../README.md#-identity-constraints-default-secure).

> The `signer.allow_unverified_identities` value and this behaviour are
> introduced together with the identity-constraint change (issue #26 / PR #38);
> until that merges, the value is inert.

## Notes for this release

- **`signer.name` is now required.** Earlier chart versions defaulted it to the
  placeholder `example.org/signer`, which let two default installs collide on the
  same signer name. Set it explicitly (`--set signer.name=...`).
- **`signer.cluster_fqdn` is now configurable.** Previously every install was
  pinned to `cluster.local`; set this to your cluster's domain so the default
  certificate DNS names resolve.
- **`health.bind_address` now drives the flag too.** Earlier it changed only the
  container port, leaving the manager on `:8081` — changing the value now moves
  both, so the probes and the listener stay in sync.

Every value is also documented inline in
[`values.yaml`](./values.yaml).
