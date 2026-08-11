# pod-certificate-signer (Helm chart)

Deploys the **pod-certificate-signer** controller — a signer for the built-in
`certificates.k8s.io/v1beta1` `PodCertificateRequest` API that issues short-lived
pod certificates and publishes its CA as a `ClusterTrustBundle`.

For what the signer does and how workloads consume it, see the [repository
README](../../README.md).

## Prerequisites

- Kubernetes **≥ 1.35** with the `PodCertificateRequest` feature gate and the
  `certificates.k8s.io/v1beta1` runtime config enabled (`kubeVersion: ">= 1.35.0"`).
- A **CA key pair**. You provide your own CA — the chart does **not** ship one.
  Create a Secret and reference it (see [Providing the CA](#providing-the-ca)):

```bash
kubectl create secret tls pod-certificate-signer-ca \
  --cert=ca.crt --key=ca.key -n <namespace>
```

## Install

`signer.name` and a CA source are **required**:

```bash
helm install pcs oci://ghcr.io/rafpe/charts/pod-certificate-signer \
  -n pcs-system --create-namespace \
  --set signer.name=example.org/signer \
  --set signer.ca.secretRef.name=pod-certificate-signer-ca
```

## Providing the CA

The signing CA is configured under `signer.ca` with an explicit `source`:

- **`secretRef` (recommended, default):** mount an existing Secret. The private
  key stays in a Secret, the chart wires a **read-only** volume for you, and only
  the CA cert + key are projected into the pod — no `volumes`/`volumeMounts` to
  plumb. `signer.ca.secretRef.name` is **required**; an empty name fails
  `helm install`/`upgrade` at render time rather than crash-looping the pod.

  ```yaml
  signer:
    ca:
      source: secretRef
      secretRef:
        name: pod-certificate-signer-ca   # existing kubernetes.io/tls or Opaque Secret
        certKey: tls.crt                  # key in the Secret holding the cert
        keyKey: tls.key                   # key in the Secret holding the private key
        mountPath: /app/signer/ca
  ```

- **`file` (advanced / BYO mount):** you mount the cert/key yourself via
  `.Values.volumes` / `.Values.volumeMounts` and point at them:

  ```yaml
  signer:
    ca:
      source: file
      file:
        certPath: /app/signer/ca/tls.crt
        keyPath: /app/signer/ca/tls.key
  volumes: [ ... ]        # your own mount landing the files at the paths above
  volumeMounts: [ ... ]
  ```

> Chart values changed here: the old `signer.ca_cert_path` / `signer.ca_key_path`
> are replaced by the `signer.ca` block above. `secretRef` mode replaces the
> manual `volumes`/`volumeMounts` CA wiring; use `source: file` to keep the old
> bring-your-own-mount behaviour.

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
| `signer.ca.source` | CA source: `secretRef` (recommended) or `file`. See [Providing the CA](#providing-the-ca). | `secretRef` |
| `signer.ca.secretRef.name` | Existing Secret with the CA cert+key. **Required** when `source=secretRef`. | `""` |
| `signer.ca.secretRef.certKey` / `.keyKey` / `.mountPath` | Secret keys projected and where they mount. | `tls.crt` / `tls.key` / `/app/signer/ca` |
| `signer.ca.file.certPath` / `.keyPath` | CA paths when `source=file` (you mount them yourself). | `/app/signer/ca/tls.crt` / `.../tls.key` |
| `signer.max_previous_ca_certs` | Previous CAs retained in the ClusterTrustBundle across rotation. | `2` |
| `signer.enable_annotation_interpolation` | Allow `${...}` placeholders in `cn`/`san`/`uris`, resolved from verified request fields. | `false` |
| `signer.honor_csr_sans` | Honor SANs from the kubelet PKCS#10 CSR (forward-compat; kubelet emits empty CSRs today). | `false` |
| **`signer.allow_unverified_identities`** | **Security escape hatch.** When `false`, annotation `cn`/`san`/`ip-san`/`uris` values must resolve to the pod's verified identity, and IP SANs are denied. See [Identity constraints](#identity-constraints-security). | `false` |
| `manager.max_concurrent_reconciles` | Concurrent reconciles. | `5` |
| `manager.reconcile_timeout` | Per-reconcile timeout. | `"5m"` |
| `resources` | Container resource requests/limits. Conservative defaults for a lightweight controller; set `{}` to leave it unconstrained. | requests `100m`/`128Mi`, limits `500m`/`256Mi` |
| `podDisruptionBudget.enabled` | Create a PodDisruptionBudget for the controller. | `true` |
| `podDisruptionBudget.minAvailable` / `.maxUnavailable` | Disruption budget (mutually exclusive; `minAvailable` wins when both set). With 2 replicas `minAvailable: 1` drains one at a time; switch to `maxUnavailable: 1` if you scale to a single replica. | `1` / `""` |
| `podDisruptionBudget.unhealthyPodEvictionPolicy` | Eviction policy so a not-yet-Ready pod can't wedge a node drain. | `AlwaysAllow` |
| `serviceAccount.create` / `serviceAccount.automount` | ServiceAccount management. | `true` / `true` |
| `volumes` / `volumeMounts` | Extra volumes/mounts. Only needed to mount the CA yourself when `signer.ca.source=file`; `secretRef` mode wires the CA volume for you. | `[]` |
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
> [identity constraints documentation](../../docs/configuration.md#identity-constraints).

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
