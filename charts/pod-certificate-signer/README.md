# pod-certificate-signer (Helm chart)

Deploys the **pod-certificate-signer** controller — a signer for the built-in
`certificates.k8s.io/v1` `PodCertificateRequest` API that issues short-lived
pod certificates and publishes its CA as a `ClusterTrustBundle`.

For what the signer does and how workloads consume it, see the [repository
README](../../README.md).

## Prerequisites

- Kubernetes **≥ 1.37**, where `PodCertificateRequest` is GA in
  `certificates.k8s.io/v1` and served by default — no feature gate or runtime
  config required (`kubeVersion: ">= 1.37.0-0"`).
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
| **`metrics.insecure`** | **Security escape hatch.** When `false` (default) `/metrics` is served over HTTPS and every scrape must authenticate (TokenReview) and be authorized (SubjectAccessReview). `true` restores the legacy unauthenticated plaintext endpoint. See [Metrics authentication](#metrics-authentication-security). | `false` |
| `metrics.reader.create` | Create the `*-metrics-reader` ClusterRole (`get` on the `/metrics` nonResourceURL) to bind to your scraper. Ignored when `metrics.insecure`. | `true` |
| `metrics.networkPolicy.enabled` | Create an optional NetworkPolicy restricting ingress to the metrics port. | `false` |
| `metrics.networkPolicy.namespaceSelector` / `.podSelector` | Label selectors for allowed scrapers when the NetworkPolicy is enabled (empty allows all). | `{}` / `{}` |
| `log.level` / `log.encoder` / `log.time_encoding` | zap logging config. | `info` / `console` / `rfc3339` |
| **`signer.name`** | **Required.** Signer name this controller claims (`spec.signerName`). Empty makes the controller fail fast at startup. | `""` |
| **`signer.cluster_fqdn`** | Cluster FQDN used to build the default certificate DNS names (`<pod>.<ns>.pod.<fqdn>` / `<pod>.<ns>.svc.<fqdn>`); rendered as `--cluster-fqdn`. | `cluster.local` |
| `signer.ca.source` | CA source: `secretRef` (recommended) or `file`. See [Providing the CA](#providing-the-ca). | `secretRef` |
| `signer.ca.secretRef.name` | Existing Secret with the CA cert+key. **Required** when `source=secretRef`. | `""` |
| `signer.ca.secretRef.certKey` / `.keyKey` / `.mountPath` | Secret keys projected and where they mount. | `tls.crt` / `tls.key` / `/app/signer/ca` |
| `signer.ca.file.certPath` / `.keyPath` | CA paths when `source=file` (you mount them yourself). | `/app/signer/ca/tls.crt` / `.../tls.key` |
| `signer.max_previous_ca_certs` | Previous CAs retained in the ClusterTrustBundle across rotation. | `2` |
| `signer.require_ca_history` | Refuse to start when the signer's ClusterTrustBundle is absent, instead of starting with an empty previous-CA history. Off by default (a first install has no bundle yet); turn it on afterwards so a deleted bundle cannot silently reset the retained history. | `false` |
| `signer.enable_annotation_interpolation` | Allow `${...}` placeholders in `cn`/`san`/`uris`, resolved only from apiserver-verified request fields plus `cluster_fqdn`. Resolved values are checked against the pod's verified identity by exact string equality, exactly as literal values are, so interpolation grants no identity the pod does not already own — the security gate is `signer.allow_unverified_identities`, not this flag. Set to `false` to deny values containing `${...}` outright. | `true` |
| `signer.honor_csr_sans` | Honor SANs from the kubelet PKCS#10 CSR (forward-compat; kubelet emits empty CSRs today). | `false` |
| **`signer.allow_unverified_identities`** | **Security escape hatch.** When `false`, annotation `cn`/`san`/`ip-san`/`uris` values must resolve to the pod's verified identity, and IP SANs are denied. See [Identity constraints](#identity-constraints-security). | `false` |
| `admissionPolicies.dnsSANValidation.enabled` | Create a signer-specific policy and binding that validate explicit Pod certificate DNS SANs before admission. | `false` |
| `admissionPolicies.dnsSANValidation.validationActions` | Binding actions. Use `Warn`/`Audit` to stage, then `Deny`; `Deny` and `Warn` cannot be combined. | `[Deny]` |
| `admissionPolicies.dnsSANValidation.namespaceSelector` / `.objectSelector` | Optional selectors limiting where the DNS SAN binding applies. | `{}` / `{}` |
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

## Metrics authentication (security)

By default (`metrics.insecure: false`) the controller serves `/metrics` over
**HTTPS** and requires every scrape to be **authenticated** (a Kubernetes bearer
token, verified via `TokenReview`) and **authorized** (`SubjectAccessReview` for
`get` on the `/metrics` nonResourceURL). This renders `--metrics-secure=true` and
adds `create` on `tokenreviews`/`subjectaccessreviews` to the controller
ClusterRole.

> [!WARNING]
> **Breaking change.** Unauthenticated plaintext scrapes that worked before now
> fail. Prometheus must scrape over `https`, present a ServiceAccount token bound
> to the `*-metrics-reader` ClusterRole, and trust (or skip verifying) the
> controller's in-memory self-signed serving certificate.

Bind the rendered `*-metrics-reader` ClusterRole to your scraper's
ServiceAccount and point a `ServiceMonitor` (or equivalent) at the endpoint with
`scheme: https`, a `bearerTokenFile`, and `tlsConfig.insecureSkipVerify: true`
(or your serving CA). Full walkthrough in the
[configuration docs](../../docs/configuration.md#metrics-authentication).

The role is named from the chart's `fullname` helper, so it is
`<release>-metrics-reader` only when the release name already contains the
chart name. A release called `pcs` renders
`pcs-pod-certificate-signer-metrics-reader`; binding a name that does not exist
returns `403` on every scrape. Confirm with
`kubectl get clusterrole -o name | grep metrics-reader`.

Set `metrics.insecure: true` **only** to restore the legacy unauthenticated
plaintext endpoint, and only when the port is protected by other means. An
optional `metrics.networkPolicy` (off by default) restricts ingress to the
metrics port to selected namespaces/pods.

## Preventive admission policies

`admissionPolicies` is a map of independently enabled safeguards. The initial
`dnsSANValidation` policy validates explicit DNS SAN annotations after
admission-time interpolation and rejects malformed DNS-1123 names, labels over
63 characters, names over 253 characters, empty list members, and unsupported
placeholders.

```yaml
admissionPolicies:
  dnsSANValidation:
    enabled: true
    validationActions:
      - Warn
      - Audit
    namespaceSelector: {}
    objectSelector: {}
```

Use `Warn` and `Audit` for rollout visibility, then change the actions to
`[Deny]`. The policy only sees explicit `userAnnotations` on a Pod's projected
`podCertificate` source. Signer-side validation remains mandatory and also
covers CSR SANs and generated defaults, regardless of
`signer.allow_unverified_identities`.

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
