# pod-certificate-signer (Helm chart)

This chart deploys the **pod-certificate-signer** controller. The controller is a
signer for the built-in `certificates.k8s.io/v1` `PodCertificateRequest` API. It
issues short-lived pod certificates and publishes its CA as a
`ClusterTrustBundle`.

For what the signer does and how workloads use it, see the [repository
README](../../README.md).

## Prerequisites

- Kubernetes **≥ 1.37**. In this version, `PodCertificateRequest` is GA in
  `certificates.k8s.io/v1`, and the API server serves it by default. You do not
  need a feature gate or a runtime config (`kubeVersion: ">= 1.37.0-0"`).
- A **CA key pair**. You supply your own CA. The chart does **not** include one.
  Create a Secret and refer to it (see [Providing the CA](#providing-the-ca)):

```bash
kubectl create namespace pcs-system
kubectl create secret tls podcertificate-signer-ca \
  --cert=ca.pem --key=ca-key.pem -n pcs-system
```

## Install

`signer.name` and a CA source are **required**:

```bash
helm install pod-certificate-signer oci://ghcr.io/rafpe/charts/pod-certificate-signer \
  -n pcs-system --create-namespace \
  --set signer.name=example.org/signer \
  --set signer.ca.secretRef.name=podcertificate-signer-ca
```

## Providing the CA

The signing CA is in `signer.ca`, with an explicit `source`:

- **`secretRef` (recommended, default).** The chart mounts an existing Secret.
  The private key stays in a Secret, and the chart adds a **read-only** volume
  for you. The chart projects only the CA certificate and key into the pod. You
  do not set `volumes` or `volumeMounts`. `signer.ca.secretRef.name` is
  **required**. An empty name stops `helm install` or `helm upgrade` at render
  time, before the pod can enter a crash loop.

  ```yaml
  signer:
    ca:
      source: secretRef
      secretRef:
        name: podcertificate-signer-ca    # existing kubernetes.io/tls or Opaque Secret
        certKey: tls.crt                  # key in the Secret holding the cert
        keyKey: tls.key                   # key in the Secret holding the private key
        mountPath: /app/signer/ca
  ```

- **`file` (advanced, bring your own mount).** You mount the certificate and key
  through `.Values.volumes` and `.Values.volumeMounts`. Then you set the paths
  to them:

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

> The `signer.ca` block above replaces the old `signer.ca_cert_path` and
> `signer.ca_key_path` values. `secretRef` mode replaces the manual
> `volumes`/`volumeMounts` CA configuration. To keep the old
> bring-your-own-mount behavior, use `source: file`.

## Values

| Key | Description | Default |
| --- | --- | --- |
| `replicaCount` | Number of replicas. Leader election selects one active replica. The other replicas are warm standbys. The chart ignores this value when `autoscaling.enabled` is `true`. | `2` |
| `image.repository` / `image.tag` | Image. The chart uses a tag with the `sha256:` prefix as a digest. | `ghcr.io/rafpe/pod-certificate-signer` / chart `appVersion` |
| `image.pullPolicy` | Image pull policy. | `IfNotPresent` |
| `imagePullSecrets` | Secrets to pull the image from a private registry. | `[]` |
| `nameOverride` / `fullnameOverride` | Override the chart name, or the full name that the chart uses for its resources. | `""` / `""` |
| `leader_election.enabled` | Enable leader election. | `true` |
| `health.bind_address` | Health and readiness bind address. The chart renders it as the container port **and** as the `--health-probe-bind-address` flag. | `":8081"` |
| `metrics.enable_scraping` | Expose the metrics port, and add the Prometheus scrape annotations to the pod. | `true` |
| `metrics.bind_address` | Metrics server bind address. | `":9090"` |
| **`metrics.insecure`** | **Security escape hatch.** When `false` (default), the controller serves `/metrics` over HTTPS. Each scrape must have authentication (TokenReview) and authorization (SubjectAccessReview). `true` restores the legacy unauthenticated plaintext endpoint. See [Metrics authentication](#metrics-authentication-security). | `false` |
| `metrics.reader.create` | Create the `*-metrics-reader` ClusterRole (`get` on the `/metrics` nonResourceURL). Bind it to your scraper. The chart ignores this value when `metrics.insecure` is `true`. | `true` |
| `metrics.networkPolicy.enabled` | Create an optional NetworkPolicy that limits ingress to the metrics port. It also requires `metrics.enable_scraping: true`. | `false` |
| `metrics.networkPolicy.namespaceSelector` / `.podSelector` | Labels (`matchLabels`) of the scrapers that the NetworkPolicy allows. When both are empty, the policy allows all sources. | `{}` / `{}` |
| `log.level` / `log.encoder` / `log.time_encoding` | zap logging configuration. | `info` / `console` / `rfc3339` |
| **`signer.name`** | **Required.** The signer name that this controller claims (`spec.signerName`). With an empty value, the controller stops at startup. | `""` |
| **`signer.cluster_fqdn`** | Cluster FQDN for the default certificate DNS names (`<pod>.<ns>.pod.<fqdn>` / `<pod>.<ns>.svc.<fqdn>`). The chart renders it as `--cluster-fqdn`. | `cluster.local` |
| `signer.ca.source` | CA source: `secretRef` (recommended) or `file`. See [Providing the CA](#providing-the-ca). | `secretRef` |
| `signer.ca.secretRef.name` | Existing Secret with the CA certificate and key. **Required** when `source=secretRef`. | `""` |
| `signer.ca.secretRef.certKey` / `.keyKey` / `.mountPath` | The Secret keys that the chart projects, and their mount path. | `tls.crt` / `tls.key` / `/app/signer/ca` |
| `signer.ca.file.certPath` / `.keyPath` | CA paths when `source=file`. You mount the files yourself. | `/app/signer/ca/tls.crt` / `/app/signer/ca/tls.key` |
| `signer.max_previous_ca_certs` | Number of previous CAs that the ClusterTrustBundle keeps across rotation. | `2` |
| `signer.require_ca_history` | Refuse to start when the ClusterTrustBundle of the signer does not exist. When `false`, the controller starts with an empty previous-CA history. Disabled by default, because a first install has no bundle. Enable it after the first install. Then a deleted bundle cannot silently reset the retained history. | `false` |
| `signer.enable_annotation_interpolation` | Allow `${...}` placeholders in configuration values, mostly in `cn`/`san`/`uris`. They resolve only from apiserver-verified request fields and `cluster_fqdn`. The signer compares resolved values to the verified identity of the pod by exact string equality, as it does for literal values. Thus interpolation gives no identity that the pod does not already own. The security gate is `signer.allow_unverified_identities`, not this flag. Set to `false` to deny all values that contain `${...}`. | `true` |
| `signer.honor_csr_sans` | Use SANs from the kubelet PKCS#10 CSR. This is for forward compatibility: at this time, kubelet sends empty CSRs. | `false` |
| **`signer.allow_unverified_identities`** | **Security escape hatch.** When `false`, annotation `cn`/`san`/`ip-san`/`uris` values must resolve to the verified identity of the pod, and the signer denies IP SANs. See [Identity constraints](#identity-constraints-security). | `false` |
| `signer.allow_pod_annotations` | Deprecated fallback to the annotations of the pod, for items that the `userAnnotations` of the request do not contain. Version 4.0.0 removes it. Set to `false` when all workloads use `userAnnotations`. Then pod annotations have no effect on issuance. | `true` |
| `audit.enabled` | Write the issuance audit record: a JSON line on stdout for each signing attempt and each terminal outcome. The record is best-effort. The controller reports a dropped record on the operational log, which stays on stderr. See [docs/auditing.md](../../docs/auditing.md). | `true` |
| `audit.pod_labels` | Pod label keys to copy into each record. Each entry is an exact key or a prefix that ends in `*`. A bare `*` copies all labels. The number of different exact keys must not be greater than `audit.max_copied_keys`, or the controller does not start. | `[]` |
| `audit.pod_annotations` | Pod annotation keys to copy into each record. Same format and the same `audit.max_copied_keys` rule as `audit.pod_labels`, but a bare `*` is not allowed. | `[]` |
| `audit.max_copied_keys` | Maximum number of labels that a record copies, and separately of annotations. 1 to 256. | `32` |
| `audit.max_value_length` | Maximum length in bytes of each label value, annotation value, supplied value and denial or failure message in a record. The controller cuts a longer value and appends `...[truncated]`. 1 to 4096. | `256` |
| `audit.max_record_bytes` | Maximum size in bytes of one record line. The controller removes the copied annotations, then the labels, then the supplied values from a longer record. 4096 to 262144. | `16384` |
| `audit.record_supplied_values` | Add the raw values of the supplied certificate configuration annotations to each record. When `false`, a record has only their names. | `false` |
| `admissionPolicies.dnsSANValidation.enabled` | Create a policy and binding for this signer. They validate explicit Pod certificate DNS SANs at admission. | `false` |
| `admissionPolicies.dnsSANValidation.validationActions` | Binding actions. Use `Warn`/`Audit` to test, then `Deny`. You cannot use `Deny` and `Warn` together. | `[Deny]` |
| `admissionPolicies.dnsSANValidation.namespaceSelector` / `.objectSelector` | Optional selectors that limit where the DNS SAN binding applies. Empty selectors apply it to Pods in all namespaces. | `{}` / `{}` |
| `manager.max_concurrent_reconciles` | Maximum number of concurrent reconciles. | `5` |
| `manager.reconcile_timeout` | Timeout for each reconcile. | `"5m"` |
| `serviceAccount.create` / `serviceAccount.automount` | Create the ServiceAccount, and mount its API credentials. | `true` / `true` |
| `serviceAccount.annotations` | Annotations on the ServiceAccount. | `{}` |
| `serviceAccount.name` | ServiceAccount name. When empty and `create` is `true`, the chart uses the full name. When empty and `create` is `false`, the chart uses `default`. | `""` |
| `podAnnotations` / `podLabels` | Extra annotations and labels on the controller pod. | `{}` / `{}` |
| `podSecurityContext` / `securityContext` | Defaults that comply with the restricted Pod Security Standard: non-root, seccomp `RuntimeDefault`, read-only root file system, drop `ALL`. | see `values.yaml` |
| `service.create` | Create a Service with the `http` (health) port and, when `metrics.enable_scraping` is `true`, the `metrics` port. | `true` |
| `service.type` / `service.port` | Service type, and the Service port that targets the `http` container port. | `ClusterIP` / `80` |
| `resources` | Container resource requests and limits. Conservative defaults for a lightweight controller. Set to `{}` to remove all limits. | requests `100m`/`128Mi`, limits `500m`/`256Mi` |
| `livenessProbe` / `readinessProbe` | Probes on the `http` port. | `/healthz` / `/readyz` |
| `podDisruptionBudget.enabled` | Create a PodDisruptionBudget for the controller. | `true` |
| `podDisruptionBudget.minAvailable` / `.maxUnavailable` | Disruption budget. The two values are mutually exclusive. When both are set, `minAvailable` wins. When neither is set, the render fails. With 2 replicas, `minAvailable: 1` drains one replica at a time. If you scale to one replica, change to `maxUnavailable: 1`. | `1` / `""` |
| `podDisruptionBudget.unhealthyPodEvictionPolicy` | Eviction policy. With `AlwaysAllow`, a pod that is not Ready cannot block a node drain. | `AlwaysAllow` |
| `autoscaling.enabled` | Create a HorizontalPodAutoscaler. Of limited use for a leader-elected controller. | `false` |
| `autoscaling.minReplicas` / `.maxReplicas` / `.targetCPUUtilizationPercentage` | HPA limits and CPU target. Set `targetMemoryUtilizationPercentage` to add a memory target. | `1` / `100` / `80` |
| `volumes` / `volumeMounts` | Extra volumes and mounts. Necessary only to mount the CA yourself when `signer.ca.source=file`. `secretRef` mode adds the CA volume for you. | `[]` |
| `nodeSelector` / `tolerations` / `affinity` | Standard pod scheduling settings. | `{}` / `[]` / `{}` |

## Identity constraints (security)

By default (`signer.allow_unverified_identities: false`), the controller issues
certificates **only for the verified identity of the requesting pod**. The
signer accepts annotation `cn`/`san`/`uris` values only when they resolve to an
identity from the apiserver-verified request fields. These identities are the
pod name, `<pod>.<ns>`, the canonical `*.pod`/`*.svc` DNS forms, the SPIFFE ID,
and the service account. The signer **denies** all other values. It denies
`ip-san` values, because they have no verified derivation. The default extended
key usage is only `serverAuth`.

Set `signer.allow_unverified_identities: true` **only** when you trust pod
authors to request any identity. Use it together with a
`ValidatingAdmissionPolicy` that limits which `userAnnotations` workloads can
set. The chart renders the value as `--allow-unverified-identities=<value>` on
the controller.

> [!WARNING]
> **Breaking change.** By default, the signer no longer grants literal identity
> values or `clientAuth` in the default EKU. To keep the old behavior, set
> `signer.allow_unverified_identities: true` and add the `eku: server,client`
> annotation. The better migration is to use `${...}` interpolation. See the
> [identity constraints documentation](../../docs/configuration.md#identity-constraints).

## Metrics authentication (security)

By default (`metrics.insecure: false`), the controller serves `/metrics` over
**HTTPS**. Each scrape must have **authentication**: a Kubernetes bearer token
that a `TokenReview` verifies. Each scrape must also have **authorization**: a
`SubjectAccessReview` for `get` on the `/metrics` nonResourceURL. The chart
renders `--metrics-secure=true`. It also adds `create` on
`tokenreviews`/`subjectaccessreviews` to the controller ClusterRole.

> [!WARNING]
> **Breaking change.** Unauthenticated plaintext scrapes that worked before now
> fail. Prometheus must scrape over `https` and send a ServiceAccount token that
> is bound to the `*-metrics-reader` ClusterRole. It must also trust the
> self-signed serving certificate of the controller, or skip verification. The
> controller generates that certificate in memory.

Bind the rendered `*-metrics-reader` ClusterRole to the ServiceAccount of your
scraper. Then configure a `ServiceMonitor` (or equivalent) for the endpoint. Use
`scheme: https`, a `bearerTokenFile`, and `tlsConfig.insecureSkipVerify: true`
(or your serving CA). The
[configuration docs](../../docs/configuration.md#metrics-authentication) give
the full procedure.

The chart `fullname` helper sets the role name. Thus the name is
`<release>-metrics-reader` only when the release name already contains the chart
name. A release called `pcs` gets `pcs-pod-certificate-signer-metrics-reader`.
If you bind a name that does not exist, each scrape returns `403`. To find the
real name, use `kubectl get clusterrole -o name | grep metrics-reader`.

Set `metrics.insecure: true` **only** to restore the legacy unauthenticated
plaintext endpoint. Do this only when a different control protects the port. An
optional `metrics.networkPolicy` (disabled by default) limits ingress to the
metrics port to selected namespaces and pods.

## Preventive admission policies

`admissionPolicies` is a map of safeguards that you enable independently. The
first policy, `dnsSANValidation`, validates explicit DNS SAN annotations after
interpolation at admission time. It rejects these values:

- malformed DNS-1123 names
- labels longer than 63 characters
- names longer than 253 characters
- empty list members
- unsupported placeholders

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

Use `Warn` and `Audit` to see the effect during rollout. Then change the actions
to `[Deny]`. The policy only examines explicit `userAnnotations` on the projected
`podCertificate` source of a Pod. Signer-side validation is still mandatory. It
also covers CSR SANs and generated defaults, for all values of
`signer.allow_unverified_identities`.

## Upgrade notes for 2.0.0

Chart version 2.0.0 introduced these changes:

- **`signer.name` is now required.** Earlier chart versions used the placeholder
  `example.org/signer` as the default. Thus two default installs used the same
  signer name. Set it explicitly (`--set signer.name=...`).
- **You can now set `signer.cluster_fqdn`.** Before, every install used
  `cluster.local`. Set it to the domain of your cluster, so that the default
  certificate DNS names resolve.
- **`health.bind_address` now also sets the flag.** Before, it changed only the
  container port, and the manager stayed on `:8081`. Now a change moves both.
  Thus the probes and the listener stay aligned.

[`values.yaml`](./values.yaml) also documents each value inline.

## Next steps

To make sure that the chart applied your values, read the flags of the
controller. The commands use the `pcs-system` namespace and the
`pod-certificate-signer` release name from [Install](#install). Replace them with
your values. The Deployment name is the release `fullname`:

```bash
helm get values pod-certificate-signer -n pcs-system
kubectl -n pcs-system get deployment pod-certificate-signer \
  -o jsonpath='{.spec.template.spec.containers[0].command}'
```

Then request a certificate from a workload. See
[Getting started](../../docs/getting-started.md#3-request-a-certificate-from-a-workload).
For all certificate annotations and controller flags, see
[Configuration](../../docs/configuration.md).
