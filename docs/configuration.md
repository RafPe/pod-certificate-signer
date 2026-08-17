# Configuration

This page documents everything you can tune: the per-request certificate
annotation contract, the identity-constraint model, the controller CLI flags,
and the Helm values including the recommended production posture. For a first
install see [Getting started](./getting-started.md).

## Certificate configuration annotations

To override the controller defaults for an issued certificate, set keys on the
`userAnnotations` field of the `podCertificate` projected volume source. This is
the standard Kubernetes mechanism for passing context to a signer: kubelet
copies these keys verbatim into `spec.unverifiedUserAnnotations` of the
resulting `PodCertificateRequest`, which is what the signer reads.

Keys follow the scheme `<signer-domain>/<name>-<item>: <value>` — the signer's
own name as a prefix, then the configuration item:

```yaml
      volumes:
        - name: x509-cert
          projected:
            sources:
              - podCertificate:
                  signerName: coolcert.example.com/foo
                  keyType: ED25519
                  credentialBundlePath: credentialbundle.pem
                  userAnnotations:
                    coolcert.example.com/foo-cn: "some-name.example.com"
                    coolcert.example.com/foo-duration: "2h"
```

| Item | Required | Default | Notes |
| --- | --- | --- | --- |
| `-cn` | No | pod name | Common name. Must resolve to the pod's verified identity unless `--allow-unverified-identities`. Max 64 chars (RFC 5280). |
| `-san` | No | `<pod>.<ns>.pod.<fqdn>,<pod>.<ns>.svc.<fqdn>` | Comma-separated DNS SANs. Subject to identity constraints. |
| `-ip-san` | No | *(empty)* | Comma-separated IP SANs. No verified derivation, so **denied by default** — requires `--allow-unverified-identities`. |
| `-eku` | No | `server` | Extended key usage; tokens `server` and/or `client`. Add `client` to opt into client auth. |
| `-uris` | No | *(empty)* | Comma-separated URI SANs (e.g. SPIFFE IDs). Subject to identity constraints. |
| `-duration` | No | `24h` | Certificate lifetime. Clamped to the request's `maxExpirationSeconds`; minimum `1h`. |
| `-refresh` | No | `15m` | Refresh hint (`beginRefreshAt`). At least `10m`, at most `duration − 10m`. |

> [!NOTE]
> Keys the signer does not recognise, and malformed values (e.g. an invalid
> duration), deny the request with reason `InvalidUnverifiedUserAnnotations`, as
> the Kubernetes API contract for signers recommends.

### Interpolating pod identity into values

> [!IMPORTANT]
> This is a feature flag, **disabled by default**. Enable it with
> `--enable-annotation-interpolation` (Helm:
> `signer.enable_annotation_interpolation: true`). While disabled, values
> containing `${...}` are denied rather than issued verbatim.

A value authored on a pod template is identical for every replica, so a static
`cn` can never carry the pod's own name. With interpolation enabled, the `cn`,
`san` and `uris` values may contain `${...}` placeholders resolved per request:

```yaml
                  userAnnotations:
                    coolcert.example.com/foo-cn: "${pod.name}.${pod.namespace}.svc.${cluster.fqdn}"
                    coolcert.example.com/foo-san: "${pod.name}.${pod.namespace}.svc,${pod.serviceAccountName}.${pod.namespace}"
                    coolcert.example.com/foo-uris: "spiffe://${cluster.fqdn}/ns/${pod.namespace}/sa/${pod.serviceAccountName}"
```

Every variable resolves from fields of the `PodCertificateRequest` that kubelet
populates and the apiserver verifies (never from user-controlled input), so a
workload can only interpolate its **own** verified identity:

| Variable | Value |
| --- | --- |
| `${pod.name}` | Name of the pod the certificate is issued to |
| `${pod.namespace}` | Namespace of the pod |
| `${pod.uid}` | UID of the pod |
| `${pod.serviceAccountName}` | Service account the pod runs as |
| `${node.name}` | Node the pod is scheduled on |
| `${cluster.fqdn}` | Cluster FQDN from `--cluster-fqdn` |

Unknown variables and unterminated placeholders deny the request with reason
`InvalidUnverifiedUserAnnotations`. Values are validated **after** expansion,
including the 64-character common-name limit and DNS-1123 SAN limits. DNS SAN
labels may contain at most 63 characters and the complete name at most 253;
wildcard SANs are not supported.

#### What bounds interpolation

Interpolation is a **naming** mechanism, not an authorization one. Two properties
bound it, and it is worth being precise about which does what, because the second
is the one people mistake this feature flag for.

1. **Where values come from.** The variable table above is the whole table.
   Every entry resolves from a `PodCertificateRequest` spec field that kubelet
   populates and kube-apiserver verifies, except `${cluster.fqdn}`, which comes
   from the operator's own `--cluster-fqdn`. No user-controlled input reaches it.
   Expansion is a single non-recursive pass — a resolved value cannot itself
   contain `${...}`, because Kubernetes object names and UIDs cannot.
2. **What the resolved value is then checked against.** Every expanded `cn`,
   `san` and `uris` value must be an exact string member of the
   [verified-identity allowlist](#identity-constraints-security). The comparison
   is **exact string equality**, never a prefix or pattern match — which is why
   `${pod.name}.evil.example.com` is denied even though it begins with a name the
   pod owns.

Together these mean an interpolated value is subject to **exactly the same
identity check as a literal one**. The check is membership-based and does not
care how the string was produced, so interpolation grants no identity a pod does
not already own. What it buys is portability — the same pod template across
namespaces and clusters — plus per-pod values like `${pod.name}` that cannot be
written literally in a shared Deployment at all.

> [!IMPORTANT]
> **The security gate is `--allow-unverified-identities`, not this flag.** That
> is the setting that decides whether a pod may claim an identity it does not
> own. `--enable-annotation-interpolation` decides only whether `${...}` is
> resolved or rejected as a value; it is not a substitute for the identity
> constraints and does not weaken them.

**Claimable** via interpolation: the pod's name, its canonical Kubernetes DNS
forms, its SPIFFE ID, and its service account's short DNS form `<sa>.<ns>` and
SPIFFE ID. `${node.name}` and `${pod.uid}` resolve but are **not** claimable as a
subject — a node identity belongs to the kubelet, and a UID is an opaque token.
The boundary of that set, including which forms are deliberately excluded and
why, is recorded in
[ADR-0001](adr/0001-verified-identity-allowlist-boundary.md).

### CSR-requested SANs (forward compatibility)

Upstream Kubernetes plans to let pod authors request DNS and IP SANs that
kubelet embeds in the PKCS#10 CSR of the `PodCertificateRequest` (today kubelet
generates empty CSRs). The controller is ready for this behind
`--honor-csr-sans` (Helm: `signer.honor_csr_sans`, disabled by default): when
enabled, CSR-requested DNS and IP SANs are used unless a `san`/`ip-san`
annotation overrides them. CSR SANs stay subject to the [identity
constraints](#identity-constraints): unless `--allow-unverified-identities` is
set, a CSR-requested DNS SAN must resolve to a verified pod identity and
CSR-requested IP SANs are denied (an IP has no verified derivation). While
disabled, CSR SANs are ignored — which the API contract explicitly permits.

Until then, IP SANs can be requested via the `ip-san` annotation; once kubelet
gains native SAN support the same values move into the pod spec and the
annotation becomes the override.

### Configuration via pod annotations (deprecated)

> [!WARNING]
> Configuration via pod `annotations` is deprecated and will be removed in a
> future release — use `unverifiedUserAnnotations` instead. When both are set,
> `unverifiedUserAnnotations` take precedence.

The same items (`cn`/`san`/`ip-san`/`eku`/`uris`/`duration`/`refresh`) can be
set as pod [`annotations`](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/)
with the same `<signer>/<name>-<item>` keys, e.g.
`coolcert.example.com/foo-cn: some-name.example.com`. This path predates
`userAnnotations` and is kept only for compatibility.

## Identity constraints

> [!IMPORTANT]
> By default the signer issues certificates only for the **requesting pod's own
> verified identity**. A `cn`, `san` or `uris` value is accepted only when it
> resolves to an identity the signer derives from the apiserver-verified
> `PodCertificateRequest` fields — the pod's name, its canonical Kubernetes DNS
> forms (`<pod>.<ns>.pod[.<fqdn>]`, `<pod>.<ns>.svc[.<fqdn>]`), its SPIFFE ID, or
> its service account (`<sa>.<ns>` and the SA SPIFFE ID). Any other value is
> **Denied**, so a pod author cannot obtain a certificate for an identity it does
> not own (e.g. `kubernetes.default.svc` or another team's service).

Because a value authored on a pod template is identical for every replica, the
intended way to set per-pod identities is `${...}` interpolation of verified
fields (above); a literal `cn` that does not match the pod's verified identity is
denied. `node.name` and `pod.uid` are available for interpolation but are **not**
claimable as a certificate subject (a node identity belongs to the kubelet; a UID
is opaque). `ip-san` values have no verified derivation and are denied.

**Escape hatch (not recommended).** To lift these constraints — allowing
arbitrary literal `cn`/`san`/`ip-san`/`uris` values — start the controller with
`--allow-unverified-identities` (Helm: `signer.allow_unverified_identities:
true`). Only do this if a `ValidatingAdmissionPolicy` (or equivalent) already
restricts which annotations workloads may set.

> [!WARNING]
> **Breaking change.** Earlier releases issued certificates for arbitrary literal
> `cn`/`san`/`ip-san`/`uris` values and included `clientAuth` in the default
> extended key usage. Both defaults have changed: unverified identities are now
> denied, and the default EKU is `serverAuth` only. To restore the previous
> behaviour set `signer.allow_unverified_identities: true` **and** add
> `eku: server,client`; the recommended migration is to switch literal values to
> `${...}` interpolation and request client auth explicitly with `eku`.

### Restricting annotations with a ValidatingAdmissionPolicy

[`examples/validating-admission-policy.yaml`](https://github.com/rafpe/pod-certificate-signer/blob/main/examples/validating-admission-policy.yaml)
is a ready-to-apply `ValidatingAdmissionPolicy` and binding that decides, at
admission time, which pods may set signer-prefixed `userAnnotations`:

- `cn`, `san`, `ip-san` and `uris` claim an identity, so they are rejected unless
  the pod's namespace carries an allowlist label — on the deprecated pod
  `annotations` path too, which no flag disables and which would otherwise be an
  open bypass;
- `eku`, `duration` and `refresh` only shape a certificate the pod is already
  entitled to, so any namespace may set them;
- any other key using the signer's prefix is rejected as a typo.

[`examples/validating-admission-policy-eku.yaml`](https://github.com/rafpe/pod-certificate-signer/blob/main/examples/validating-admission-policy-eku.yaml)
is a second, standalone example focused on `eku`: it restricts which extended key
usages a workload may request (`server`, `client`, or both) based on a namespace
label, so client-auth certificates can be confined to specific namespaces.

**When to use it.** If you enable `--allow-unverified-identities`, this policy is
what replaces the protection you switched off — without it any pod author can
request a certificate for any name. Under the default constraints it is still
worth applying as defense in depth: a pod rejected at admission gets an immediate
error, instead of a volume that never mounts and a `Denied` request to go read.

### Preventive DNS SAN admission policy

The chart can also manage a signer-specific DNS SAN policy. Policies live under
the `admissionPolicies` map so each policy remains independently selectable as
the catalog grows:

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

The policy inspects Pods on create and update when a projected `podCertificate`
volume names this chart's `signer.name` and supplies the matching `-san`
`userAnnotations` key. It expands the values available at admission time
(`${pod.name}`, `${pod.namespace}`, `${pod.serviceAccountName}`, and
`${cluster.fqdn}`), then checks comma-separated DNS names, label lengths, total
length, and DNS-1123 syntax. It ignores other signers, Pods without an explicit
SAN annotation, CSR SANs, and generated defaults; those remain signer-side
concerns.

Start with `Warn` and `Audit`, observe warnings/audit events, narrow rollout with
`namespaceSelector` or `objectSelector` if needed, then use `Deny`. Kubernetes
does not allow `Deny` and `Warn` together in one binding, and the chart schema
rejects that combination. The feature is disabled by default because enabling a
cluster-scoped admission control is an operator rollout decision.

This is complementary defense in depth, not an alternative to signer
validation. The signer validates annotation, CSR, and generated DNS SANs after
the source is resolved in both constrained and
`--allow-unverified-identities` modes. That flag relaxes ownership checks only;
it never permits malformed DNS identities.

## Validation rules

The controller performs these validations by default:

1. **CA files present** — the mounted CA cert/key files exist and load.
2. **CA valid** — the CA is a valid, non-expired CA.
3. **Cluster FQDN valid** — `--cluster-fqdn` is a DNS-1123 subdomain; invalid
   operator configuration fails controller startup.
4. **Request configuration** — the `unverifiedUserAnnotations` (or deprecated
   annotations) are validated against the constraints the apiserver enforces on
   the request status, so misconfigurations are denied immediately:
   - Duration is at least `1h` and no more than the request's
     `spec.maxExpirationSeconds` (default `24h`); the default is clamped to it.
   - The refresh hint lies within `beginRefreshAt`: at least `10m` and at most
     the certificate duration minus `10m`.
   - `eku` accepts `client` and/or `server`; unknown tokens deny. The default is
     `serverAuth` only. Certificates for non-RSA keys carry only the
     `digitalSignature` key usage.
   - Every selected DNS SAN is a DNS-1123 subdomain with labels of at most 63
     characters and a total length of at most 253 characters. Invalid values are
     rejected, never truncated or rewritten. Wildcard SANs are rejected.

## Controller CLI flags

The chart renders these from Helm values; you rarely set them directly.

```
  -allow-unverified-identities
        Allow cn/san/ip-san/uris values that do not resolve to the pod's verified
        identity. Off by default.
  -ca-cert-path string        CA certificate file.
  -ca-key-path string         CA private key file.
  -cluster-fqdn string        FQDN of the cluster (default "cluster.local").
  -enable-annotation-interpolation
        Allow ${...} placeholders in certificate configuration annotations.
  -health-probe-bind-address string   Probe endpoint address (default ":8081").
  -honor-csr-sans             Honor DNS/IP SANs from the kubelet PKCS#10 CSR.
  -kubeconfig string          Kubeconfig path; only for out-of-cluster runs.
  -leader-elect               Enable leader election.
  -leader-election-id string  Leader-election ConfigMap name (default "pcs-leader-election").
  -leader-election-namespace string   Leader-election namespace (default: pod's namespace).
  -max-concurrent-reconciles int      Max concurrent reconciles (default 5).
  -max-previous-ca-certs int  Previous CAs retained across rotation (default 2).
  -metrics-bind-address string        Metrics server address (default ":9090").
  -metrics-secure
        Serve /metrics over HTTPS and require authn (TokenReview) + authz
        (SubjectAccessReview) for every scrape. On by default; set false for the
        legacy unauthenticated plaintext endpoint.
  -reconcile-timeout duration Per-reconcile timeout (default 5m0s).
  -signer-name string         Only sign requests with this .spec.signerName. Required.
  -zap-* ...                  Standard zap logging flags (encoder, level, time encoding).
```

## Helm values

The complete values reference — every key, default and the CA-source abstraction
— lives in the [chart README](../charts/pod-certificate-signer/README.md) and is
documented inline in
[`values.yaml`](../charts/pod-certificate-signer/values.yaml). The essentials:

### Providing the CA

The signing CA is configured under `signer.ca` with an explicit `source`:

- **`secretRef` (recommended, default)** — mount an existing Secret. The private
  key stays in a Secret, the chart wires a read-only volume for you, and only the
  CA cert + key are projected into the pod. `signer.ca.secretRef.name` is
  **required**; an empty name fails `helm install`/`upgrade` at render time.
- **`file` (advanced / BYO mount)** — you mount the cert/key yourself via
  `.Values.volumes` / `.Values.volumeMounts` and point `signer.ca.file.certPath`
  / `keyPath` at them.

```yaml
signer:
  name: coolcert.example.com/foo
  ca:
    source: secretRef
    secretRef:
      name: podcertificate-signer-ca
      certKey: tls.crt
      keyKey: tls.key
      mountPath: /app/signer/ca
```

### Metrics authentication

The metrics endpoint (`:9090/metrics`) is **secured by default**
(`metrics.insecure: false`): it is served over **HTTPS** and every scrape must
be **authenticated** with a Kubernetes bearer token (verified via a
`TokenReview`) and **authorized** with a `SubjectAccessReview` for `get` on the
`/metrics` nonResourceURL. This closes the previous exposure where any pod that
could reach the Service could scrape the controller's metrics.

> [!WARNING]
> **Breaking change.** Unauthenticated plaintext scrapes that worked before now
> fail. A scraper must present a `ServiceAccount` token and trust (or skip
> verifying) the controller's self-signed serving certificate.

To let Prometheus scrape the secured endpoint:

1. Bind the chart's `*-metrics-reader` `ClusterRole` (grants `get` on the
   `/metrics` nonResourceURL) to the ServiceAccount Prometheus scrapes with:

   ```yaml
   apiVersion: rbac.authorization.k8s.io/v1
   kind: ClusterRoleBinding
   metadata:
     name: pod-certificate-signer-metrics-reader
   roleRef:
     apiGroup: rbac.authorization.k8s.io
     kind: ClusterRole
     name: pod-certificate-signer-metrics-reader
   subjects:
   - kind: ServiceAccount
     name: prometheus
     namespace: monitoring
   ```

2. Configure the scrape (e.g. a Prometheus Operator `ServiceMonitor`) to use the
   `https` scheme, the pod's bearer token, and either the serving CA or
   `insecureSkipVerify: true` (the serving cert is self-signed, generated in
   memory by controller-runtime):

   ```yaml
   endpoints:
   - port: metrics
     scheme: https
     bearerTokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token
     tlsConfig:
       insecureSkipVerify: true
   ```

The controller ServiceAccount is granted `create` on `tokenreviews` and
`subjectaccessreviews` by the chart so the auth filter can call the apiserver.
Annotation-based Prometheus scraping (the `prometheus.io/*` pod annotations)
cannot supply a token and will not authenticate against the secured endpoint —
use a `ServiceMonitor` (or equivalent) instead.

**Escape hatch.** To restore the legacy unauthenticated plaintext endpoint, set
`metrics.insecure: true` (renders `--metrics-secure=false`). Only do this when
the metrics port is protected by other means (e.g. a NetworkPolicy and a trusted
network). The chart also ships an optional `metrics.networkPolicy` (off by
default) to restrict ingress to the metrics port.

### Recommended production posture

The chart ships production-safe defaults and needs no extra manifests: restricted
PSS (non-root, read-only rootfs, all capabilities dropped), `replicaCount: 2`
with leader election, resource requests and limits, and a PodDisruptionBudget.
Review these two for your cluster:

- **Resource requests and limits.** Set by default for a lightweight, mostly-idle
  point-reconciler. Tune for your cluster size; `resources: {}` leaves the
  container unconstrained.

  ```yaml
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 256Mi
  ```

- **PodDisruptionBudget.** Enabled by default. With two leader-elected replicas,
  `minAvailable: 1` lets a node be drained one replica at a time while always
  keeping a pod that can hold the lease. `unhealthyPodEvictionPolicy:
  AlwaysAllow` lets a drain evict a replica that is not yet Ready, so a bad pod
  cannot wedge the drain.

  ```yaml
  podDisruptionBudget:
    enabled: true
    minAvailable: 1
    maxUnavailable: ""   # mutually exclusive with minAvailable, which wins if both are set
    unhealthyPodEvictionPolicy: AlwaysAllow
  ```

> [!IMPORTANT]
> If you enable the HPA and it scales the Deployment down to a single replica,
> `minAvailable: 1` blocks node drains for that sole pod. Switch to
> `maxUnavailable: 1` in that case.
