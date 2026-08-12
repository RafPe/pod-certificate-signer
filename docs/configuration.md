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
including the 64-character common-name limit.

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

## Validation rules

The controller performs these validations by default:

1. **CA files present** — the mounted CA cert/key files exist and load.
2. **CA valid** — the CA is a valid, non-expired CA.
3. **Request configuration** — the `unverifiedUserAnnotations` (or deprecated
   annotations) are validated against the constraints the apiserver enforces on
   the request status, so misconfigurations are denied immediately:
   - Duration is at least `1h` and no more than the request's
     `spec.maxExpirationSeconds` (default `24h`); the default is clamped to it.
   - The refresh hint lies within `beginRefreshAt`: at least `10m` and at most
     the certificate duration minus `10m`.
   - `eku` accepts `client` and/or `server`; unknown tokens deny. The default is
     `serverAuth` only. Certificates for non-RSA keys carry only the
     `digitalSignature` key usage.

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

### Recommended production posture

The chart ships production-safe security defaults (restricted PSS, non-root,
read-only rootfs) and `replicaCount: 2` with leader election. Two things are
left as a conscious operator choice and should be set for production:

- **Resource requests and limits.** `resources` is `{}` by default. Set modest
  requests/limits — the controller is a lightweight point-reconciler:

  ```yaml
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 200m
      memory: 128Mi
  ```

- **A PodDisruptionBudget.** With two leader-elected replicas, a PDB keeps a
  standby available during voluntary disruptions (node drains, upgrades):

  ```yaml
  apiVersion: policy/v1
  kind: PodDisruptionBudget
  metadata:
    name: pod-certificate-signer
    namespace: pcs-system
  spec:
    minAvailable: 1
    unhealthyPodEvictionPolicy: AlwaysAllow
    selector:
      matchLabels:
        app.kubernetes.io/name: pod-certificate-signer
  ```

> [!NOTE]
> Default `resources` values and a first-class `PodDisruptionBudget` chart
> template are being finalised in the chart (hardening item H8). Until that lands,
> set `resources` via values and apply the PDB above as a plain manifest — this
> is the recommended production posture either way.
