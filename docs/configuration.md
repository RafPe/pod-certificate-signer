# Configuration

This page describes every setting you can change. It covers four topics:

- the certificate annotation contract for each request
- the identity constraints
- the controller CLI flags
- the Helm values, with the recommended production settings

For a first install, see [Getting started](./getting-started.md).

## Certificate configuration annotations

To change the controller defaults for one certificate, set keys in the
`userAnnotations` field of the `podCertificate` projected volume source. This is
the standard Kubernetes mechanism to give a signer more context. Kubelet copies
these keys without change into `spec.unverifiedUserAnnotations` of the
`PodCertificateRequest`. The signer reads them from there.

Each key has the form `<signer-domain>/<name>-<item>: <value>`. The prefix is the
signer name, and the suffix is the configuration item:

```yaml
      volumes:
        - name: x509
          projected:
            sources:
              - podCertificate:
                  signerName: example.org/signer
                  keyType: ED25519
                  credentialBundlePath: credentialbundle.pem
                  userAnnotations:
                    example.org/signer-cn: "${pod.name}.${pod.namespace}.svc.${cluster.fqdn}"
                    example.org/signer-duration: "2h"
```

| Item | Required | Default | Notes |
| --- | --- | --- | --- |
| `-cn` | No | pod name | Common name. Must resolve to the verified identity of the pod, unless `--allow-unverified-identities` is set. Maximum 64 characters (RFC 5280). The default is empty when the pod name is longer than 64 characters. |
| `-san` | No | `<pod>.<ns>.pod.<fqdn>,<pod>.<ns>.svc.<fqdn>` | Comma-separated DNS SANs. Subject to the identity constraints. The signer omits the default when a label of the pod name is longer than 63 characters. |
| `-ip-san` | No | *(empty)* | Comma-separated IP SANs. An IP address has no verified derivation, so the signer **denies it by default**. It requires `--allow-unverified-identities`. |
| `-eku` | No | `server` | Extended key usage. The tokens are `server`, `client`, or both. Add `client` to request client authentication. |
| `-uris` | No | *(empty)* | Comma-separated URI SANs, for example SPIFFE IDs. Subject to the identity constraints. |
| `-duration` | No | `24h` | Certificate lifetime. Minimum `1h`. Maximum is the `maxExpirationSeconds` of the request. The signer reduces the default to that maximum, but denies an explicit value above it. |
| `-refresh` | No | `15m` | Refresh hint (`beginRefreshAt`). Minimum `10m`. Maximum is the duration minus `10m`. |

> [!NOTE]
> The signer denies a request with reason `InvalidUnverifiedUserAnnotations` when
> a key is unknown or a value is malformed, for example an invalid duration. The
> Kubernetes API contract for signers recommends this behavior.

### Interpolating pod identity into values

A value on a pod template is the same for every replica. Thus a static `cn`
cannot contain the name of each pod. Every configuration value can contain
`${...}` placeholders, which the signer resolves for each request. The
placeholders are useful in `cn`, `san` and `uris`:

```yaml
                  userAnnotations:
                    example.org/signer-cn: "${pod.name}.${pod.namespace}.svc.${cluster.fqdn}"
                    example.org/signer-san: "${pod.name}.${pod.namespace}.svc,${pod.serviceAccountName}.${pod.namespace}"
                    example.org/signer-uris: "spiffe://${cluster.fqdn}/ns/${pod.namespace}/sa/${pod.serviceAccountName}"
```

Each variable comes from a `PodCertificateRequest` field that kubelet sets and
the apiserver verifies. No variable comes from user-controlled input. Thus a
workload can interpolate only its **own** verified identity:

| Variable | Value |
| --- | --- |
| `${pod.name}` | Name of the pod that gets the certificate |
| `${pod.namespace}` | Namespace of the pod |
| `${pod.uid}` | UID of the pod |
| `${pod.serviceAccountName}` | Service account of the pod |
| `${node.name}` | Node that runs the pod |
| `${cluster.fqdn}` | Cluster FQDN from `--cluster-fqdn` |

An unknown variable or an unterminated placeholder denies the request with reason
`InvalidUnverifiedUserAnnotations`. The signer validates values **after**
expansion. This includes the 64-character limit for the common name and the
DNS-1123 limits for SANs. A DNS SAN label can have a maximum of 63 characters,
and the full name a maximum of 253. The signer does not support wildcard SANs.

> [!NOTE]
> **Default change.** `${...}` interpolation is now **enabled by default**
> (`--enable-annotation-interpolation=true`, Helm
> `signer.enable_annotation_interpolation: true`). Releases before 2.3.0 shipped
> it disabled. All configurations that worked before continue to work. The flag
> only selects whether the signer resolves or rejects a value that contains
> `${...}`. The signer still compares resolved values to the verified identity of
> the pod by exact string equality. Thus **no identity becomes available that
> was not available before**. See
> [What bounds interpolation](#what-bounds-interpolation) below and
> [ADR-0002](adr/0002-annotation-interpolation-on-by-default.md). To restore the
> previous behavior, set `signer.enable_annotation_interpolation: false`
> (`--enable-annotation-interpolation=false`). The signer then denies `${...}`
> values and does not resolve them.

#### What bounds interpolation

Interpolation is a **naming** mechanism, not an authorization mechanism. Two
properties limit it. Each property has a different function. People often
think that the second property is the function of this feature flag.

1. **Where values come from.** The variable table above is the full list. Each
   entry resolves from a `PodCertificateRequest` spec field that kubelet sets and
   kube-apiserver verifies. The exception is `${cluster.fqdn}`, which comes from
   the `--cluster-fqdn` value of the operator. No user-controlled input gets
   into a value. Expansion is a single pass and is not recursive. A resolved
   value cannot contain `${...}`, because Kubernetes object names and UIDs
   cannot contain it.
2. **What the signer compares the resolved value to.** Each expanded `cn`, `san`
   and `uris` value must be an exact string member of the
   [verified-identity allowlist](#identity-constraints). The comparison is
   **exact string equality**. It is never a prefix or pattern match. Thus the
   signer denies `${pod.name}.evil.example.com`, although its first part is a
   name that the pod owns.

Thus the signer compares an interpolated value **in the same way as a literal
value**. The comparison uses set membership, and the source of the string has no
effect.
Interpolation gives a pod no identity that it does not already own. It gives
portability: one pod template works in different namespaces and clusters. It also
gives values for each pod, such as `${pod.name}`. A shared Deployment cannot
contain such values as literals.

> [!IMPORTANT]
> **The security gate is `--allow-unverified-identities`, not this flag.** That
> setting controls whether a pod can claim an identity that it does not own.
> `--enable-annotation-interpolation` only controls whether the signer resolves
> or rejects `${...}` in a value. It does not replace the identity constraints
> and does not make them weaker.

A pod can **claim** these identities through interpolation:

- its name, `<pod>.<ns>`, and its canonical Kubernetes DNS forms
- its SPIFFE ID
- the short DNS form `<sa>.<ns>` and the SPIFFE ID of its service account

`${node.name}` and `${pod.uid}` resolve, but a pod **cannot claim** them as a
subject. A node identity belongs to the kubelet, and a UID is an opaque token.
[ADR-0001](adr/0001-verified-identity-allowlist-boundary.md) records the limits
of this set. It also records which forms are excluded and why.

### CSR-requested SANs (forward compatibility)

[KEP-4317](https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/4317-pod-certificates) says that a pod author can request DNS and IP SANs, and
that kubelet puts them in the PKCS#10 CSR of the `PodCertificateRequest`. At this time,
kubelet generates empty CSRs. The controller supports this change behind
`--honor-csr-sans` (Helm: `signer.honor_csr_sans`, disabled by default). When the
flag is enabled, the signer uses CSR-requested DNS and IP SANs. A `san` or
`ip-san` annotation overrides them.

CSR SANs are subject to the [identity constraints](#identity-constraints).
Unless `--allow-unverified-identities` is set, these rules apply:

- A CSR-requested DNS SAN must resolve to a verified pod identity.
- The signer denies CSR-requested IP SANs, because an IP address has no verified
  derivation.

When the flag is disabled, the signer ignores CSR SANs. The API contract
explicitly permits this.

Until kubelet supports SANs, use the `ip-san` annotation to request IP SANs.
When kubelet gets native SAN support, the same values move into the pod spec.
The annotation then becomes the override.

### Configuration via pod annotations (deprecated)

> [!WARNING]
> Configuration through pod `annotations` is deprecated. Version 4.0.0 removes
> it. Use `unverifiedUserAnnotations` instead. When both are set,
> `unverifiedUserAnnotations` take precedence. The signer writes a log line for
> each value that it reads from a pod annotation. To find the remaining users
> before you upgrade, use
> `kubectl logs ... | grep "read from a pod annotation"`.

You can set the same items (`cn`/`san`/`ip-san`/`eku`/`uris`/`duration`/`refresh`)
as pod [`annotations`](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/).
The keys are the same `<signer>/<name>-<item>` keys, for example
`example.org/signer-cn: ${pod.name}.${pod.namespace}.svc.${cluster.fqdn}`. This path is older than
`userAnnotations`, and it stays only for compatibility. The signer validates
values from this path in the same way as request values. It denies an item that
is present with an empty value. But it ignores unknown keys and does not deny
them, for these reasons:

- Pod annotations are shared with all other consumers of the pod.
- A signer-name prefix cannot tell a typo from the key of a different signer
  whose name starts with this signer name. For example, a signer
  `example.org/signer` sees `example.org/signer-x-cn` from the signer
  `example.org/signer-x` as an unknown item.

Thus a misspelled pod annotation falls back to the default. Use
`unverifiedUserAnnotations` instead, where an unknown key denies the request.

When all workloads use `unverifiedUserAnnotations`, operators can close the
fallback with `--allow-pod-annotations=false` (Helm:
`signer.allow_pod_annotations: false`). Pod annotations then stop being a second
input that the requester controls. The flag default is `true` until 4.0.0
removes the fallback. An item on the request with an empty value is a
misconfiguration. It denies the request and does not fall back to the pod.

## Identity constraints

> [!IMPORTANT]
> By default, the signer issues certificates only for the **verified identity
> of the requesting pod**. The signer accepts a `cn`, `san` or `uris` value only
> when it resolves to an identity from the apiserver-verified
> `PodCertificateRequest` fields. These identities are:
>
> - the name of the pod, and `<pod>.<ns>`
> - its canonical Kubernetes DNS forms (`<pod>.<ns>.pod[.<fqdn>]`,
>   `<pod>.<ns>.svc[.<fqdn>]`)
> - its SPIFFE ID
> - its service account (`<sa>.<ns>` and the service account SPIFFE ID)
>
> The signer **denies** all other values. Thus a pod author cannot get a
> certificate for an identity that the pod does not own. Examples are
> `kubernetes.default.svc` and the service of a different team.

A value on a pod template is the same for every replica. Thus, to set an
identity for each pod, use `${...}` interpolation of verified fields (see above).
The signer denies a literal `cn` that is not the verified identity of the pod.
`node.name` and `pod.uid` are available for interpolation, but a pod **cannot
claim** them as a certificate subject. A node identity belongs to the kubelet,
and a UID is opaque. `ip-san` values have no verified derivation, and the signer
denies them.

**Escape hatch (not recommended).** To remove these constraints, start the
controller with `--allow-unverified-identities` (Helm:
`signer.allow_unverified_identities: true`). The signer then accepts any literal
`cn`/`san`/`ip-san`/`uris` value. Use this flag only when a
`ValidatingAdmissionPolicy` (or equivalent) already limits the annotations that
workloads can set.

> [!WARNING]
> **Breaking change.** Earlier releases issued certificates for any literal
> `cn`/`san`/`ip-san`/`uris` value. They also included `clientAuth` in the
> default extended key usage. Both defaults changed. The signer now denies
> unverified identities, and the default EKU is only `serverAuth`. To restore
> the previous behavior, set `signer.allow_unverified_identities: true` **and**
> add `eku: server,client`. The recommended migration is different. Change
> literal values to `${...}` interpolation, and request client authentication
> explicitly with `eku`.

### Restricting annotations with a ValidatingAdmissionPolicy

[`examples/validating-admission-policy.yaml`](https://github.com/rafpe/pod-certificate-signer/blob/main/examples/validating-admission-policy.yaml)
contains a `ValidatingAdmissionPolicy` and binding that you can apply as they
are. At admission time, they control which pods can set signer-prefixed
`userAnnotations`:

- `cn`, `san`, `ip-san` and `uris` claim an identity. The policy rejects them
  unless the namespace of the pod has an allowlist label. This also applies to
  the deprecated pod `annotations` path. That path is on by default and is
  otherwise an open bypass. `--allow-pod-annotations=false` closes it at the
  signer instead.
- `eku`, `duration` and `refresh` only change a certificate that the pod can
  already get. Thus any namespace can set them.
- The policy rejects all other keys with the signer prefix as typos.

[`examples/validating-admission-policy-eku.yaml`](https://github.com/rafpe/pod-certificate-signer/blob/main/examples/validating-admission-policy-eku.yaml)
is a second, standalone example for `eku`. It uses a namespace label to control
which extended key usages a workload can request: `server`, `client`, or both.
Thus you can limit client-auth certificates to specific namespaces.

**When to use it.** If you enable `--allow-unverified-identities`, this policy
replaces the protection that you removed. Without it, any pod author can request
a certificate for any name. Also apply it with the default constraints, as
defense in depth. Admission rejects a bad pod immediately with an error. Without
the policy, the volume does not mount, and you must find the `Denied` request.

### Preventive DNS SAN admission policy

The chart can also manage a DNS SAN policy for this signer. Policies are in the
`admissionPolicies` map, so you can select each policy independently as the
catalog grows:

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

The policy examines Pods on create and update. It applies when a projected
`podCertificate` volume names the `signer.name` of this chart and sets the
matching `-san` `userAnnotations` key. The policy expands the values that are
available at admission time: `${pod.name}`, `${pod.namespace}`,
`${pod.serviceAccountName}`, and `${cluster.fqdn}`. Then it checks the
comma-separated DNS names for label length, total length, and DNS-1123 syntax.

The policy ignores these items, which stay the responsibility of the signer:

- other signers
- Pods without an explicit SAN annotation
- CSR SANs
- generated defaults

Start with `Warn` and `Audit`, and monitor the warnings and audit events. If
necessary, use `namespaceSelector` or `objectSelector` to limit the rollout. Then
change to `Deny`. Kubernetes does not allow `Deny` and `Warn` together in one
binding, and the chart schema rejects that combination. The feature is disabled
by default. Enabling a cluster-scoped admission control is a rollout decision
for the operator.

This policy adds defense in depth. It does not replace signer validation. The
signer validates annotation, CSR, and generated DNS SANs after it selects the
source. It does this both with the default constraints and with
`--allow-unverified-identities`. That flag only removes the ownership check. It
never permits malformed DNS identities.

## Validation rules

The controller does these validations by default:

1. **Required flags set.** `--signer-name` must not be empty, and
   `--cluster-fqdn` must not be empty. Otherwise the controller does not start.
2. **Cluster FQDN valid.** `--cluster-fqdn` must be a DNS-1123 subdomain. An
   invalid value stops controller startup.
3. **CA files present.** The mounted CA certificate and key files must exist and
   load.
4. **CA valid.** The certificate must be a CA certificate with the `certSign`
   key usage. It must not be expired. Its `NotBefore` must not be more than 5
   minutes in the future.
5. **Request configuration.** The signer validates the
   `unverifiedUserAnnotations` (or the deprecated pod annotations). It uses the
   same constraints that the apiserver applies to the request status. Thus it
   denies misconfigurations immediately:
   - The duration is a minimum of `1h`. It is not more than the
     `spec.maxExpirationSeconds` of the request (default `24h`). The signer
     reduces the default duration to that maximum.
   - The refresh hint is in the `beginRefreshAt` range: a minimum of `10m`, and a
     maximum of the certificate duration minus `10m`.
   - `eku` accepts `client`, `server`, or both. An unknown token denies the
     request. The default is only `serverAuth`. Certificates for non-RSA keys
     have only the `digitalSignature` key usage. Certificates for RSA keys also
     have `keyEncipherment`.
   - Each selected DNS SAN is a DNS-1123 subdomain. Each label has a maximum of
     63 characters, and the full name a maximum of 253 characters. The signer
     rejects invalid values. It never shortens or changes them. The signer
     rejects wildcard SANs.

## Controller CLI flags

The chart sets these flags from Helm values. Usually you do not set them
directly.

```
  -allow-pod-annotations
        Fall back to the pod's own annotations for items the request's
        userAnnotations do not carry. Deprecated; removed in 4.0.0. On by
        default until then; set false to close the pod-annotation path.
  -allow-unverified-identities
        Allow cn/san/ip-san/uris values that do not resolve to the pod's verified
        identity. Off by default.
  -ca-cert-path string        CA certificate file.
  -ca-key-path string         CA private key file.
  -cluster-fqdn string        FQDN of the cluster (default "cluster.local").
  -enable-annotation-interpolation
        Allow ${...} placeholders in certificate configuration annotations,
        resolved from the verified request fields. On by default; set false to
        deny values containing ${...} instead of resolving them.
  -health-probe-bind-address string   Probe endpoint address (default ":8081").
  -honor-csr-sans             Honor DNS/IP SANs from the kubelet PKCS#10 CSR.
  -kubeconfig string          Kubeconfig path; only for out-of-cluster runs.
  -leader-elect               Enable leader election.
  -leader-election-id string  Leader-election Lease name (default "pcs-leader-election").
  -leader-election-namespace string   Leader-election namespace (default: pod's namespace).
  -max-concurrent-reconciles int      Max concurrent reconciles (default 5).
  -max-previous-ca-certs int  Previous CAs retained across rotation (default 2).
  -metrics-bind-address string        Metrics server address (default ":9090").
  -metrics-secure
        Serve /metrics over HTTPS and require authn (TokenReview) + authz
        (SubjectAccessReview) for every scrape. On by default; set false for the
        legacy unauthenticated plaintext endpoint.
  -reconcile-timeout duration Per-reconcile timeout (default 5m0s).
  -require-ca-history
        Refuse to start when the signer's ClusterTrustBundle does not exist,
        instead of starting with an empty previous-CA history. Off by default;
        turn it on once the bundle has been published (see ADR-0004).
  -signer-name string         Only sign requests with this .spec.signerName. Required.
  -zap-* ...                  Standard zap logging flags (encoder, level, time encoding).
```

The chart sets `--leader-election-id` to the release `fullname`, not to the flag
default. The chart sets `--zap-log-level`, `--zap-encoder` and
`--zap-time-encoding` from the `log` values.

## Helm values

The [chart README](../charts/pod-certificate-signer/README.md) is the full values
reference. It gives every key, every default, and the CA source abstraction.
[`values.yaml`](../charts/pod-certificate-signer/values.yaml) also documents each
value inline. The most important values follow.

### Providing the CA

The signing CA is in `signer.ca`, with an explicit `source`:

- **`secretRef` (recommended, default).** The chart mounts an existing Secret.
  The private key stays in a Secret, and the chart adds a read-only volume for
  you. The chart projects only the CA certificate and key into the pod.
  `signer.ca.secretRef.name` is **required**. An empty name stops
  `helm install` or `helm upgrade` at render time.
- **`file` (advanced, bring your own mount).** You mount the certificate and key
  through `.Values.volumes` and `.Values.volumeMounts`. Then you set
  `signer.ca.file.certPath` and `keyPath` to their paths.

```yaml
signer:
  name: example.org/signer
  ca:
    source: secretRef
    secretRef:
      name: podcertificate-signer-ca
      certKey: tls.crt
      keyKey: tls.key
      mountPath: /app/signer/ca
```

### Metrics authentication

The metrics endpoint (`:9090/metrics`) is **secure by default**
(`metrics.insecure: false`). The controller serves it over **HTTPS**. Each scrape
must have **authentication** with a Kubernetes bearer token, which a
`TokenReview` verifies. Each scrape must also have **authorization**: a
`SubjectAccessReview` for `get` on the `/metrics` nonResourceURL. Before this
change, any pod that could reach the Service could scrape the controller
metrics.

> [!WARNING]
> **Breaking change.** Unauthenticated plaintext scrapes that worked before now
> fail. A scraper must send a `ServiceAccount` token. It must also trust the
> self-signed serving certificate of the controller, or skip verification.

To let Prometheus scrape the secure endpoint, do these steps:

1. Bind the `*-metrics-reader` `ClusterRole` of the chart to the ServiceAccount
   that Prometheus uses to scrape. The role grants `get` on the `/metrics`
   nonResourceURL.

   > [!IMPORTANT]
   > **The name below uses the release name of these docs**
   > (`helm install pod-certificate-signer`). The chart `fullname` helper sets the
   > role name. The name is the release name, then the chart name, unless the
   > release name already contains the chart name. Thus a release called `pcs`
   > gets `pcs-pod-certificate-signer-metrics-reader`, not `pcs-metrics-reader`.
   > If the bound name does not exist, the `SubjectAccessReview` fails. Every
   > scrape then returns `403`, and the controller log does not show the cause.
   > Read the real name from the cluster:
   >
   > ```sh
   > kubectl get clusterrole -o name | grep metrics-reader
   > ```
   >
   > `roleRef` is immutable. To correct a binding, delete it and create it again.
   > You cannot patch it.

   ```yaml
   apiVersion: rbac.authorization.k8s.io/v1
   kind: ClusterRoleBinding
   metadata:
     name: prometheus-metrics-reader
   roleRef:
     apiGroup: rbac.authorization.k8s.io
     kind: ClusterRole
     name: pod-certificate-signer-metrics-reader
   subjects:
   - kind: ServiceAccount
     name: prometheus
     namespace: monitoring
   ```

2. Configure the scrape with the `https` scheme and the bearer token of the pod.
   Also give the serving CA, or set `insecureSkipVerify: true`. The serving
   certificate is self-signed. controller-runtime generates it in memory.

   With a Prometheus Operator `ServiceMonitor`:

   ```yaml
   endpoints:
   - port: metrics
     scheme: https
     bearerTokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token
     tlsConfig:
       insecureSkipVerify: true
   ```

   Without the operator, use the equivalent `scrape_config`. The `keep` regex
   matches `<service name>;<port name>`. The service name comes from the same
   release-dependent `fullname` as the ClusterRole above:

   ```yaml
   - job_name: pod-certificate-signer
     scheme: https
     tls_config:
       insecure_skip_verify: true
     authorization:
       type: Bearer
       credentials_file: /var/run/secrets/kubernetes.io/serviceaccount/token
     kubernetes_sd_configs:
     - role: endpoints
       namespaces:
         names: [pcs-system]
     relabel_configs:
     - source_labels: [__meta_kubernetes_service_name, __meta_kubernetes_endpoint_port_name]
       action: keep
       regex: pod-certificate-signer;metrics
   ```

   Prometheus needs `get`, `list` and `watch` on `services`, `endpoints` and
   `pods` for discovery. That permission is separate from the metrics-reader
   role. The metrics-reader role only authorizes the scrape.

The chart grants the controller ServiceAccount `create` on `tokenreviews` and
`subjectaccessreviews`. The auth filter needs these permissions to call the
apiserver. Annotation-based Prometheus scraping (the `prometheus.io/*` pod
annotations) cannot send a token. Thus it cannot authenticate to the secure
endpoint. Use a `ServiceMonitor` (or equivalent) instead.

**Escape hatch.** To restore the legacy unauthenticated plaintext endpoint, set
`metrics.insecure: true`. The chart then renders `--metrics-secure=false`. Do
this only when a different control protects the metrics port, for example a
NetworkPolicy and a trusted network. The chart also has an optional
`metrics.networkPolicy` (disabled by default) that limits ingress to the metrics
port.

### Recommended production posture

The chart ships production-safe defaults, and needs no extra manifests. The
defaults are:

- the restricted Pod Security Standard: non-root, read-only root file system,
  and all capabilities dropped
- `replicaCount: 2` with leader election
- resource requests and limits
- a PodDisruptionBudget

Examine these two settings for your cluster:

- **Resource requests and limits.** The defaults fit a lightweight controller
  that is idle most of the time. Change them for the size of your cluster.
  `resources: {}` removes all limits from the container.

  ```yaml
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 256Mi
  ```

- **PodDisruptionBudget.** Enabled by default. The chart runs two
  leader-elected replicas. With `minAvailable: 1`, a node drain evicts one
  replica at a time, and one pod can always hold the lease.
  `unhealthyPodEvictionPolicy: AlwaysAllow` lets a drain evict a replica that is
  not Ready. Thus a bad pod cannot block the drain.

  ```yaml
  podDisruptionBudget:
    enabled: true
    minAvailable: 1
    maxUnavailable: ""   # mutually exclusive with minAvailable, which wins if both are set
    unhealthyPodEvictionPolicy: AlwaysAllow
  ```

> [!IMPORTANT]
> If you enable the HPA and it scales the Deployment down to one replica,
> `minAvailable: 1` blocks node drains for that single pod. In that case, change
> to `maxUnavailable: 1`.

## Next steps

To make sure that a setting is active, do these steps:

1. Read the flags that the chart rendered on the controller. The commands on
   this page use the `pcs-system` namespace and the
   `pod-certificate-signer` release name:

   ```sh
   kubectl -n pcs-system get deployment pod-certificate-signer \
     -o jsonpath='{.spec.template.spec.containers[0].command}'
   ```

2. Read the conditions of a `PodCertificateRequest`. A configuration error
   shows a `Denied` condition with reason `InvalidUnverifiedUserAnnotations`.
   The message gives the exact error:

   ```sh
   kubectl describe podcertificaterequest -n <namespace>
   ```

3. Read the controller logs:

   ```sh
   kubectl logs -n pcs-system deployment/pod-certificate-signer
   ```

Then continue with [Operations](./operations.md). It covers CA rotation,
metrics, alerts and troubleshooting.
