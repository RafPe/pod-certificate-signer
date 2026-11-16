# Security Policy

pod-certificate-signer is a Kubernetes controller. It signs
[PodCertificateRequests](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#pod-certificate-requests)
with a CA private key that it holds. It publishes that CA as a
[ClusterTrustBundle](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#cluster-trust-bundles),
and workloads across the cluster can mount that bundle as a trust anchor.
Thus the controller is security-critical infrastructure. A bug in the signer,
or a bad configuration of its deployment, can let an attacker forge identities
across the cluster. Read the threat model below before you deploy the
controller and before you report an issue.

## Reporting a vulnerability

**Do not open a public issue for a suspected vulnerability.**

- Preferred: use GitHub's private vulnerability reporting —
  [Report a vulnerability](https://github.com/RafPe/pod-certificate-signer/security/advisories/new)
  on the repository's **Security** tab.
- Fallback: email the maintainer at `rpieniaz@gmail.com` with
  `[SECURITY] pod-certificate-signer` in the subject.

Include these items in the report:

- the version (image tag and chart version)
- the relevant controller flags and Helm values
- a reproduction, or a clear description of the impact

What to expect:

- Acknowledgement within **7 days**.
- An assessment within **30 days**: accepted, duplicate of a tracked issue, or
  out of scope. An accepted report also gets a remediation plan in that time.
- Coordinated disclosure: we ask for up to **90 days** before public
  disclosure. The advisory credits the reporter, unless the reporter prefers
  no credit.

The threat model below documents the known security limitations. You do not
need to report a documented limitation again. But we welcome a report that
shows a limitation is *worse* than the description.

## Supported versions

Only the newest release line receives security fixes. There are no backports.

| Version  | Supported                             |
| -------- | ------------------------------------- |
| >= 3.1.0 | ✅                                    |
| < 3.1.0  | ❌ — upgrade to the latest release    |

Security fixes ship as patch releases of the current line (image
`ghcr.io/rafpe/pod-certificate-signer`, chart
`oci://ghcr.io/rafpe/charts/pod-certificate-signer`).

## Threat model

### Assets and trust boundaries

| Asset | Why it matters |
| ----- | -------------- |
| CA private key | It signs every pod certificate. If an attacker gets the key, the attacker can forge any identity for as long as workloads trust the CA. |
| Issuance decision (subject, SANs and EKU in each certificate) | It controls which identities a pod can prove. |
| ClusterTrustBundle contents | Any workload can mount the bundle as `ca.crt`. If an attacker adds a CA to the bundle, the whole cluster trusts that CA. |
| Controller's Kubernetes identity (ServiceAccount and RBAC) | It holds `sign` and `attest` on the signer name, and write access to the ClusterTrustBundle. |

The main trust boundary is between **request fields that kube-apiserver
verifies** and **input that the pod author controls**. Kubelet fills
`spec.podName`, `spec.podUID`, `spec.serviceAccountName`, `spec.nodeName` and
the CSR public key, and kube-apiserver verifies them. Kubelet copies
`spec.unverifiedUserAnnotations` **verbatim** from the pod author's
`userAnnotations`. The upstream API contract does not validate this field, by
design. The signer must validate it.

### CA key handling and reload

- The CA certificate and key come from a Secret (`kubernetes.io/tls` or
  `Opaque`) that the chart mounts as a volume. The default paths are
  `/app/signer/ca/tls.crt` and `/app/signer/ca/tls.key`. The controller only
  reads these files. It never writes, logs or serves key material.
- The controller validates the CA on each load. The certificate must have
  `isCA` set with valid basic constraints, and it must carry `keyCertSign`. It
  must not be expired. Its `notBefore` must not be more than 5 minutes in the
  future.
- The signer does not sign a certificate whose requested lifetime goes past the
  CA's `notAfter`. It requeues the request and emits a `CASignerUnusable`
  warning event on it.
- **Rotation** is a hot reload. Update the Secret, and a file watcher on every
  replica reloads the key pair without a restart. The watcher also reloads the
  CA every 60 seconds, so a missed file event does not stop a rotation.
- The controller keeps previous CA certificates (`--max-previous-ca-certs`,
  default 2) in the published ClusterTrustBundle. Thus workloads continue to
  verify certificates from the old CA during the rotation window.
- On startup, the controller reads the previous-CA history back from its
  existing ClusterTrustBundle. It validates each entry and drops entries that
  are not usable CAs, expired entries, duplicates and entries over the limit
  ([ADR-0004](docs/adr/0004-bootstrapped-previous-ca-history.md)).
- The controller does not generate or manage the CA. The operator must issue
  and protect the CA (for example with cert-manager, cfssl or an external PKI).
  The operator also owns RBAC on the CA Secret.

Earlier versions had three limitations in this area. All three are fixed, and
epic [#25](https://github.com/RafPe/pod-certificate-signer/issues/25) is closed:

- The CA watcher runs on every replica, not only on the leader
  ([#27](https://github.com/RafPe/pod-certificate-signer/issues/27)).
- Reload failures that continue fail readiness: 3 consecutive failed attempts
  over at least 10 minutes. A watcher that stops fails readiness at once
  ([#32](https://github.com/RafPe/pod-certificate-signer/issues/32)).
- If the startup read of the existing ClusterTrustBundle fails, the controller
  does not start. It does not start with an empty CA history
  ([#30](https://github.com/RafPe/pod-certificate-signer/issues/30)).

One limitation remains. The controller cannot tell a deleted
ClusterTrustBundle from a first install. In both cases it starts with an empty
CA history, and the next publish removes the previous CAs from the bundle. To
make a missing bundle stop startup, set `--require-ca-history` (Helm
`signer.require_ca_history`) after the first publish. See
[Operations](docs/operations.md#rotating-the-signing-ca).

### Annotation-driven identity (`unverifiedUserAnnotations`)

The signer reads `<signer-name>-cn/san/ip-san/uris/eku/duration/refresh` from
`spec.unverifiedUserAnnotations`. It also reads the same keys from pod
annotations as a deprecated fallback. The `--allow-pod-annotations` flag
controls this fallback. It is on by default and 4.0.0 removes it. The signer
denies a request with an unrecognized signer-prefixed key or a malformed value.
It does not use defaults for it.

**By default, a pod author cannot forge an identity through annotations.**
Each `cn`, `san` and `uris` value, literal or `${...}`-interpolated, must be an
exact string member of the verified identity set
([#26](https://github.com/RafPe/pod-certificate-signer/issues/26),
[#38](https://github.com/RafPe/pod-certificate-signer/issues/38),
[#48](https://github.com/RafPe/pod-certificate-signer/issues/48)). The signer
derives this set from the request's verified fields only. The set contains:

- the pod's own name
- the pod's canonical Kubernetes DNS forms
- the pod's SPIFFE ID
- the service account's short DNS form and SPIFFE ID

The set contains nothing else.
[ADR-0001](docs/adr/0001-verified-identity-allowlist-boundary.md) records this
boundary. The signer **denies** a pod author who requests
`kubernetes.default.svc`, or the service name of another team. No verified
field gives an `ip-san` value, so the signer denies all `ip-san` values.

The check is exact string equality. Thus a near-miss value such as
`${pod.name}.attacker.com` does not match.

Residual exposure, and how to limit it:

- **`--allow-unverified-identities` (default off) removes all of the checks
  above.** It is the one setting that lets a pod get a certificate for any
  identity. If you set it, a multi-tenant cluster **must** also have a
  `ValidatingAdmissionPolicy` that restricts the `userAnnotations` values that
  workloads can request. This policy is a requirement, not an extra. The chart
  can install one. See `admissionPolicies.dnsSANValidation` in
  [docs/configuration.md](docs/configuration.md#preventive-dns-san-admission-policy).
- **`${...}` interpolation** resolves only from request fields that
  kube-apiserver verifies (`pod.name`, `pod.namespace`, `pod.uid`,
  `pod.serviceAccountName`, `node.name`). It also resolves the
  `cluster.fqdn` value that the operator sets.
  - Interpolation is the intended way to express a per-pod identity. Without it,
    a value on a pod template is the same for every replica.
  - The signer resolves `node.name` and `pod.uid`, but they are not in the
    verified identity set.
  - An interpolated value gets the same identity check as a literal value.
    Thus it reaches only identities that the pod already owns. It names an
    identity. It does not authorize one.
  - For this reason interpolation is **on by default**
    (`--enable-annotation-interpolation`). Set the flag to `false` to deny all
    values that contain `${`.
  - "Interpolating pod identity into values" in
    [docs/configuration.md](docs/configuration.md#interpolating-pod-identity-into-values)
    documents the feature.
    [ADR-0002](docs/adr/0002-annotation-interpolation-on-by-default.md) records
    the reasons.
- Use the `eku` annotation to limit certificates to `client` or `server` use.
  The default is `serverAuth` **only**. You must request `clientAuth`
  explicitly.
- A `ValidatingAdmissionPolicy` is also useful with the default constraints. It
  tells the pod author about a bad value at admission time. Without it, the
  pod author sees a denial later, on the PodCertificateRequest.

### CSR-requested SANs

`--honor-csr-sans` (default **off**) prepares for a future Kubernetes feature.
With it, pod authors can request SANs in the PKCS#10 CSR that kubelet makes.
Today kubelet makes empty CSRs, so this path has no effect. Since
[#80](https://github.com/RafPe/pod-certificate-signer/pull/80), CSR SANs get
the **same** identity checks as annotation values. CSR DNS names must be in the
verified identity set, and the signer denies all CSR IP SANs. Both checks apply
unless `--allow-unverified-identities` is set. Kube-apiserver verifies the CSR
signature during admission. The signer only reads the public key and any
requested SANs from the CSR.

### ClusterTrustBundle

- The controller publishes exactly one bundle,
  `<signer-domain>:<signer-path>:bundle`. It contains the current CA, followed
  by the retained previous CAs. Every workload that mounts this bundle can
  trust its contents. Thus write access to ClusterTrustBundles is a trust
  decision for the whole cluster.
- The signer issues **leaf** certificates only. The signing template sets
  `basicConstraints` with `cA:FALSE`
  ([ADR-0003](docs/adr/0003-leaf-basic-constraints-ca-false.md)). Thus an
  issued certificate cannot sign other certificates.
- Only the elected leader publishes the bundle. It publishes on startup, after
  each CA change, and every 10 minutes to repair drift. Each publish gets up to
  5 attempts with exponential backoff. If all attempts fail, the leader fails
  readiness until a later publish succeeds
  ([#31](https://github.com/RafPe/pod-certificate-signer/issues/31), closed).

### Signer RBAC

The Helm chart gives the controller only the permissions it needs. Review them
before you add permissions:

- **ClusterRole**:
  - `pods`: `get` only, to read the requesting pod directly. There is no
    `list` or `watch`, so the controller does not cache all pods.
  - `podcertificaterequests`: `get`, `list`, `watch`.
  - `podcertificaterequests/status`: `get`, `update`, `patch`, to issue or
    deny.
  - `clustertrustbundles`: `get`, `create`, `update`, `patch`. There is
    **no** `list` or `watch`, so the controller cannot list or cache the
    bundles of other signers.
  - `events` (core and `events.k8s.io`): `create`, `patch`.
  - `signers`: `sign` and `attest`, restricted by `resourceNames` to the one
    configured signer name.
  - `tokenreviews` and `subjectaccessreviews`: `create`, to authenticate
    metrics scrapes. The chart omits these rules when `metrics.insecure` is
    set.
- **Role** (namespaced): coordination `leases` for leader election only.
  `create`, and `get` and `update` on the one named Lease.
- The controller has **no** RBAC on Secrets. It gets the CA only as a volume
  mount. It cannot read other Secrets, change pods, or sign for other signer
  names.

Deployment hardening defaults: the chart complies with the *restricted* Pod
Security Standard. It uses a distroless non-root image,
`readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, no capabilities
and seccomp `RuntimeDefault`.

The metrics endpoint (`:9090`) uses HTTPS and authentication by default since
[#82](https://github.com/RafPe/pod-certificate-signer/pull/82). Each scrape
must send a bearer token that passes a TokenReview. A SubjectAccessReview must
also allow `GET` on the `/metrics` nonResourceURL. The chart makes a
`metrics-reader` ClusterRole for scrapers to bind to.
`--metrics-secure=false` (Helm `metrics.insecure: true`) restores the old
plaintext endpoint without authentication. If you set it, restrict the port
with a NetworkPolicy. The chart can make one
(`metrics.networkPolicy.enabled`).

## Scope

**In scope** (report these):

- Certificate mis-issuance that the documented limitations do not explain:
  - identities that the configuration and admission setup should prevent
  - bypasses of interpolation restrictions
  - denial of issuance to other tenants
- Exposure of CA key material by the controller (logs, metrics, API objects,
  error messages).
- ClusterTrustBundle poisoning or corruption through the controller.
- Privilege escalation that the chart's default RBAC or deployment settings
  make possible.
- Vulnerabilities in the release supply chain (published images, charts, or
  the workflows that build them).

**Out of scope**:

- Attacks that need cluster-admin, direct access to the CA Secret, node
  compromise, or a compromised kubelet or kube-apiserver. The signer trusts
  the Kubernetes control plane by design.
- Reports of the documented limitations above. This includes certificates for
  arbitrary identities in a cluster that sets `--allow-unverified-identities`
  without the required admission policy.
- Denial of service against kube-apiserver through mass PodCertificateRequest
  creation. Rate limiting is a concern of kube-apiserver and its priority and
  fairness settings.
- Vulnerabilities in Kubernetes, the container runtime, or dependencies that
  have no reachable call path from this code base (see the Scorecard notes
  below).

## Dependency and supply-chain notes

- We triage dependency vulnerabilities with `govulncheck`. It reports a
  vulnerability only when this code base can call the affected function. A
  package in `go.mod` alone is not enough.
- The release workflow builds the image from the tagged source, on a
  distroless base, for `linux/amd64` and `linux/arm64`.
- A gitleaks scan of the full history runs in CI to find committed key
  material.
- **Known issue: historical CA key leak.** Early in the project history, a
  commit added a sample CA private key (`hack/ca-key.pem`, also embedded in
  `examples/ca_tls_secret.yaml`).
  [#37](https://github.com/RafPe/pod-certificate-signer/pull/37) removed it.
  The removal does not rewrite history, so old commits still contain the key.
  The key is **permanently compromised**. It was only a development sample.
  But if any cluster loaded it as a real signing CA, rotate that CA
  immediately. Do not trust any certificate it signed, or any trust bundle
  that contains it. The gitleaks configuration allowlists those two
  historical paths by name. It does not allow new key material.

## Accepted OpenSSF Scorecard findings

We expect the Scorecard checks below to stay red, and we **accept** them for
these reasons:

| Check | Status | Rationale |
| ----- | ------ | --------- |
| Code-Review | Accepted, narrowing | The project has one maintainer. Ordinary PRs merge after automated checks (tests, lint, e2e, secret scan) without a second human review. Two categories have a human review. A release publishes only after a maintainer approves the generated release PR ([#86](https://github.com/RafPe/pod-certificate-signer/pull/86)). An Architecture Decision Record needs at least one approving maintainer review before acceptance (see [CONTRIBUTING.md](CONTRIBUTING.md#review)). Thus a person reviews the decisions that govern future code and the artifacts that users get. Nobody reviews the routine changes between them. |
| Fuzzing | Accepted | There is no continuous fuzzing. The Go standard library parses x509, PEM and PKCS#10. Unit tests cover the parsing that this project adds. |
| CII-Best-Practices | Accepted | The project does not apply for an OpenSSF Best Practices badge at this stage. |
| Vulnerabilities | Accepted (case-by-case) | Scorecard flags an OSV entry when the package is in the dependency graph. This project triages by `govulncheck` reachability. We accept and document findings that have no reachable call path. |

We do not accept the checks below. The repository has these controls:

- SAST: a CodeQL workflow (`.github/workflows/codeql.yml`).
- Signed-Releases: the release workflow signs the image index by digest with
  keyless cosign, and attaches an SPDX SBOM to the image. The workflow does not
  sign the Helm chart.
- Pinned-Dependencies and Token-Permissions: workflows pin third-party actions
  by commit SHA and declare `permissions`.
- Dependency-Update-Tool: Dependabot (`.github/dependabot.yml`).

If one of these controls stops working, treat it as a bug and report it.
