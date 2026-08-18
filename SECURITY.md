# Security Policy

pod-certificate-signer is a Kubernetes controller that signs
[PodCertificateRequests](https://kubernetes.io/docs/reference/access-authn-authz/podcertificaterequest/)
with a CA private key it holds, and publishes that CA as a
[ClusterTrustBundle](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#cluster-trust-bundles)
that workloads across the cluster may mount as a trust anchor. That makes it
security-critical infrastructure: a bug in the signer, or a misconfigured
deployment of it, can translate into cluster-wide identity forgery. Please read
the threat model below before deploying it, and before reporting an issue.

## Reporting a vulnerability

**Do not open a public issue for a suspected vulnerability.**

- Preferred: use GitHub's private vulnerability reporting —
  [Report a vulnerability](https://github.com/RafPe/pod-certificate-signer/security/advisories/new)
  on the repository's **Security** tab.
- Fallback: email the maintainer at `rpieniaz@gmail.com` with
  `[SECURITY] pod-certificate-signer` in the subject.

Please include the version (image tag / chart version), the relevant controller
flags and Helm values, and a reproduction or a clear description of the impact.

What to expect:

- Acknowledgement within **7 days**.
- An assessment (accepted / duplicate of a tracked issue / out of scope) and,
  for accepted reports, a remediation plan within **30 days**.
- Coordinated disclosure: we ask for up to **90 days** before public
  disclosure, and will credit reporters in the advisory unless they prefer
  otherwise.

Known, publicly tracked security limitations (see the
[code-quality-review epic #25](https://github.com/RafPe/pod-certificate-signer/issues/25)
and the threat model below) do not need to be re-reported — but reports that
show a tracked limitation is *worse* than described are very welcome.

## Supported versions

Only the newest release line receives security fixes. There are no backports.

| Version  | Supported                             |
| -------- | ------------------------------------- |
| >= 2.2.0 | ✅                                    |
| < 2.2.0  | ❌ — upgrade to the latest release    |

Security fixes ship as patch releases of the current line (image
`ghcr.io/rafpe/pod-certificate-signer`, chart
`oci://ghcr.io/rafpe/charts/pod-certificate-signer`).

## Threat model

### Assets and trust boundaries

| Asset | Why it matters |
| ----- | -------------- |
| CA private key | Signs every pod certificate. Compromise = unlimited identity forgery for as long as the CA is trusted. |
| Issuance decision (subject/SANs/EKU placed into certificates) | Controls which identities a pod can prove. |
| ClusterTrustBundle contents | Mounted as `ca.crt` by arbitrary workloads; poisoning it makes attacker-controlled CAs trusted cluster-wide. |
| Controller's Kubernetes identity (ServiceAccount + RBAC) | Holds `sign`/`attest` on the signer name and write access to the trust bundle. |

The main trust boundary is between **apiserver-verified request fields** and
**pod-author-controlled input**. `spec.podName`, `spec.podUID`,
`spec.serviceAccountName`, `spec.nodeName` and the CSR public key are populated
by kubelet and verified by kube-apiserver. `spec.unverifiedUserAnnotations` is
copied **verbatim** from the pod author's `userAnnotations` and is, per the
upstream API contract, unvalidated by design — validating it is the signer's
responsibility.

### CA key handling and reload

- The CA certificate and key are mounted from a `kubernetes.io/tls` Secret
  (default paths `/app/signer/ca/tls.crt` / `tls.key`). The controller only
  reads them from disk; it never writes, logs, or serves key material.
- On load the CA is validated: it must be a CA (`isCA` + basic constraints),
  carry `keyCertSign`, and be unexpired. Signing is refused when the requested
  certificate lifetime would outlive the CA.
- **Rotation** is a hot-reload: update the Secret (or the mounted files) and a
  filesystem watcher reloads the key pair without a restart. Previously used
  CA certificates are retained (`--max-previous-ca-certs`, default 2) and kept
  in the published trust bundle so workloads keep verifying certificates
  issued by the old CA during the rollover window. CA history is re-seeded
  from the existing ClusterTrustBundle on startup.
- The controller never generates or manages the CA itself — issuing and
  protecting the CA (e.g. via cert-manager, cfssl, or an external PKI) is the
  operator's responsibility, as is RBAC on the CA Secret.

Known limitations, tracked in epic [#25](https://github.com/RafPe/pod-certificate-signer/issues/25)
with fixes in flight: the reload watcher is tied to the leader-elected replica
([#27](https://github.com/RafPe/pod-certificate-signer/issues/27)), a failed
reload is logged but not surfaced via health probes
([#32](https://github.com/RafPe/pod-certificate-signer/issues/32)), and a
failed startup read of the existing bundle starts with empty CA history
([#30](https://github.com/RafPe/pod-certificate-signer/issues/30)).

### Annotation-driven identity (`unverifiedUserAnnotations`)

The signer reads `<signer-name>-cn/san/ip-san/uris/eku/duration/refresh` from
`spec.unverifiedUserAnnotations` (with a deprecated fallback to pod
annotations). Unrecognized signer-prefixed keys and malformed values deny the
request rather than falling back to defaults.

**Annotation forgery is closed by default.** Every `cn`, `san` and `uris`
value — literal or `${...}`-interpolated — must be an exact string member of the
set of identities the signer derives from the request's apiserver-verified
fields ([#26](https://github.com/RafPe/pod-certificate-signer/issues/26),
[#38](https://github.com/RafPe/pod-certificate-signer/issues/38),
[#48](https://github.com/RafPe/pod-certificate-signer/issues/48)). That set is
the pod's own name, its canonical Kubernetes DNS forms, its SPIFFE ID, and its
service account's short DNS form and SPIFFE ID — and nothing else; the boundary
is recorded in
[ADR-0001](docs/adr/0001-verified-identity-allowlist-boundary.md). A pod author
who requests `kubernetes.default.svc`, or another team's service name, is
**Denied**. `ip-san` values have no verified derivation from the request and are
denied outright.

The check is exact string equality, which is what closes near-miss forgeries
like `${pod.name}.attacker.com`.

Residual exposure and how to bound it:

- **`--allow-unverified-identities` (default off) lifts all of the above.** It
  is the one setting that restores arbitrary-identity issuance. If you turn it
  on, a `ValidatingAdmissionPolicy` restricting which `userAnnotations` values
  workloads may request becomes a **required prerequisite** in a multi-tenant
  cluster, not a bonus hardening. The chart can install one; see
  `admissionPolicies.dnsSANValidation` in `docs/configuration.md`.
- **`${...}` interpolation** resolves exclusively from apiserver-verified
  request fields (`pod.name`, `pod.namespace`, `pod.uid`,
  `pod.serviceAccountName`, `node.name`) plus the operator-configured
  `cluster.fqdn`. It is the intended way to express per-pod identity, because a
  value authored on a pod template is otherwise identical for every replica.
  `node.name` and `pod.uid` are resolvable but not claimable as a subject. An
  interpolated value is subject to exactly the same identity check as a literal
  one; it is gated by `--enable-annotation-interpolation`, documented under
  "Interpolating pod identity into values" in `docs/configuration.md`.
- Use the `eku` annotation to narrow certificates to `client` or `server` as
  needed. The default is `serverAuth` **only** — `clientAuth` is an explicit
  opt-in.
- A `ValidatingAdmissionPolicy` remains useful even under the default
  constraints: it gives the pod author immediate feedback at admission rather
  than a denial that surfaces later on the PodCertificateRequest.

### CSR-requested SANs

`--honor-csr-sans` (default **off**) prepares for upcoming Kubernetes support
for pod authors requesting SANs via the kubelet-generated PKCS#10 CSR. Today
kubelet emits empty CSRs, so the path is inert. Since
[#80](https://github.com/RafPe/pod-certificate-signer/pull/80) CSR-derived SANs
pass through the **same** identity constraints as annotation values: CSR DNS
names are checked against the verified-identity allowlist, and CSR IP SANs are
denied outright, both unless `--allow-unverified-identities` is set. The CSR
signature itself is verified by kube-apiserver during admission; the signer only
extracts the public key and any requested SANs.

### ClusterTrustBundle

- The controller publishes exactly one bundle,
  `<signer-domain>:<signer-path>:bundle`, containing the current CA followed
  by retained previous CAs. Anything in this bundle is potentially trusted by
  every workload that mounts it — treat write access to ClusterTrustBundles
  as a cluster-wide trust decision.
- Issued certificates are always **leaf** certificates: the signing template
  sets no CA basic constraint, so an issued certificate cannot itself sign
  further certificates.
- Robustness of bundle publishing (retry on failure, drift repair) is being
  hardened in [#31](https://github.com/RafPe/pod-certificate-signer/issues/31).

### Signer RBAC

The Helm chart grants the controller the minimum it needs; review it before
widening anything:

- **ClusterRole**: `pods` get/list/watch (to verify the requesting pod);
  `podcertificaterequests` get/list/watch and `podcertificaterequests/status`
  get/update/patch (to issue or deny); `clustertrustbundles`
  get/create/update/patch — deliberately **no** list/watch, so the controller
  cannot enumerate or informer-cache other signers' bundles; `events`
  create/patch; and `signers` `sign`/`attest` restricted by `resourceNames`
  to the single configured signer name.
- **Role** (namespaced): coordination `leases` for leader election only.
- The controller has **no** RBAC on Secrets — the CA reaches it only as a
  volume mount. It cannot read other Secrets, modify pods, or sign for other
  signer names.

Deployment hardening defaults: the chart complies with the *restricted* Pod
Security Standard (distroless non-root image, `readOnlyRootFilesystem`,
`allowPrivilegeEscalation: false`, all capabilities dropped, seccomp
`RuntimeDefault`). The metrics endpoint (`:9090`) is served over HTTPS and
authenticated by default since
[#82](https://github.com/RafPe/pod-certificate-signer/pull/82): every scrape
must present a bearer token that passes a TokenReview, and be authorized by a
SubjectAccessReview for `GET` on the `/metrics` nonResourceURL. The chart
renders a `metrics-reader` ClusterRole for scrapers to bind to.
`--metrics-secure=false` restores the legacy unauthenticated plaintext
endpoint; if you set it, restrict the port with a NetworkPolicy.

## Scope

**In scope** (please report):

- Certificate mis-issuance beyond the documented limitations: issuing
  identities the configuration and admission setup should have prevented,
  bypasses of interpolation restrictions, denial-of-issuance to other tenants.
- Exposure of CA key material by the controller (logs, metrics, API objects,
  error messages).
- ClusterTrustBundle poisoning or corruption through the controller.
- Privilege escalation enabled by the chart's default RBAC or deployment
  settings.
- Vulnerabilities in the release supply chain (published images, charts, or
  the workflows that build them).

**Out of scope**:

- Attacks requiring cluster-admin, direct access to the CA Secret, node
  compromise, or a compromised kubelet/kube-apiserver — the signer trusts the
  Kubernetes control plane by design.
- Duplicate reports of the tracked limitations above (epic
  [#25](https://github.com/RafPe/pod-certificate-signer/issues/25)), including
  unconstrained annotation identities
  ([#26](https://github.com/RafPe/pod-certificate-signer/issues/26)) in
  clusters deployed without the required admission policy.
- Denial of service against kube-apiserver via mass PodCertificateRequest
  creation (rate limiting is an apiserver/priority-and-fairness concern).
- Vulnerabilities in Kubernetes itself, the container runtime, or
  dependencies without a reachable call path from this code base (see
  Scorecard notes below).

## Dependency and supply-chain notes

- Dependency vulnerabilities are triaged with `govulncheck`, which reports by
  **reachability** (an affected function must actually be callable from this
  code base), not by mere presence in `go.mod`.
- Release images are distroless, built multi-arch from the tagged source.
- A full-history gitleaks scan runs in CI to prevent committed key material.
- **Known issue — historical CA key leak**: a sample CA private key
  (`hack/ca-key.pem`, also embedded in `examples/ca_tls_secret.yaml`) was
  committed early in the project's history and removed in
  [#37](https://github.com/RafPe/pod-certificate-signer/pull/37). Removal does
  not rewrite history, so the key remains reachable in old commits and is
  **permanently compromised**. It was only ever a development sample — but if
  any cluster ever loaded it as a real signing CA, rotate that CA immediately
  and treat every certificate it signed, and any trust bundle containing it,
  as untrusted. The gitleaks configuration allowlists exactly those historical
  paths; it does not permit new key material.

## Accepted OpenSSF Scorecard findings

The following Scorecard checks are expected to stay red and are **accepted**,
with rationale:

| Check | Status | Rationale |
| ----- | ------ | --------- |
| Code-Review | Accepted, narrowing | Single-maintainer project; ordinary PRs merge after automated checks (tests, lint, e2e, secret scan) without a second human reviewer. Two categories no longer do: a release publishes only when a maintainer approves the generated release PR ([#86](https://github.com/RafPe/pod-certificate-signer/pull/86)), and an Architecture Decision Record requires at least one approving maintainer review before it is accepted (see [CONTRIBUTING.md](CONTRIBUTING.md#review)). So the decisions that govern future code, and the artifacts users actually consume, are reviewed; the routine changes between them are not. |
| Fuzzing | Accepted | No continuous fuzzing. Parsing surfaces (x509, PEM, PKCS#10) are Go standard library; project-specific parsing is covered by unit tests. |
| CII-Best-Practices | Accepted | No OpenSSF Best Practices badge pursued at this stage. |
| Vulnerabilities | Accepted (case-by-case) | Scorecard flags OSV entries by *presence* in the dependency graph; this project triages with `govulncheck` *reachability*. Findings without a reachable call path are accepted and documented. |

Not accepted — the following are being actively addressed by the repository's
hardening work and should converge to green: SAST (CodeQL), Signed-Releases
and build provenance (cosign + SBOM), Pinned-Dependencies and
Token-Permissions (SHA-pinned actions, least-privilege workflow tokens), and
Dependency-Update-Tool (Dependabot). If one of these regresses after landing,
treat it as a bug and report it.
