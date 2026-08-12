# Changelog

The full, per-release change list is published as **[GitHub Releases](https://github.com/RafPe/pod-certificate-signer/releases)**,
generated automatically from the `release/*` label on each merged pull request
(see [`.github/release-drafter.yml`](.github/release-drafter.yml)). This file
curates the highlights and — for breaking releases — the migration steps.

## Unreleased

### ⚠️ Breaking changes & migration

- **The metrics endpoint now requires authentication and authorization** (#49).
  `/metrics` is served over **HTTPS** and every scrape must present a Kubernetes
  bearer token (verified via `TokenReview`) that is authorized (via
  `SubjectAccessReview`) for `get` on the `/metrics` nonResourceURL. Previously
  the endpoint was plaintext and unauthenticated, so any pod that could reach the
  Service could scrape it.
  - _Migration (Prometheus):_ bind the chart's new `<release>-metrics-reader`
    `ClusterRole` to the ServiceAccount your scraper uses, and configure the
    scrape (e.g. a `ServiceMonitor`) with `scheme: https`, a `bearerTokenFile`,
    and either the serving CA or `tlsConfig.insecureSkipVerify: true` (the
    serving certificate is self-signed, generated in memory). Annotation-based
    scraping cannot authenticate and no longer works against this endpoint.
  - _Escape hatch:_ set `metrics.insecure: true` (renders `--metrics-secure=false`)
    to restore the legacy unauthenticated plaintext endpoint — do this only when
    the port is protected by other means. An optional `metrics.networkPolicy`
    (off by default) can restrict ingress to the metrics port.
  - The controller `ClusterRole` gains `create` on `tokenreviews` and
    `subjectaccessreviews` so the auth filter can call the apiserver.

## v2.0.0

The first release under the constrained-identity security model, with a hardened
supply chain and a restructured Helm chart. Captures the code-quality (#25) and
CI/security/presentation (#52) epics.

### ⚠️ Breaking changes & migration

- **Certificate identities are constrained to verified fields** (#26, #38).
  Literal `cn` / `san` / `ip-san` / `uris` annotation values are now **denied by
  default** unless they resolve to a verified `PodCertificateRequest` identity
  (pod name, namespace, service-account name, pod UID, and the cluster FQDN).
  - _Migration:_ adopt the supplied
    [`examples/validating-admission-policy.yaml`](examples/validating-admission-policy.yaml)
    to govern which identities workloads may request, **or** start the controller
    with `--allow-unverified-identities` to keep the pre-2.0 behaviour.
  - The default Extended Key Usage is now **ServerAuth only**; add the `eku`
    annotation (`client`, or `server,client`) to opt into client authentication.
- **The Helm chart is renamed to `pod-certificate-signer`** (#74), published at
  `oci://ghcr.io/rafpe/charts/pod-certificate-signer`. Rendered resource names
  change (`podcertificate-signer-*` → `pod-certificate-signer-*`).
  - _Migration:_ install the new chart rather than upgrading in place. The
    previous `charts/podcertificate-signer` artifact keeps its 1.x versions.
  - The dev/example CA `Secret` names are unchanged.

### 🚀 Highlights

- **Supply chain:** cosign keyless signing + SBOM attestation on the release
  image (#72); digest-pinned distroless build with `-trimpath`, chart
  PodDisruptionBudget and default resource requests/limits (#71).
- **Reliability:** the CA file watcher runs on every replica with reload health
  surfaced via `readyz` (#41, #45); CA history fails closed on read errors (#46);
  the ClusterTrustBundle reconciles durably with retry and drift repair (#47);
  pod identity is verified with a live UID-aware read (#43); CA-availability
  signing errors are classified as transient (#42); the pod cache is bypassed and
  pod RBAC narrowed to get-only (#44).
- **Security & CI:** CodeQL, `govulncheck`, OpenSSF Scorecard, and
  `gosec`/`bodyclose` gates; SHA-pinned, least-privilege workflows; Dependabot;
  `SECURITY.md` and governance files (#53–#56, #64–#68). Committed CA key
  material was removed and dev CAs are now ephemeral (#37).
- **Docs:** restructured README and a `docs/` tree with C4 diagrams, plus
  Artifact Hub packaging (#70).

See the [v2.0.0 release notes](https://github.com/RafPe/pod-certificate-signer/releases/tag/v2.0.0)
for the complete, categorised list of changes.

## Versioning

This project follows [Semantic Versioning](https://semver.org/). Every merged PR
carries exactly one `release/{major,minor,patch,skip}` label, which determines
both the next version bump and the section a change appears under in the notes.
