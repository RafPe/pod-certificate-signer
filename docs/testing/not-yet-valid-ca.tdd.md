# Not-yet-valid CA rejection — TDD evidence

Issue: [#137](https://github.com/RafPe/pod-certificate-signer/issues/137) —
`validateCACertificate` never checked `NotBefore`, so a CA whose validity
opens ahead of the local clock loaded cleanly, passed readiness and signed
leaves that fail chain verification on every peer.

## Journeys

- An operator rotating to an externally minted CA (cert-manager sub-CA, AWS
  Private CA, Vault) whose issuer's clock runs ahead gets a named reload
  failure instead of a healthy signer issuing unverifiable certificates.
- Benign clock skew around a fresh rotation does not turn into a reload
  failure: a `NotBefore` within the five-minute tolerance is accepted.
- A not-yet-valid certificate offered as previous-CA history is dropped
  rather than adopted and republished into the ClusterTrustBundle.

## Evidence

| Guarantee | Type | RED | GREEN |
| --- | --- | --- | --- |
| All four rejection reasons and the skew boundary are enforced | Unit | `TestValidateCACertificate/not_yet_valid_beyond_the_skew_tolerance`: `= <nil>, want error containing "not yet valid"` | Same run: PASS, all 8 cases |
| `New`/`load` refuses a not-yet-valid CA on disk | Unit | `TestNewRejectsNotYetValidCertificate`: `err = <nil>` | Same run: PASS |
| Bootstrapped history drops a not-yet-valid entry | Unit | `TestBootstrappedHistoryDropsUnusableEntries`: `history = [not-yet-valid kept], want [kept]` | Same run: PASS |
| A not-yet-valid CA written to the secret is inert: rejected by name, bundle unchanged, last-good CA keeps signing, recovery needs no restart | E2E | Entry added to the unusable-replacement-material table (RED not runnable in isolation; the assertion needle `CA certificate is not yet valid` did not exist before the fix) | Focused Kind run of `a CA certificate that is not yet valid`: PASS |

## Coverage and E2E

`make test` is green across the repository. `internal/kubernetes/authority`
sits at 86.8% statement coverage with `validateCACertificate` itself at 100%
(`go tool cover -func`). `make lint` (golangci-lint, including
`--build-tags=e2e`) reports 0 issues.

The E2E entry joins the nightly-labelled `DescribeTable` in
`test/e2e/ca_lifecycle_test.go`, so per-PR CI compiles it and nightly runs it.
It was additionally executed once locally against a Kind cluster with
`-ginkgo.focus='should run successfully|a CA certificate that is not yet
valid'` (the first spec resolves `controllerPodName`, which the log
assertions read): 2 of 106 specs ran, both passed in 274s.
