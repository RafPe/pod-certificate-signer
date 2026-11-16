# Unified release workflow — TDD evidence

## Journeys

- A contributor gets deterministic feedback for release labels and fragments.
- A maintainer can prepare and review a release without publishing it.
- A release only tags and publishes the exact commit that passed unit and E2E checks.
- A maintainer can recover an existing immutable tag without moving it.

## Evidence

| Guarantee | Type | RED | GREEN |
| --- | --- | --- | --- |
| Required release workflows and documentation exist | Contract | `sh scripts/release-contract-check.sh` failed on missing `pr-release-metadata.yml` | Same command: `release-contract-check: ok` |
| GitHub workflow syntax and shell are valid | Integration/static | N/A | `actionlint .github/workflows/*.yml`: PASS |
| Existing application behavior is unchanged | Unit/integration | N/A | `make test`: PASS, including the envtest controller suite (5/5 specs) |
| The resolved release SHA reaches the release E2E workflow | Contract | Added after recovery-path review | Contract and actionlint: PASS; `target_ref` is passed from `verify.outputs.sha` |

## Coverage and E2E

Measured when the workflow merged (PR
[#86](https://github.com/RafPe/pod-certificate-signer/pull/86)): `make test` kept
the package coverage results of the repository, including 92.9% for
`internal/controller` and 92.4% for `internal/podcertificate`.
The per-PR tier of the Kind E2E suite (`make test-e2e`, through
`test-e2e.yml`) is a release gate in `release.yml`. The E2E Tests workflow
also runs it on pull requests. It did not run locally, because it
creates a cluster and the change is GitHub event orchestration. actionlint and
the offline contract check cover that wiring.

The procedure that uses this workflow is in [docs/releasing.md](../releasing.md).
