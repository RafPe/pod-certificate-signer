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

`make test` retained the repository's package coverage results, including 92.9%
for `internal/controller` and 92.4% for `internal/kubernetes/podcertificate`.
The full Kind E2E suite is intentionally a release gate in
`release.yml`; it is also still exercised on pull requests. It was not started
locally because it creates a cluster and the changed behavior is GitHub event
orchestration; actionlint and the offline contract cover that wiring here.
