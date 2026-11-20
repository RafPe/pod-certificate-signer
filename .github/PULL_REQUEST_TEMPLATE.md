<!-- Thanks for contributing! See CONTRIBUTING.md for the full workflow. -->

## What does this PR do?

<!-- Describe the change and the motivation behind it. -->

## Related issues

<!-- e.g. Fixes #123 -->

## Checklist

- [ ] **Exactly one `release/*` label is set** (`release/major`, `release/minor`, `release/patch` or `release/skip`) — required, CI fails without it.
- [ ] A `.changes/unreleased/*.yaml` fragment is included for non-skip changes; `release/skip` changes include none.
- [ ] The PR title is descriptive — it ends up verbatim in the release notes.
- [ ] The `ci/e2e` label is set. Without it the required status `gate:e2e` stays pending.
- [ ] The `review/claude-allowed` label is set, so the owner can start the review that approves the PR.
- [ ] `make test`, `make lint` and `make scan-secrets` pass locally.
- [ ] Tests were added/updated for new behavior.
- [ ] Docs (README, chart docs, examples) were updated for user-facing changes.
- [ ] An ADR in `docs/adr/` accompanies this change if it needs one — see [when an ADR is required](/CONTRIBUTING.md#when-an-adr-is-required). Not CI-enforced; use your judgement.
