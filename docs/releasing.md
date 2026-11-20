# Releasing (maintainer runbook)

A maintainer review and merge gate each release.
Ordinary pull requests never publish a release. Each one adds a SemVer signal
and, unless it is `release/skip`, a small changelog fragment.

## Release model

| Concept | Contract |
| --- | --- |
| Release label | Every ordinary PR has exactly one of `release/major`, `release/minor`, `release/patch`, or `release/skip`. |
| Changelog fragment | Every PR that is not `release/skip` adds `.changes/unreleased/*.yaml`. A `release/skip` PR adds none. |
| Prepare Release | A manual workflow calculates the next version, collects the fragments into `CHANGELOG.md`, and opens or updates the `release/next -> main` PR. It never publishes. |
| Release approval | A maintainer reviews the generated PR, which has the `autorelease: pending` label, and merges it with the ruleset bypass. |
| Verification | Before the tag, the exact merge commit must pass the unit checks and the reusable Kind E2E suite. |
| Publication | The serialized **Release** workflow creates an annotated immutable tag and publishes the signed image and the chart. When both jobs succeed, it makes the draft GitHub Release public. |

The largest label since the previous release sets the version bump:
`major > minor > patch`. If only `release/skip` PRs merged, there are no
fragments, and Prepare Release opens no release PR.

## Cutting a release

1. Merge all the ordinary PRs for the release. Make sure that their labels and
   fragments are correct.
2. Run **Actions -> Prepare Release -> Run workflow** on `main`, or run:

   ```sh
   gh workflow run prepare-release.yml --ref main
   ```

3. Review the generated `release/next -> main` PR. Check its version, its
   `CHANGELOG.md` section and its release notes. Make sure that no fragments
   remain in `.changes/unreleased/`.
4. Wait until all required checks on that PR pass. Then merge it with the
   ruleset bypass. The merge is the explicit approval to publish:

   ```sh
   gh pr merge <number> --squash --admin
   ```

   The PR cannot get the approval that the `main` ruleset requires.
   `github-actions[bot]` opens it, and `GITHUB_TOKEN` cannot approve a PR of
   its own identity. `claude-review.yml` also skips PRs with an `autorelease`
   label. The bypass also skips the required status checks. Thus check that
   they all passed before you merge.
5. Monitor the **Release** workflow. It verifies the merge commit, runs the unit
   checks and E2E, creates the annotated tag, publishes the artifacts, and then
   publishes the GitHub Release.
6. Verify the release, the image signature and the chart:

   ```sh
   gh release view vX.Y.Z
   cosign verify \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     --certificate-identity-regexp 'release-image\.yml' \
     ghcr.io/rafpe/pod-certificate-signer:vX.Y.Z
   helm show chart oci://ghcr.io/rafpe/charts/pod-certificate-signer --version X.Y.Z
   ```

   The release is complete when `gh release view` shows the release as not a
   draft, `cosign verify` succeeds, and `helm show chart` prints version
   `X.Y.Z`. The image build also attaches an SBOM attestation
   (`sbom: true` in `release-image.yml`). The chart is not signed.

Next: [Publishing on Artifact Hub](artifact-hub.md#keeping-the-listing-fresh)
tells how the listing picks up the new chart version.

## Recovery

Tags are immutable. Never delete or move a release tag. If publication fails
**after** the workflow creates the tag, fix the workflow on `main`. Then
dispatch **Release** with the existing `vX.Y.Z` tag. Recovery makes sure that
the tag resolves to a commit on `main`. It runs the checks, E2E and the
artifact publication job again, and then publishes the draft GitHub Release. It
refuses a release that is already published, or a tag that points to a commit
other than the release commit.

### When the tag was never created

`workflow_dispatch` takes an *existing* tag. Thus it cannot recover a release
that failed in the `release:tag` job. Create the tag manually from a checkout
that has the `workflow` scope. Then dispatch as above. The tag push also starts
`release-image.yml`, which publishes the image and the chart:

```sh
git fetch origin --tags
# The SHA is the release PR's merge commit; the failed run logs it as SHA.
git tag -a vX.Y.Z -m "Release vX.Y.Z" <merge-sha>
git push origin refs/tags/vX.Y.Z
gh workflow run release.yml -f tag=vX.Y.Z
```

This error message shows that the tag was not created:

```
! [remote rejected] vX.Y.Z -> vX.Y.Z (refusing to allow a GitHub App to
  create or update workflow `.github/workflows/...` without `workflows`
  permission)
```

The `release:tag` job runs after the verify, check and E2E jobs. Thus `main`
can move during those approximately 20 minutes. GitHub refuses a tag *push*
that uses `GITHUB_TOKEN` when the `.github/workflows/` files of the tagged
commit differ from the tip of every branch. A workflow change that merges
during the pipeline causes exactly this.

No `permissions:` key removes that restriction. `workflows` is a PAT or OAuth
scope, not an Actions permission. In a `permissions:` block it makes the whole
workflow fail to parse. Thus `release:tag` creates the tag through the REST API.
The API points a new ref at a commit that is already on `main` and pushes
nothing. If that stops working, use a PAT or an App token with the `workflow`
scope, in that job only.

Do not merge changes to `.github/workflows/` while a release runs. Only such a
change makes the tagged commit differ from the branch tips.

Verify the recovery with the commands in step 6 of
[Cutting a release](#cutting-a-release).

## Repository setup

Create the four `release/*` labels and the `autorelease: pending` label:

```sh
for label in release/major release/minor release/patch release/skip; do
  gh label create "$label" --force
done
gh label create 'autorelease: pending' --color ededed \
  --description 'Generated release PR awaiting maintainer approval' --force
```

Prepare Release refuses to run without the `autorelease: pending` label.
**Release** never publishes a release PR that does not have it.

Let Actions open the release pull request. Without this setting, Prepare
Release pushes `release/next` and then fails on `gh pr create`. `GITHUB_TOKEN`
can push a branch but cannot open a PR without it:

```sh
gh api --method PUT "repos/${OWNER}/${REPO}/actions/permissions/workflow" \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=true
```

Keep `default_workflow_permissions` at `read`. Every workflow here declares its
own `permissions:` block. The same flag also lets Actions approve pull
requests. `review:approve` uses it. Two things stop automation from approving a
release PR. GitHub does not let `GITHUB_TOKEN` approve a PR that
`github-actions[bot]` opened. `claude-review.yml` skips PRs with an
`autorelease` label.

Create the CI label that gates e2e:

```sh
gh label create ci/e2e --color 0e8a16 \
  --description 'Run the per-PR e2e suite (sets gate:e2e)' --force
```

Set up the on-demand Claude review (`.github/workflows/claude-review.yml`).
Install the Claude GitHub App on the repository. The review posts its comments
as `claude[bot]`. Create the label:

```sh
gh label create review/claude-allowed --color 5319e7 \
  --description 'Allow an on-demand Claude review (@claude review)' --force
```

The repository variable `CLAUDE_REVIEW_AUTH` selects the credential. Its value
is `wif` or `token`. The default is `wif`. Each mode needs these secrets:

| Mode | Required secrets | Optional secrets |
| --- | --- | --- |
| `wif` (workload identity federation) | `ANTHROPIC_FEDERATION_RULE_ID`, `ANTHROPIC_ORGANIZATION_ID` | `ANTHROPIC_SERVICE_ACCOUNT_ID`, `ANTHROPIC_WORKSPACE_ID` |
| `token` | `CLAUDE_CODE_OAUTH_TOKEN` | none |

In `wif` mode, the federation rule in the Anthropic organization must accept
the GitHub OIDC token of this repository on the default branch.
`issue_comment` runs the workflow file of the default branch. The `token`
mode puts a long-lived token in a job that reads untrusted PR content. Use it
only for a short time:

```sh
gh secret set ANTHROPIC_FEDERATION_RULE_ID
gh secret set ANTHROPIC_ORGANIZATION_ID
gh variable set CLAUDE_REVIEW_AUTH --body wif
```

`review:approve` approves with `GITHUB_TOKEN`. The setting
`can_approve_pull_request_reviews=true` above allows this. The review never
runs on a release PR, so release PRs need no other token.

Protect `main` with one ruleset, named `main`. It has these rules:

- It blocks deletion and force pushes.
- It requires linear history and allows squash and rebase merges only.
- It requires a pull request with 1 approving review. The approval must come
  after the last push. A push dismisses earlier approvals. All review threads
  must be resolved.
- It requires these status checks, strict (the branch must be up to date), each
  pinned to the GitHub Actions app (integration ID 15368):

| Check | Source |
| --- | --- |
| `lint:go` | `lint.yml` |
| `test:unit` | `test.yml` |
| `test:chart` | `test-chart.yml` |
| `gate:e2e` | commit status from `test-e2e.yml` |
| `scan:secrets` | `secret-scan.yml` |
| `scan:vuln` | `security.yaml` |
| `scan:codeql` | `codeql.yml` |
| `meta:release-label` | `pr-release-metadata.yml` |

Do not require `test:e2e` itself: GitHub counts a skipped job as passed. Do not
require a workflow with a path filter: its check never appears on a PR that
does not touch those paths.

The repository admin role (`RepositoryRole` ID 5) is a bypass actor with mode
`always`. The bypass skips the review and the status checks. The admin uses it
in these cases:

- Release PRs. Automation cannot approve them (see
  [Cutting a release](#cutting-a-release)).
- Fork PRs. They cannot post `gate:e2e`, and `review:approve` never approves
  them.
- Dependabot PRs that do not get the `review/claude-allowed` label and a review.

Create the ruleset with this body:

```sh
gh api --method POST "repos/${OWNER}/${REPO}/rulesets" --input - <<'JSON'
{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "exclude": [],
      "include": [
        "refs/heads/main"
      ]
    }
  },
  "rules": [
    {
      "type": "deletion"
    },
    {
      "type": "non_fast_forward"
    },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "required_reviewers": [],
        "require_code_owner_review": false,
        "require_last_push_approval": true,
        "required_review_thread_resolution": true,
        "require_extra_approval_for_unattributed_changes": true,
        "allowed_merge_methods": [
          "squash",
          "rebase"
        ]
      }
    },
    {
      "type": "required_linear_history"
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          {
            "context": "lint:go",
            "integration_id": 15368
          },
          {
            "context": "test:unit",
            "integration_id": 15368
          },
          {
            "context": "test:chart",
            "integration_id": 15368
          },
          {
            "context": "gate:e2e",
            "integration_id": 15368
          },
          {
            "context": "scan:secrets",
            "integration_id": 15368
          },
          {
            "context": "scan:vuln",
            "integration_id": 15368
          },
          {
            "context": "scan:codeql",
            "integration_id": 15368
          },
          {
            "context": "meta:release-label",
            "integration_id": 15368
          }
        ]
      }
    }
  ],
  "bypass_actors": [
    {
      "actor_id": 5,
      "actor_type": "RepositoryRole",
      "bypass_mode": "always"
    }
  ]
}
JSON
```

To change the ruleset later, send the whole body with
`gh api --method PUT "repos/${OWNER}/${REPO}/rulesets/<id>" --input -`. A PUT
replaces the `rules` array. A rule that is not in the body is removed. Find the
ID with `gh api "repos/${OWNER}/${REPO}/rulesets"`.

Turn on Dependabot alerts and Dependabot security updates. Require actions
pinned to a full commit SHA:

```sh
gh api --method PUT "repos/${OWNER}/${REPO}/vulnerability-alerts"
gh api --method PUT "repos/${OWNER}/${REPO}/automated-security-fixes"
gh api --method PUT "repos/${OWNER}/${REPO}/actions/permissions" \
  -F enabled=true -f allowed_actions=all -F sha_pinning_required=true
```

New GHCR packages are private by default. Make the image and chart packages
public. Then follow [Artifact Hub](artifact-hub.md).

To verify the setup, run `gh label list --search release` and
`gh label list --search autorelease`, and make sure that all five labels show.

## Maintainer checks

- Keep action SHAs and tool versions pinned.
- Keep the Kind version (`KIND_VERSION`) pinned in `test-e2e.yml`. A release
  must not download an unspecified latest binary.
- Keep `release-image.yml` as the only workflow that publishes artifacts.
- Run `sh scripts/release-contract-check.sh` when you change the release
  automation. It prints `release-contract-check: ok` on success.
