# Releasing (maintainer runbook)

A maintainer review gates each release. Ordinary pull requests never publish a
release. Each one adds a SemVer signal and, unless it is `release/skip`, a
small changelog fragment.

## Release model

| Concept | Contract |
| --- | --- |
| Release label | Every ordinary PR has exactly one of `release/major`, `release/minor`, `release/patch`, or `release/skip`. |
| Changelog fragment | Every PR that is not `release/skip` adds `.changes/unreleased/*.yaml`. A `release/skip` PR adds none. |
| Prepare Release | A manual workflow calculates the next version, collects the fragments into `CHANGELOG.md`, and opens or updates the `release/next -> main` PR. It never publishes. |
| Release approval | A maintainer reviews and merges the generated PR, which has the `autorelease: pending` label. |
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
4. Merge that PR. The merge is the explicit approval to publish.
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
requests. Thus the branch protection review below is what stops automation from
approving a release PR.

Make **PR Release Metadata** a required status check. Protect `main` so that the
generated release PR gets a review like any other PR. New GHCR packages are
private by default. Make the image and chart packages public. Then follow
[Artifact Hub](artifact-hub.md).

To verify the setup, run `gh label list --search release` and
`gh label list --search autorelease`, and make sure that all five labels show.

## Maintainer checks

- Keep action SHAs and tool versions pinned.
- Keep the Kind version (`KIND_VERSION`) pinned in `test-e2e.yml`. A release
  must not download an unspecified latest binary.
- Keep `release-image.yml` as the only workflow that publishes artifacts.
- Run `sh scripts/release-contract-check.sh` when you change the release
  automation. It prints `release-contract-check: ok` on success.
