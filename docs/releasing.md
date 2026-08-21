# Releasing (maintainer runbook)

The project uses a review-gated release pipeline. Ordinary pull requests never publish
a release. They only contribute a SemVer signal and, unless skipped, a
small changelog fragment.

## Release model

| Concept | Contract |
| --- | --- |
| Release label | Every ordinary PR has exactly one of `release/major`, `release/minor`, `release/patch`, or `release/skip`. |
| Changelog fragment | Every non-skip PR adds `.changes/unreleased/*.yaml`; skip PRs add none. |
| Prepare Release | A manual workflow computes the next version, batches fragments, and opens or updates `release/next -> main`. It never publishes. |
| Release approval | A maintainer reviews and merges the generated PR carrying `autorelease: pending`. |
| Verification | The exact merge commit passes unit checks and the reusable Kind E2E suite before tagging. |
| Publication | The serialized workflow creates an annotated immutable tag, publishes the signed image and chart, verifies success, then makes the draft GitHub Release public. |

The largest label since the previous release wins: `major > minor > patch`.
If only skip changes have landed, no release should be prepared.

## Cutting a release

1. Merge all intended ordinary PRs. Confirm their labels and fragments are
   accurate.
2. Run **Actions -> Prepare Release -> Run workflow** on `main`, or:

   ```sh
   gh workflow run prepare-release.yml --ref main
   ```

3. Review the generated `release/next -> main` PR. Check its version,
   `CHANGELOG.md` section, release notes, and that no unreleased fragments remain.
4. Merge that PR. This is the explicit publication approval.
5. Watch **Release**. It verifies the merge commit, runs unit checks and E2E,
   creates the annotated tag, publishes artifacts, and finally publishes the
   GitHub Release.
6. Verify the release, image, signature, SBOM, and chart:

   ```sh
   gh release view vX.Y.Z
   cosign verify \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     --certificate-identity-regexp 'release-image\.yml' \
     ghcr.io/rafpe/pod-certificate-signer:vX.Y.Z
   helm show chart oci://ghcr.io/rafpe/charts/pod-certificate-signer --version X.Y.Z
   ```

## Recovery

Tags are immutable: never delete or move a release tag. If publication fails
**after** the tag is created, fix the workflow on `main` and dispatch
**Release** with the existing `vX.Y.Z` tag. Recovery verifies that the tag
resolves to a commit on `main`, reruns checks and E2E, and resumes publication.
It refuses a published release or a tag that points elsewhere.

### When the tag was never created

`workflow_dispatch` takes an *existing* tag, so it cannot recover a release that
failed at `release:tag` itself. Create the tag by hand from a checkout that has
`workflow` scope, then dispatch as above — pushing it also triggers
`release-image.yml`, so the image and chart publish on their own and the
dispatch only finishes the GitHub Release:

```sh
git fetch origin --tags
# The SHA is the release PR's merge commit; the failed run logs it as SHA.
git tag -a vX.Y.Z -m "Release vX.Y.Z" <merge-sha>
git push origin refs/tags/vX.Y.Z
gh workflow run release.yml -f tag=vX.Y.Z
```

The failure that makes this necessary is worth recognising:

```
! [remote rejected] vX.Y.Z -> vX.Y.Z (refusing to allow a GitHub App to
  create or update workflow `.github/workflows/...` without `workflows`
  permission)
```

`release:tag` runs after verify, check and E2E, so `main` can move during those
~20 minutes. GitHub refuses a tag push from `GITHUB_TOKEN` whenever the tagged
commit's `.github/workflows/` differ from the tip of every branch, which is
exactly what a workflow change merged mid-pipeline produces. The job now holds
`workflows: write` for this reason. Merging anything that touches
`.github/workflows/` while a release is in flight is still best avoided — it is
the only thing that makes the tagged commit diverge in the first place.

## Repository setup

Create the four `release/*` labels and `autorelease: pending`:

```sh
for label in release/major release/minor release/patch release/skip; do
  gh label create "$label" --force
done
gh label create 'autorelease: pending' --color ededed \
  --description 'Generated release PR awaiting maintainer approval' --force
```

Prepare Release refuses to run without `autorelease: pending`, because a
release PR that does not carry it can never be published by **Release**.

Allow Actions to open the release pull request. Without this, Prepare Release
pushes `release/next` and then fails on `gh pr create`, because `GITHUB_TOKEN`
may push a branch but not open a PR:

```sh
gh api --method PUT "repos/${OWNER}/${REPO}/actions/permissions/workflow" \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=true
```

Keep `default_workflow_permissions` at `read`: every workflow here declares its
own `permissions:` block. Note that the same flag also permits Actions to
approve pull requests, so the review gate below is what keeps a release PR from
being approved by automation.

Make **PR Release Metadata** a required status check. Protect `main` so the generated
release PR is reviewed like any other PR. New GHCR packages default to private;
make the image and chart packages public, then follow [Artifact Hub](artifact-hub.md).

## Maintainer checks

- Keep action SHAs and tool versions pinned.
- Keep the Kind version pinned in `test-e2e.yml`; releases must not download an
  unspecified latest binary.
- Keep `release-image.yml` as the only artifact publisher.
- Run `sh scripts/release-contract-check.sh` when changing release automation.
