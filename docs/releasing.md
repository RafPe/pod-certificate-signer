# Releasing (maintainer runbook)

How a release is cut, how to recover a failed artifact build, and the one-time
steps for a new package. The `release/*` label contract itself is in
[CONTRIBUTING.md](../CONTRIBUTING.md).

## How it works

Releases are driven by [release-drafter](../.github/release-drafter.yml):

- Every merged PR carries exactly one `release/*` label (enforced by
  `pr-labels.yml`). release-drafter keeps a rolling **draft** of the next
  release, grouped into sections by label; the version resolves to the **max**
  label since the last release (`major` > `minor` > `patch`).
- **Merging a PR that is _not_ `release/skip` publishes** the draft: `release.yml`
  tags `vX.Y.Z`, then calls `release-image.yml` to build the multi-arch image
  (cosign keyless-signed + SBOM) and package + push the chart to
  `oci://ghcr.io/rafpe/charts/pod-certificate-signer:X.Y.Z`.
- Merging a `release/skip` PR only updates the draft.

## Cutting a release

1. Merge everything intended for the release.
2. **Curate the notes (optional but recommended):** make sure each merged PR
   since the last release carries its true `release/*` category — release-drafter
   reads the PRs' *current* labels at publish time, so re-labelling merged PRs
   reshapes the draft.
3. **Preview:** the draft updates in **Releases** on every merge. To refresh it
   without publishing, merge any `release/skip` PR.
4. **Publish:** merge one PR with a non-`skip` label (e.g. `release/major`). This
   triggers `release.yml` → publishes `vX.Y.Z` + tag → builds and pushes the
   image and chart.
5. **Verify:**
   - Release + tag on GitHub, notes categorised as expected.
   - Image `ghcr.io/rafpe/pod-certificate-signer:vX.Y.Z` (plus `vX.Y`, `vX`,
     `latest`) and a `sha256-…` cosign signature tag.
   - Chart `ghcr.io/rafpe/charts/pod-certificate-signer:X.Y.Z`.

   ```bash
   gh release view vX.Y.Z
   gh api "users/RafPe/packages/container/pod-certificate-signer/versions" \
     --jq '.[].metadata.container.tags[]'
   gh api "users/RafPe/packages/container/charts%2Fpod-certificate-signer/versions" \
     --jq '.[].metadata.container.tags[]'
   ```

## Backfilling artifacts (image/chart build failed)

The release + tag publish **first**; the artifact build runs after. If that build
fails (e.g. a transient buildx error), the release exists but the image/chart are
missing. Land any fix on `main`, then re-run **only** the artifact build against
the existing tag — no re-release:

```bash
gh workflow run release-image.yml --ref main -f tag=vX.Y.Z
gh run watch "$(gh run list --workflow=release-image.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

`--ref main` uses the current workflow definition (so fix forward first); the job
checks out the `vX.Y.Z` source. Verify the image/chart tags as above.

## One-time: a new package

When a new image or chart **package name** is first pushed, GHCR makes it
**private**. Make it public so consumers (and Artifact Hub) can pull it
unauthenticated:

- GitHub → profile → **Packages** → the package → **Package settings** →
  **Change visibility → Public**.

## One-time: Artifact Hub

Follow [docs/artifact-hub.md](./artifact-hub.md) to claim the repository (add it,
paste the Repository ID into `charts/pod-certificate-signer/artifacthub-repo.yml`,
`oras push` the ownership file). After that, Artifact Hub polls the OCI repo and
picks up new chart versions automatically. The signature-verification recipe for
consumers is in the same doc.

## Gotchas

- **No GHA build cache.** `cache-to: type=gha` fails hard (`failed to reserve
  cache`) under the `workflow_call` context and takes the build down; it was
  removed. Don't re-add it without confirming the cache backend works there.
- **cosign needs `id-token: write` on the caller.** A called workflow's jobs are
  capped by the caller's permissions, so `release.yml`'s `publish-artifacts` grants
  it too — otherwise the OIDC token is never minted on the real release path.
- **Chart `.tgz` name follows `Chart.yaml` `name`.** If the chart is renamed,
  keep the `helm push` filename in `release-image.yml` in sync.
