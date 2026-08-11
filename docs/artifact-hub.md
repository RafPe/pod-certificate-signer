# Publishing on Artifact Hub

[Artifact Hub](https://artifacthub.io) is where most Helm users discover charts.
Listing `pod-certificate-signer` there makes it installable and searchable beyond
GitHub.

The chart is already prepared for it:

- [`charts/pod-certificate-signer/Chart.yaml`](../charts/pod-certificate-signer/Chart.yaml)
  carries `artifacthub.io/*` annotations (category, license, links, images) that
  populate the listing.
- [`charts/pod-certificate-signer/artifacthub-repo.yml`](../charts/pod-certificate-signer/artifacthub-repo.yml)
  is the ownership file used to claim the repository and become a Verified
  Publisher.

Registration is a one-time manual step — it needs an Artifact Hub account.

> [!NOTE]
> Signed releases: the release image is signed with **cosign keyless** signing
> (Fulcio/Rekor, no static public key), so there is no `artifacthub.io/signKey`
> annotation to fill in — Artifact Hub detects the signature on its own. See
> [Verifying the image signature](#verifying-the-image-signature) for how a
> consumer verifies it.

## One-time setup

1. **Sign in** at <https://artifacthub.io> (GitHub sign-in works).

2. **Add the repository** under *Control Panel → Repositories → Add*:
   - **Kind:** `Helm charts`
   - **Name:** `pod-certificate-signer` (this becomes the URL slug and **must**
     match the Artifact Hub badge in the README)
   - **URL:** `oci://ghcr.io/rafpe/charts/pod-certificate-signer`

3. **Copy the Repository ID** shown for the new repository and paste it into
   `charts/pod-certificate-signer/artifacthub-repo.yml` (replacing the
   `repositoryID` placeholder). Also set `owners[].email` to the address on your
   Artifact Hub account. Commit that change.

4. **Publish the ownership metadata** to the OCI registry once, so Artifact Hub
   can verify ownership (requires [`oras`](https://oras.land) and a GHCR login).
   Artifact Hub reads this file **from the registry**, not from git:

   ```bash
   echo "$GITHUB_TOKEN" | oras login ghcr.io -u <your-github-user> --password-stdin

   oras push ghcr.io/rafpe/charts/pod-certificate-signer:artifacthub.io \
     --config /dev/null:application/vnd.cncf.artifacthub.config.v1+yaml \
     charts/pod-certificate-signer/artifacthub-repo.yml:application/vnd.cncf.artifacthub.repository-metadata.layer.v1.yaml
   ```

Artifact Hub re-indexes the repository within a few minutes and shows the chart,
its annotations, and a "Verified Publisher" badge. The README's Artifact Hub
badge stays a 404 until this registration completes.

## Keeping the listing fresh

Artifact Hub polls the OCI repository and picks up new chart versions
automatically; the `artifacthub.io/*` annotations travel with each packaged
chart.

The release workflow (`.github/workflows/release-image.yml`) overrides the chart
`version`/`appVersion` from the git tag **and** rewrites the
`artifacthub.io/images` tag to the released version when it packages the chart,
so the annotation never drifts from the published image. The value committed in
`Chart.yaml` only applies to installs from a source checkout.

## Verifying the image signature

Release images are signed keyless with [cosign](https://github.com/sigstore/cosign):
the signing identity is the GitHub Actions release workflow, certified by Fulcio
and logged in Rekor — there is no long-lived public key to distribute.

> [!NOTE]
> Signatures and SBOM attestations exist only for releases cut **after** cosign
> signing landed (hardening item H7). Tags published before that are unsigned;
> `cosign verify` against them fails as expected.

Verify a released image **by digest** so you verify the exact content a tag
points at. Resolve the tag to a digest first (with
[`crane`](https://github.com/google/go-containerregistry), or
`docker buildx imagetools inspect <image> --format '{{.Manifest.Digest}}'`):

```bash
IMAGE=ghcr.io/rafpe/pod-certificate-signer:vX.Y.Z
DIGEST="${IMAGE%:*}@$(crane digest "$IMAGE")"

cosign verify \
  --certificate-identity-regexp '(?i)^https://github\.com/RafPe/pod-certificate-signer/\.github/workflows/release-image\.yml@.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$DIGEST"
```

The identity regexp anchors on this repository and its release workflow but stays
permissive on the git ref, because the release runs through a reusable-workflow
call and the ref recorded in the certificate is not always the tag. To inspect
the exact identity that was recorded rather than trusting the pattern:

```bash
cosign verify --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$DIGEST" -o text
```

The image also carries a per-platform SPDX SBOM attached at build time as an
in-toto attestation. Inspect it with:

```bash
cosign download sbom "$DIGEST"
# or
docker buildx imagetools inspect "$IMAGE" --format '{{ json .SBOM }}'
```
