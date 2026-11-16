# Publishing on Artifact Hub

Most Helm users find charts on [Artifact Hub](https://artifacthub.io). A listing
there lets users find and install `pod-certificate-signer` outside GitHub.

The chart has these Artifact Hub files:

- [`charts/pod-certificate-signer/Chart.yaml`](../charts/pod-certificate-signer/Chart.yaml)
  has `artifacthub.io/*` annotations (category, license, links, images). Artifact
  Hub shows them in the listing.
- [`charts/pod-certificate-signer/artifacthub-repo.yml`](../charts/pod-certificate-signer/artifacthub-repo.yml)
  is the ownership file. It claims the repository and gives the Verified
  Publisher status.

Registration is a one-time manual step. It requires an Artifact Hub account.

> [!NOTE]
> Signed releases: the release workflow signs the image with **cosign keyless**
> signing (Fulcio/Rekor, no static public key). Thus there is no
> `artifacthub.io/signKey` annotation to set. Artifact Hub finds the signature
> without a key. To verify the signature, see
> [Verifying the image signature](#verifying-the-image-signature).

## One-time setup

1. **Sign in** at <https://artifacthub.io>. GitHub sign-in works.

2. **Add the repository** under *Control Panel → Repositories → Add*:
   - **Kind:** `Helm charts`
   - **Name:** `pod-certificate-signer`. This name becomes the URL slug. It
     **must** match the Artifact Hub badge in the README.
   - **URL:** `oci://ghcr.io/rafpe/charts/pod-certificate-signer`

3. **Copy the Repository ID** of the new repository into the `repositoryID`
   field of `charts/pod-certificate-signer/artifacthub-repo.yml`. Also set
   `owners[].email` to the address of your Artifact Hub account. Commit that
   change. The file in the repository already has an ID and an email. Replace
   them only when you register the repository again.

4. **Publish the ownership metadata** to the OCI registry one time. Artifact Hub
   uses it to verify ownership. This step requires [`oras`](https://oras.land)
   and a GHCR login. Artifact Hub reads this file **from the registry**, not
   from git:

   ```bash
   echo "$GITHUB_TOKEN" | oras login ghcr.io -u <your-github-user> --password-stdin

   oras push ghcr.io/rafpe/charts/pod-certificate-signer:artifacthub.io \
     --config /dev/null:application/vnd.cncf.artifacthub.config.v1+yaml \
     charts/pod-certificate-signer/artifacthub-repo.yml:application/vnd.cncf.artifacthub.repository-metadata.layer.v1.yaml
   ```

Artifact Hub indexes the repository again within a few minutes. Then it shows
the chart, its annotations, and a "Verified Publisher" badge. The Artifact Hub
badge in the README returns 404 until this registration is complete.

## Keeping the listing fresh

Artifact Hub polls the OCI repository and finds new chart versions
automatically. Each packaged chart contains its `artifacthub.io/*` annotations.

The release workflow (`.github/workflows/release-image.yml`) packages the chart.
It sets the chart `version` and `appVersion` from the git tag. It also sets the
`artifacthub.io/images` tag to the release version. Thus the annotation always
agrees with the published image. The value in `Chart.yaml` in git applies only
to installs from a source checkout.

## Verifying the image signature

The release workflow signs release images keyless with
[cosign](https://github.com/sigstore/cosign). The signing identity is the GitHub
Actions release workflow. Fulcio certifies it, and Rekor logs it. There is no
long-lived public key to distribute.

> [!NOTE]
> Signatures and SBOM attestations exist only for releases after cosign signing
> was added
> ([#72](https://github.com/RafPe/pod-certificate-signer/pull/72), commit
> `27d0017`). By git history, `v2.0.0` is the first tag that contains this
> change. Images of earlier tags have no signature, and `cosign verify` fails
> for them, as expected.

Verify a release image **by digest**. Then you verify the exact content that a
tag points to. First, get the digest of the tag. Use
[`crane`](https://github.com/google/go-containerregistry), or
`docker buildx imagetools inspect <image> --format '{{.Manifest.Digest}}'`:

```bash
IMAGE=ghcr.io/rafpe/pod-certificate-signer:vX.Y.Z
DIGEST="${IMAGE%:*}@$(crane digest "$IMAGE")"

cosign verify \
  --certificate-identity-regexp '(?i)^https://github\.com/RafPe/pod-certificate-signer/\.github/workflows/release-image\.yml@.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$DIGEST"
```

The identity regexp requires this repository and its release workflow. It
accepts any git ref. The release runs through a reusable-workflow call, and the
ref in the certificate is not always the tag. To see the exact identity in the
certificate, and not trust the pattern, use this command:

```bash
cosign verify --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$DIGEST" -o text
```

The image also has an SPDX SBOM for each platform. The build attaches it as an
in-toto attestation. To examine it, use this command:

```bash
cosign download sbom "$DIGEST"
# or
docker buildx imagetools inspect "$IMAGE" --format '{{ json .SBOM }}'
```

## Next steps

To make sure that a published chart has the correct annotations, read them
from the registry:

```bash
helm show chart oci://ghcr.io/rafpe/charts/pod-certificate-signer --version X.Y.Z
```

The `artifacthub.io/images` annotation must name the image tag `vX.Y.Z`. Then
open the listing at
<https://artifacthub.io/packages/search?repo=pod-certificate-signer>. For the
full release procedure, see [Releasing](./releasing.md).
