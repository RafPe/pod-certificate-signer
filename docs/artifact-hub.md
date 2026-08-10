# Publishing on Artifact Hub

[Artifact Hub](https://artifacthub.io) is where most Helm users discover charts.
Listing `podcertificate-signer` there makes it installable and searchable beyond
GitHub.

The chart is already prepared for it:

- [`charts/podcertificate-signer/Chart.yaml`](../charts/podcertificate-signer/Chart.yaml)
  carries `artifacthub.io/*` annotations (category, license, links, images) that
  populate the listing.
- [`charts/podcertificate-signer/artifacthub-repo.yml`](../charts/podcertificate-signer/artifacthub-repo.yml)
  is the ownership file used to claim the repository and become a Verified
  Publisher.

Registration is a one-time manual step — it needs an Artifact Hub account.

> [!NOTE]
> Signed releases: cosign keyless signing is tracked separately (hardening item
> H7). Once releases are signed, Artifact Hub detects and displays the signature
> automatically, and the `artifacthub.io/signKey` annotation placeholder in
> `Chart.yaml` should be filled in.

## One-time setup

1. **Sign in** at <https://artifacthub.io> (GitHub sign-in works).

2. **Add the repository** under *Control Panel → Repositories → Add*:
   - **Kind:** `Helm charts`
   - **Name:** `podcertificate-signer` (this becomes the URL slug and **must**
     match the Artifact Hub badge in the README)
   - **URL:** `oci://ghcr.io/rafpe/charts/podcertificate-signer`

3. **Copy the Repository ID** shown for the new repository and paste it into
   `charts/podcertificate-signer/artifacthub-repo.yml` (replacing the
   `repositoryID` placeholder). Also set `owners[].email` to the address on your
   Artifact Hub account. Commit that change.

4. **Publish the ownership metadata** to the OCI registry once, so Artifact Hub
   can verify ownership (requires [`oras`](https://oras.land) and a GHCR login).
   Artifact Hub reads this file **from the registry**, not from git:

   ```bash
   echo "$GITHUB_TOKEN" | oras login ghcr.io -u <your-github-user> --password-stdin

   oras push ghcr.io/rafpe/charts/podcertificate-signer:artifacthub.io \
     --config /dev/null:application/vnd.cncf.artifacthub.config.v1+yaml \
     charts/podcertificate-signer/artifacthub-repo.yml:application/vnd.cncf.artifacthub.repository-metadata.layer.v1.yaml
   ```

Artifact Hub re-indexes the repository within a few minutes and shows the chart,
its annotations, and a "Verified Publisher" badge. The README's Artifact Hub
badge stays a 404 until this registration completes.

## Keeping the listing fresh

Artifact Hub polls the OCI repository and picks up new chart versions
automatically; the `artifacthub.io/*` annotations travel with each packaged
chart.

> [!NOTE]
> The release workflow (`.github/workflows/release-image.yml`) overrides the
> chart `version`/`appVersion` from the git tag, but does **not** currently
> rewrite the `artifacthub.io/images` tag in `Chart.yaml`. Bump that annotation
> when it drifts from the released image, or extend the workflow to rewrite it on
> release.
