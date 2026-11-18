# pod-certificate-signer articles

This directory holds the article series about `pod-certificate-signer` and the
tools that build it. Each article is an operator how-to. The reader runs the
commands and sees the same result.

| # | Article | Directory | Status |
| --- | --- | --- | --- |
| 01 | Per-pod x509 certificates with no sidecar, on Kubernetes 1.37+ | [`01-per-pod-certificates/`](01-per-pod-certificates/) | Ready to publish |
| 02 | A signer that denies by default: the verified-identity allowlist | not in the repository | Drafted |
| 03 | Rotating the CA with no restart: the delay, its cause, and the upstream fix | not in the repository | Drafted |
| 04 | Watching the signer: nine metric families, four alerts and one dashboard | not in the repository | Drafted |

## Layout

| Path | Content |
| --- | --- |
| [`SERIES.md`](SERIES.md) | The contract for each article: reader, fixed names, evidence rules, structure, voice, limits for code cards. |
| [`_shared/`](_shared/README.md) | The render tool, the stylesheet, the diagram template and the cover specification. |
| `NN-slug/` | One article. |

Each article directory has these files:

| File | Content |
| --- | --- |
| `article.md` | The article text. It is the source for the preview and the code cards. |
| `post.md` | The short post that announces the article. |
| `facts.md` | One row for each claim, with its source. It also lists what was not verified. |
| `evidence/` | The raw command output from the test cluster. |
| `assets/BRIEF.md` | The exact text for the cover, each diagram and each code card. |
| `assets/cover.jpg` | The cover. No command makes it again, so Git tracks it. |
| `assets/*.svg` | The diagrams. |

## What Git tracks

Git tracks the sources only. The render tool makes these files, and Git
ignores them:

- `preview.html`, the rendered article
- one PNG in `assets/` for each code block, table and diagram
- `desktop.png`, `mobile.png` and the card inspection files

An article with its images is about 8 MB. Its sources are about 0.5 MB.

## Read an article

1. Set up the render tool one time. See [`_shared/README.md`](_shared/README.md).
2. Render the article:

   ```sh
   python3 articles/_shared/render.py articles/01-per-pod-certificates
   ```

3. Open `articles/01-per-pod-certificates/preview.html` in a browser.

You can also read `article.md` directly. It has the full text and each code
block. Its image lines point to files that the render makes.

## Write the next article

1. Read [`SERIES.md`](SERIES.md).
2. Create `articles/NN-slug/`.
3. Run each command on a test cluster. Save the raw output in `evidence/`.
4. Write `article.md`, `post.md` and `facts.md`.
5. Write `assets/BRIEF.md`.
6. Make the cover from [`_shared/COVER.md`](_shared/COVER.md).
7. Draw each diagram from [`_shared/DIAGRAMS.md`](_shared/DIAGRAMS.md).
8. Render the article. See [`_shared/README.md`](_shared/README.md) for the setup.

   ```sh
   python3 articles/_shared/render.py articles/NN-slug
   ```

9. Open `card-inspection.png`, `desktop.png` and `mobile.png`. Check each image.
10. Add the article to the table in this file.

If an article uses an image from another directory of the repository, copy it
into `assets/` before the render. `assets/BRIEF.md` names its source path.

## Publish on LinkedIn

The LinkedIn article editor has no code blocks, no tables and no SVG images.
Thus each code block, table and diagram is also a PNG in `assets/`.

1. Render the article.
2. Copy the text from `preview.html`.
3. Upload `assets/cover.jpg` as the cover image.
4. Put each PNG at the position of its image line in `article.md`.
5. Put the article link in `post.md` in place of `<link>`.

How LinkedIn renders and compresses the images was not verified.

## Never commit a private key

`evidence/` holds command output from a cluster. Do not save a private key, a
token or a kubeconfig there. The repository hygiene test rejects a PEM private
key header in each tracked file.
