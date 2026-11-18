# Cover specification

Use the built-in image generation tool.
Request a 16:9 canvas.
Accept the image tool output at 1672 × 941 pixels.
This matches the earlier series within one pixel of 16:9.
Do not resize the generated cover.
Use `assets/social-card.png` from the repository root as a style reference only.
Use `assets/logo.png` from the repository root as the mascot reference.
View both reference images before generation.

Keep the cream background from `#faf6ea` to `#f3ebd6`.
Place a thin blue-to-green stripe at the top.
Use rounded bold typography.
Use navy `#1f2a44`, muted `#5b6785`, and blue `#2f63d6`.
Place the text on the left.
Place the blue project mascot on the right.
Place a pale Kubernetes wheel behind the mascot.
Give the mascot only the prop from the brief.
Keep all text inside the canvas with generous margins.

The eyebrow is exactly `KUBERNETES · POD CERTIFICATE SIGNER`.
Use the three title lines from the brief.
Render the first line in blue.
Render the second and third lines in navy.
Use the exact subtitle and three pastel pill labels from the brief.
Do not add text, product logos, or invented numbers.
Do not copy text from either reference image.

Convert the image to JPEG and save it as `<article-dir>/assets/cover.jpg`.
Use quality 88 and do not change the pixel size.
On macOS, use `sips -s format jpeg -s formatOptions 88 cover.png --out cover.jpg`.
Git tracks the JPEG, because no command makes the cover again.
Record the tool, date, references, and final prompt in `assets/cover-provenance.md`.
View the saved image before rendering the article.
Check every character against the brief.
Check that the cover uses the accepted dimensions or an exact 16:9 ratio.
Regenerate the cover if text or layout fails these checks.

## Prompt template

```text
Use case: illustration-story.
Create a new 16:9 editorial cover for the pod-certificate-signer article series.
Image 1 is assets/social-card.png, a STYLE REFERENCE ONLY.
Image 2 is assets/logo.png, the mascot identity reference.
Preserve the friendly blue pod mascot from Image 2.
Use a cream background, a thin blue-to-green top stripe, and rounded bold typography.
Place the text on the left and the mascot on the right.
Place a pale Kubernetes wheel behind the mascot.
The mascot holds one prop: {PROP}.
Render this exact eyebrow: KUBERNETES · POD CERTIFICATE SIGNER
Render these exact title lines:
{TITLE_LINE_1} [blue]
{TITLE_LINE_2} [navy]
{TITLE_LINE_3} [navy]
Render this exact subtitle: {SUBTITLE}
Render these three exact pastel pill labels: {PILL_1}, {PILL_2}, {PILL_3}.
Use blue #2f63d6, navy #1f2a44, and muted #5b6785.
Keep generous margins and readable text.
No extra text, other product logos, or invented numbers.
Do not render placeholder names or color instructions as text.
```
