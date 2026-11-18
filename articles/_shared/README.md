# Shared article toolkit

The toolkit reads one article directory.
It writes code cards, table cards, diagram PNGs, HTML, and screenshots inside that directory.
It uses the layout from the earlier kube-oidc-proxy series.
The preview contains inline CSS and relative image paths.
Keep the preview beside its assets when you share it.

## Install

Use Python 3.11 or later.
Create the virtual environment outside the repository.
Run these commands from the repository root.

```sh
python3 -m venv /tmp/pcs-article-toolkit-venv
/tmp/pcs-article-toolkit-venv/bin/python -m pip install -r articles/_shared/requirements.txt
/tmp/pcs-article-toolkit-venv/bin/python -m playwright install chromium
```

The requirements file records the version check date.
The Playwright package selects its matching Chromium revision.
Set `PCS_ARTICLE_VENV` if you use another external environment path.
Set `PCS_ARTICLE_BROWSER` to use an existing Chromium executable instead.
The renderer starts the external Python interpreter automatically.

## Prepare an article

1. Create the article directory `articles/NN-slug/` in this repository.
2. Read `articles/SERIES.md`.
3. Write `article.md` in the article directory.
4. Read that article's `assets/BRIEF.md`.
5. Generate `assets/cover.jpg` with the instructions in `COVER.md`.
6. Draw each diagram with the instructions in `DIAGRAMS.md`.
7. Copy each reused image to its relative path.
8. Place the cover image line directly after the H1 title.
9. Place each code-card image line directly above its fenced block.
10. Use a unique PNG filename for each code card.

```markdown
![Read the certificate](assets/read-certificate.png)
~~~sh
cat /var/run/certificates/credential-bundle.pem
~~~
```

The renderer accepts `sh`, `yaml`, `text`, `promql`, and `json` fences.
It accepts backtick fences and tilde fences.
It also accepts blank lines between the image and its fence.
It preserves the code body, including spaces, tabs, and its final newline.
It compares the browser text with the original UTF-8 bytes.
It uses navy code text for `sh`, `yaml`, `promql`, and `json`.
A `text` block without a `$ ` line also uses navy text.
In other `text` blocks, `$ ` starts a command line.
The prompt character uses accent blue.
Command text uses navy.
Output uses muted `#5b6785`.
A trailing continuation backslash keeps the next line in the command colour.
An open single or double quote also keeps subsequent lines in the command colour.
The renderer preserves every character and line ending when it adds colour.
The image alt text supplies the card header.
Every image path must refer to a local file.

Keep each code line within 90 characters.
Keep each code block within 25 lines.
The character check expands tabs to four-column stops.
Line endings do not count as characters.
The renderer reports each rejected line with its `article.md` line number.
For an oversized block, it reports the location of line 26.
The renderer checks these limits before writing output files.

Code cards never wrap code lines.
All cards use one width that fits 90 characters in the selected monospace font.
The width does not depend on the block length.
The renderer preserves the header label from the image alt text.

## Render

Replace the directory in this command with your article directory.

```sh
python3 articles/_shared/render.py articles/01-per-pod-certificates
```

Use this command for the included sample.

```sh
python3 articles/_shared/render.py articles/_shared/sample
```

The renderer exports every `assets/*.svg` file at twice its original size.
It creates one HTML source and one PNG for each code card.
It creates `preview.html`, `desktop.png`, and `mobile.png`.
The screenshot widths are 1200 px and 390 px.
It also writes `card-inspection.html` and `card-inspection.png`.
The gallery shows every code card and table card at 744 px wide.
The renderer prints the computed code text size at that width.
It fails if that size falls below 12.5 px.
The checked macOS environment uses 1150 px cards and 12.94 px text at 744 px.
Narrower screens scale the card text proportionally.
Open the gallery to inspect every card before publication.
It checks page overflow with code sections open and closed.
A missing image stops the render with its path.
The renderer blocks external browser requests.

Open `preview.html` in a browser.
Select an image to open its full size.
Expand `View and copy the code` to select the original code.
Inspect both screenshots and every asset before publication.

The sample describes the toolkit only.
It does not provide evidence about a Kubernetes cluster.

## Table cards

Keep each Markdown table in `article.md`.
Do not replace the source table with an image line.
The renderer creates `assets/table-1.png`, `assets/table-2.png`, and subsequent numbers in document order.
Reserve these filenames for table cards.
The renderer also saves the HTML source beside each PNG.

Table cards use the same source width as code cards.
The header row uses bold text on a light blue band.
Columns use automatic layout based on their content.
The table card has no title above its header row.
Inline identifiers can wrap only after `.`, `/`, `:`, `,`, `-`, or `_`.
Each segment between those separators stays on one line.
Columns expand to fit an unbreakable segment.
A segment wider than the entire card causes an error instead of clipping.
Inline code keeps the monospace font.
Rows grow to fit their text.
The renderer checks each cell for overflow.

Table body text measures at least 14 px at a card width of 744 px.
The checked macOS environment uses 14.23 px text at that width.
The preview places the table image before an expandable HTML table.
Select `View the table as text` to read or select the table content.
Use the image when you publish through the LinkedIn editor.
Inspect long identifiers at full size before publication.

## Check the renderer

Run the additional checks with this command.

```sh
python3 articles/_shared/selftest.py
```

The checks cover all five languages, exact whitespace, HTML characters, and missing images.
They also check card limits, equal widths, and the gallery width.
Table checks cover three columns, long text, inline code, numbering, and expandable HTML.
They use a temporary directory under `articles/_shared/`.
They remove that directory when the checks finish.
