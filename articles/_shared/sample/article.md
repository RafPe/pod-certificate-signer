# Per-pod x509 certificates
![cover](assets/cover.png)

This sample checks the shared article toolkit before the series uses it. The cover introduces the visual style. The article panel keeps text readable on desktop and mobile screens. Each image opens at its full size when you select it.

## Read the example

The code card below shows a short shell example. Expand the section below the card to select the original text. The renderer compares that text with the fenced block before it saves the screenshots. This example prints a label and does not contact a Kubernetes cluster.

![Print a sample label](assets/sample-code.png)
```text
$ printf '%s\n' 'pod-certificate-signer'
pod-certificate-signer
$ printf '%s\n' \
  'first line
second line'
first line
second line
```

## Follow the diagram

The diagram shows how article files become preview files. Its boxes describe the toolkit, not certificate issuance. The table names the files that you inspect after rendering.

![Article source flows through the renderer to the preview](assets/flow.png)

| File | Purpose | Inspection |
| --- | --- | --- |
| `preview.html` | Read the article with its images and expandable source sections. | Open each image at full size, then expand the code and table sections to compare their text. |
| `desktop.png` | Check the desktop layout before publication. | Confirm that long table descriptions wrap inside their cells without hiding words or overlapping adjacent columns. |
| `mobile.png` | Check the mobile layout on a narrow screen. | Confirm that each image remains inside the article panel and that expanded tables do not cause page overflow. |

## Check the result

Open both screenshots. Check the cover text, code card, table, and diagram. Confirm that each image fits the article panel without hiding any text or forcing horizontal page scrolling.

Keep these checks with the other article assets.
