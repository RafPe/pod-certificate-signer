# Diagram instructions

Read the diagram entry in `assets/BRIEF.md`.
Use `diagram-template.svg` as the starting file.
Save the diagram under the filename from the brief, with an `.svg` extension.
The renderer writes the matching `.png` file at twice the SVG dimensions.

1. Preserve the exact title, box labels, arrow labels, direction, and reading order.
2. Use a 1400 px canvas width.
3. Increase the height when the content needs more space.
4. Keep a 40 px margin around the content.
5. Use the cream gradient and the thin blue-to-green stripe.
6. Draw white boxes with 18 px corners and a 2 px border.
7. Keep at least 28 px between text and each box edge.
8. Use 28 px box titles and 23 px body text.
9. Use 21 px arrow labels and 3 px blue arrows.
10. Keep arrow labels at least 20 px above each arrow.
11. Use explicit `tspan` lines for long labels.
12. Increase box dimensions when the exact text does not fit.
13. Keep every label inside its box.
14. Keep every arrow outside box text.
15. Use one pale blue accent band below the boxes.
16. Use one muted footnote line below that band.
17. Limit each diagram to eight boxes and one idea.
18. Describe the reading order in the SVG `desc` element.
19. Use local fonts from the template.
20. View the PNG at full size and inside the mobile preview.

Do not invent a relationship or a number.
Ask the article author when the brief does not specify required content.
Do not use external fonts, scripts, images, or product logos.

The template shows the toolkit workflow only.
Replace its text with the exact text from the article brief.
The browser exports the SVG at a scale factor of two.
A 1400 px SVG produces a 2800 px PNG.
