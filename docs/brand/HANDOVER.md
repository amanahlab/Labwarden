# LabWarden logo — handover notes

## Rationale
- **Round 1:** three directions (Prompt Tower, Chart Key, Flagged Rack). The tower won, but it needed to show a server instead of a terminal prompt, and the brief moved to "bolder, more alert".
- **Round 2:** three tower-and-rack variations. **Stacked Keep** was chosen: the most legible at small sizes, and the clearest "tower = rack" reading.
- **Final:** the tower is 144 × 184 on a 256 grid, with five 28.8-wide crenel units and three 40-tall server units separated by 12-unit gaps. Corners are square throughout to match the squared wordmark. The LED circles are sized to look as big as the diamond (r 8.5 against a 13.5 half-diagonal).

## Tests run
- `svg_audit.py` on the masters scored 97 to 100 with no warnings. The masters are paths only: no live text, rasters, filters or gradients.
- `preview_sheet.py` checks (`work/preview.html`): size ladder, pixel test at 16/32/48 px, backgrounds, one colour, reversed, squint/blur, mirrored and rotated, plus favicon, app-icon and header contexts.
  - At 16 to 24 px the detailed symbol turns to mush. That's why there is a pixel-fitted **small cut**, which keeps the battlements and the alert light at 16 px.
  - Mirrored and rotated views gave no unintended readings.
- **Reversed version:** solids are thinned by 1.5 units and holes opened by the same amount, to counter the way white on dark looks heavier.

## Open items
- **Trademark:** not searched. Run a professional trademark search and a reverse image search before launch.
- **Print colour:** the CMYK and Pantone values are approximations. Proof them against a physical swatch.
- **Mockups:** in the board, the app-icon, terminal and sticker mockups draw the reversed symbol in plain white, so the orange light is lost there. The real web icons (`web/public/`) keep the orange.
- **No PDF/AI/EPS masters were produced** because no vector app was available. If a printer asks for them, export from the SVGs in Inkscape or Illustrator.
