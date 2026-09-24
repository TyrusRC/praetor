"""Draw a red call-out box around Burp's native search highlight in a screenshot.

Pentest-report standard: frame the payload / result in RED ("khoanh đỏ") so the
reader's eye lands on the finding. Burp's `setSearchExpression` already paints a
yellow background behind every match; this finds those yellow regions by colour
(robust — no OCR of symbol-heavy payloads) and draws a red rectangle around each.

The colour test and the point→box clustering are pure and unit-tested; the image
scan / draw shell out to PIL.
"""

from __future__ import annotations

# Burp's TEXT search highlight is a solid yellow ~(248,248,95): R,G both high and
# nearly equal, B in a mid band (~95). Two look-alikes are deliberately excluded:
#   - UI chrome (tab underline / search accent) is a PALE tan ~(255,222,156):
#     higher B and a wider R-G gap.
#   - Burp's SCROLLBAR match-markers are a PURE yellow (255,255,0): B≈0.
# So B must sit in [40,130] — the text highlight's band, not 0 and not pale.
def is_highlight(r: int, g: int, b: int) -> bool:
    return r >= 225 and g >= 225 and 40 <= b <= 130 and abs(r - g) <= 25


def cluster_points(points: list[tuple[int, int]], y_tol: int = 22,
                   min_w: int = 10, min_h: int = 8) -> list[list[int]]:
    """Group yellow (x,y) points into per-match [x,y,w,h] boxes.

    Points whose y falls within `y_tol` of an existing box's vertical span join it
    (one text line's highlight is contiguous in y); a far-apart match starts a new
    box. Tiny boxes (stray yellow pixels — icons, anti-aliasing) are dropped.
    """
    if not points:
        return []
    boxes: list[list[int]] = []   # each [minx, miny, maxx, maxy]
    for x, y in sorted(points, key=lambda p: (p[1], p[0])):
        for bx in boxes:
            if bx[1] - y_tol <= y <= bx[3] + y_tol:
                bx[0] = min(bx[0], x)
                bx[1] = min(bx[1], y)
                bx[2] = max(bx[2], x)
                bx[3] = max(bx[3], y)
                break
        else:
            boxes.append([x, y, x, y])
    out = [[a, b, c - a, d - b] for a, b, c, d in boxes]
    return [box for box in out if box[2] >= min_w and box[3] >= min_h]


def find_highlight_boxes(img, step: int = 2) -> list[list[int]]:
    """Scan the image for highlight-yellow pixels and cluster them into boxes."""
    px = img.load()
    w, h = img.size
    pts: list[tuple[int, int]] = []
    for y in range(0, h, step):
        for x in range(0, w, step):
            p = px[x, y]
            if is_highlight(p[0], p[1], p[2]):
                pts.append((x, y))
    return cluster_points(pts)


def _clear_yellow(img, boxes, pad: int) -> None:
    """Repaint Burp's yellow highlight pixels to white inside each box region, so
    a red-box call-out isn't doubled up with the native yellow (the reader gets
    ONE marker). Glyph pixels aren't yellow, so the text survives."""
    px = img.load()
    w, h = img.size
    for x, y, bw, bh in boxes:
        for yy in range(max(0, y - pad), min(h, y + bh + pad)):
            for xx in range(max(0, x - pad), min(w, x + bw + pad)):
                p = px[xx, yy]
                if is_highlight(p[0], p[1], p[2]):
                    px[xx, yy] = (255, 255, 255)


def annotate_highlights(path: str, pad: int = 7, thickness: int = 4,
                        draw_box: bool = True, clear_native: bool = True) -> int:
    """Mark the native highlight(s) in the PNG at `path` (overwrites it).

    `draw_box` draws a red call-out rectangle around each match; `clear_native`
    repaints the yellow search highlight to white. The default (box on, native
    off) yields a RED-BOX-ONLY marker — never both a red box and a yellow fill.
    Returns the number of matches found (0 = none)."""
    from PIL import Image, ImageDraw
    img = Image.open(path).convert("RGB")
    boxes = find_highlight_boxes(img)
    if not boxes:
        return 0
    if clear_native:
        _clear_yellow(img, boxes, pad)
    if draw_box:
        d = ImageDraw.Draw(img)
        w, h = img.size
        for x, y, bw, bh in boxes:
            d.rectangle(
                [max(0, x - pad), max(0, y - pad),
                 min(w - 1, x + bw + pad), min(h - 1, y + bh + pad)],
                outline=(220, 0, 0), width=thickness,
            )
    img.save(path)
    return len(boxes)
