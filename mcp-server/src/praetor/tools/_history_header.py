"""Draw a Burp-style "Proxy > HTTP history" context header above a captured
request/response evidence shot, so it reads as real proxy-history evidence
(top tab bar + sub-tabs + the selected history row with its real metadata).

Composited in Python (PIL) on top of the side-by-side panes — no dependency on
Burp's live table. The pure row/title helpers are unit-tested; the draw shells
out to PIL.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# Top-level Burp tabs and the Proxy sub-tabs, for the context breadcrumb.
_TOP_TABS = ["Dashboard", "Target", "Proxy", "Intruder", "Repeater",
             "Collaborator", "Sequencer", "Decoder", "Comparer", "Logger",
             "Organizer", "Extensions"]
_SUB_TABS = ["Intercept", "HTTP history", "WebSockets history", "Match and replace"]

# HTTP-history columns (name, relative weight — normalised to the width). Mirrors
# Burp's HTTP history row.
_COLS = [
    ("#", 2.5), ("Host", 11), ("Method", 4.5), ("URL", 17), ("Params", 3.5),
    ("Edited", 3.5), ("Status", 4.5), ("Length", 5), ("MIME", 5), ("Extension", 4.5),
    ("Title", 11), ("Notes", 5), ("TLS", 3), ("IP", 7), ("Cookies", 7),
    ("Time", 6), ("Listener", 5),
]


def title_from_body(body: str) -> str:
    """Extract <title> text from a response body (Burp's Title column)."""
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    return (m.group(1).strip() if m else "")[:80]


def _cookies(entry: dict) -> str:
    """Set-Cookie names from the response headers (Burp's Cookies column)."""
    names = []
    for h in entry.get("response_headers", []) or []:
        n = h.get("name", "") if isinstance(h, dict) else ""
        v = h.get("value", "") if isinstance(h, dict) else ""
        if n.lower() == "set-cookie" and "=" in v:
            names.append(v.split("=", 1)[0].strip())
    return ", ".join(names)


def _extension(path: str) -> str:
    seg = path.rsplit("/", 1)[-1]
    if "." in seg:
        ext = seg.rsplit(".", 1)[-1]
        if ext and len(ext) <= 5 and ext.isalnum():
            return ext
    return ""


def _time_hms(iso: str) -> str:
    m = re.search(r"T(\d{2}:\d{2}:\d{2})", iso or "")
    return m.group(1) if m else (iso or "")[:8]


def row_values(entry: dict, index: int) -> dict:
    """The history-row cell values for a proxy-history detail dict."""
    url = str(entry.get("url", ""))
    parsed = urlparse(url)
    has_params = bool(parsed.query) or bool(str(entry.get("request_body", "")).strip())
    return {
        "#": str(entry.get("entry_number", index)),
        "Host": str(entry.get("host", "") or parsed.netloc or url),
        "Method": str(entry.get("method", "")),
        "URL": (parsed.path or "/") + (("?" + parsed.query) if parsed.query else ""),
        "Params": "✓" if has_params else "",
        "Edited": "✓" if entry.get("edited") else "",
        "Status": str(entry.get("status_code", "")),
        "Length": str(entry.get("response_length", "")),
        "MIME": str(entry.get("mime_type", "")),
        "Extension": _extension(parsed.path),
        "Title": title_from_body(entry.get("response_body", "")),
        "Notes": str(entry.get("notes", "") or ""),
        "TLS": "✓" if (entry.get("secure") or url.startswith("https")) else "",
        "IP": str(entry.get("ip", "") or ""),
        "Cookies": _cookies(entry),
        "Time": _time_hms(str(entry.get("time", ""))),
        "Listener": str(entry.get("listener_port", "") or ""),
    }


def _clip(draw, text, font, maxw):
    if not text:
        return ""
    if draw.textlength(text, font=font) <= maxw:
        return text
    while text and draw.textlength(text + "…", font=font) > maxw:
        text = text[:-1]
    return text + "…"


# Burp's real palette (sampled from a live capture).
_BG = (251, 251, 251)
_BAND = (238, 238, 238)
_SEL = (202, 218, 240)          # selected history row — pale blue
_SEL_EDGE = (38, 100, 157)
_ORANGE = (219, 97, 47)         # active-tab underline / logo
_SEP = (223, 223, 223)
_TEXT = (40, 40, 40)
_GRAY = (100, 100, 100)
_MENU = ["Burp", "Project", "Intruder", "Repeater", "View", "Help"]


def _load_fonts(fs: int):
    from PIL import ImageFont
    for base in ("liberation/LiberationSans", "dejavu/DejaVuSans"):
        try:
            root = f"/usr/share/fonts/truetype/{base}"
            return (ImageFont.truetype(f"{root}.ttf", fs),
                    ImageFont.truetype(f"{root}-Bold.ttf", fs))
        except OSError:
            continue
    from PIL import ImageFont as F
    return F.load_default(), F.load_default()


def _paste_icon(img, icon_b64: str, x: int, y_center: int, size: int) -> bool:
    """Paste the real Burp window icon (PNG base64) centred vertically at y. True
    on success, False to fall back to a drawn glyph."""
    if not icon_b64:
        return False
    try:
        import base64
        import io
        from PIL import Image as PImage
        ic = PImage.open(io.BytesIO(base64.b64decode(icon_b64))).convert("RGBA")
        ic = ic.resize((size, size))
        img.paste(ic, (x, y_center - size // 2), ic)
        return True
    except Exception:
        return False


def build_header(entry: dict, index: int, width: int, scale: float = 2.0,
                 title: str = "", icon_b64: str = ""):
    """A Burp-style header: title bar + menu + tab bar + Proxy sub-tabs + filter
    bar + the selected HTTP-history row, matched to Burp's real colours. `title`
    and `icon_b64` (from the live window) render the exact chrome when supplied."""
    from PIL import ImageDraw
    from PIL import Image as PImage
    s = scale
    fs = int(13 * s)            # top-level tabs
    fs_sm = int(11 * s)         # menu / title / sub-tabs / filter / columns
    pad = int(9 * s)
    # Compact chrome so the HTTP message panes below get the most room.
    titlemenu_h = int(26 * s)   # icon + menu + title on ONE row
    tabbar_h, subbar_h, filt_h = int(26 * s), int(22 * s), int(20 * s)
    colhdr_h, row_h = int(21 * s), int(25 * s)
    H = titlemenu_h + tabbar_h + subbar_h + filt_h + colhdr_h + row_h

    img = PImage.new("RGB", (width, H), _BG)
    d = ImageDraw.Draw(img)
    fs_ttl = int(10 * s)                     # window title (smallest)
    font, bold = _load_fonts(fs)             # tabs
    sfont, sbold = _load_fonts(fs_sm)        # menu / sub-tabs / columns
    _, tbold = _load_fonts(fs_ttl)           # title

    def strip(y, h, items, active, gap, fnt, bfnt, fsz, x0=None):
        x = pad if x0 is None else x0
        for name in items:
            f = bfnt if name == active else fnt
            d.text((x, y + (h - fsz) // 2 - int(1 * s)), name,
                   fill=_TEXT if name == active else _GRAY, font=f)
            w = d.textlength(name, font=f)
            if name == active:
                d.rectangle([x, y + h - int(3 * s), x + w, y + h - 1], fill=_ORANGE)
            x += int(w) + gap
        d.line([0, y + h, width, y + h], fill=_SEP)

    # ONE top row: real Burp icon + menu items (left) + centred window title
    isz = int(15 * s)
    if not _paste_icon(img, icon_b64, pad, titlemenu_h // 2, isz):
        d.rectangle([pad, (titlemenu_h - isz) // 2, pad + isz, (titlemenu_h + isz) // 2],
                    fill=(255, 102, 0))
    mx = pad + isz + int(10 * s)
    for name in _MENU:
        d.text((mx, (titlemenu_h - fs_sm) // 2), name, fill=_GRAY, font=sfont)
        mx += int(d.textlength(name, font=sfont)) + int(14 * s)
    ttl = title.strip() or "Burp Suite Professional"
    d.text(((width - d.textlength(ttl, font=tbold)) // 2, (titlemenu_h - fs_ttl) // 2), ttl,
           fill=_TEXT, font=tbold)
    d.line([0, titlemenu_h, width, titlemenu_h], fill=_SEP)
    # top-level tabs (larger) + Proxy sub-tabs (smaller)
    y = titlemenu_h
    strip(y, tabbar_h, _TOP_TABS, "Proxy", int(18 * s), font, bold, fs)
    strip(y + tabbar_h, subbar_h, _SUB_TABS, "HTTP history", int(16 * s), sfont, sbold, fs_sm)
    # filter bar
    yf = y + tabbar_h + subbar_h
    d.text((pad, yf + (filt_h - fs_sm) // 2), "Filter settings: Hiding CSS and image "
           "content; hiding specific extensions", fill=_GRAY, font=sfont)
    d.line([0, yf + filt_h, width, yf + filt_h], fill=_SEP)

    # normalise column weights -> pixel positions/widths
    total = sum(wgt for _, wgt in _COLS)
    xs, widths, acc = [], [], 0.0
    for _, wgt in _COLS:
        xs.append(int(acc / total * width))
        widths.append(int(wgt / total * width))
        acc += wgt

    # column-header band
    y0 = yf + filt_h
    d.rectangle([0, y0, width, y0 + colhdr_h], fill=_BAND)
    for (name, _), x, cw in zip(_COLS, xs, widths):
        d.text((x + pad, y0 + (colhdr_h - fs_sm) // 2), _clip(d, name, sfont, cw - 2 * pad),
               fill=_GRAY, font=sfont)
        if x > 0:
            d.line([x, y0, x, y0 + colhdr_h + row_h], fill=_SEP)

    # selected data row — pale blue, dark text (Burp's real selection)
    y1 = y0 + colhdr_h
    d.rectangle([0, y1, width, y1 + row_h], fill=_SEL)
    d.rectangle([0, y1, width, y1 + int(1 * s)], fill=_SEL_EDGE)
    vals = row_values(entry, index)
    for (name, _), x, cw in zip(_COLS, xs, widths):
        d.text((x + pad, y1 + (row_h - fs_sm) // 2),
               _clip(d, vals.get(name, ""), sfont, cw - 2 * pad), fill=_TEXT, font=sfont)
    return img


def prepend_history_header(panes_path: str, entry: dict, index: int,
                           scale: float = 2.0, title: str = "",
                           icon_b64: str = "") -> int:
    """Stack a history-context header above the panes image at `panes_path`
    (overwrites it). Returns the header height in px."""
    from PIL import Image
    panes = Image.open(panes_path).convert("RGB")
    header = build_header(entry, index, panes.width, scale, title, icon_b64)
    out = Image.new("RGB", (panes.width, panes.height + header.height), (255, 255, 255))
    out.paste(header, (0, 0))
    out.paste(panes, (0, header.height))
    out.save(panes_path)
    return header.height
