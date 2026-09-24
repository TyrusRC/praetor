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


# Logger's own columns (differ from Proxy history).
_LOGGER_COLS = [
    ("#", 2.5), ("Time", 9.5), ("Tool", 4.5), ("Method", 4.5), ("Host", 13),
    ("Path", 15), ("Query", 12), ("Param count", 6), ("Status code", 6),
    ("Length", 5.5), ("Start response timer", 9), ("Comment", 8),
]

_MONTHS = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
           "Oct", "Nov", "Dec"]


def _time_full(iso: str) -> str:
    """'2026-09-24T20:22:32...' -> '20:22:32 24 Sep 2026' (Logger's Time format)."""
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2}:\d{2})", iso or "")
    if not m:
        return (iso or "")[:19]
    y, mo, da, hms = m.groups()
    return f"{hms} {int(da)} {_MONTHS[int(mo)]} {y}"


def logger_row(entry: dict, index: int) -> dict:
    url = str(entry.get("url", ""))
    p = urlparse(url)
    q = p.query
    return {
        "#": str(entry.get("entry_number", index)),
        "Time": _time_full(str(entry.get("time", ""))),
        "Tool": "Proxy",
        "Method": str(entry.get("method", "")),
        "Host": p.netloc,
        "Path": p.path or "/",
        "Query": q,
        "Param count": str(len([x for x in q.split("&") if x]) if q else 0),
        "Status code": str(entry.get("status_code", "")),
        "Length": str(entry.get("response_length", "")),
        "Start response timer": "",
        "Comment": "",
    }


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
                 title: str = "", icon_b64: str = "", tool: str = "proxy"):
    """A Burp-style chrome header matched to Burp's real colours, for the source
    `tool`: 'proxy' (Proxy>HTTP history tabs + history row), 'logger' (Logger tab
    + row, no sub-tabs), or 'repeater' (Repeater tab + numbered request tabs, no
    table). `title`/`icon_b64` (from the live window) render the exact chrome."""
    from PIL import ImageDraw
    from PIL import Image as PImage
    s = scale
    fs = int(13 * s)            # top-level tabs
    fs_sm = int(11 * s)         # menu / sub-tabs / filter / columns
    fs_ttl = int(10 * s)        # window title (smallest)
    pad = int(9 * s)
    titlemenu_h = int(26 * s)
    tabbar_h, subbar_h, filt_h = int(26 * s), int(22 * s), int(20 * s)
    colhdr_h, row_h = int(21 * s), int(25 * s)

    tool = (tool or "proxy").strip().lower()
    active = {"logger": "Logger", "repeater": "Repeater"}.get(tool, "Proxy")
    has_sub = tool in ("proxy", "repeater")          # HTTP-history or numbered tabs
    has_table = tool in ("proxy", "logger")          # filter(s) + columns + row
    toolbar_h = int(30 * s)                          # Repeater Send/Target toolbar
    label_h = int(22 * s)                            # Request / Response labels
    n_filters = 2 if tool == "logger" else 1         # Logger has capture + view filters
    H = titlemenu_h + tabbar_h
    H += subbar_h if has_sub else 0
    H += toolbar_h if tool == "repeater" else 0
    H += (n_filters * filt_h + colhdr_h + row_h) if has_table else 0
    H += label_h

    img = PImage.new("RGB", (width, H), _BG)
    d = ImageDraw.Draw(img)
    font, bold = _load_fonts(fs)
    sfont, sbold = _load_fonts(fs_sm)
    _, tbold = _load_fonts(fs_ttl)

    def strip(y, h, items, act, gap, fnt, bfnt, fsz):
        x = pad
        for name in items:
            f = bfnt if name == act else fnt
            d.text((x, y + (h - fsz) // 2 - int(1 * s)), name,
                   fill=_TEXT if name == act else _GRAY, font=f)
            w = d.textlength(name, font=f)
            if name == act:
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

    # top-level tabs
    y = titlemenu_h
    strip(y, tabbar_h, _TOP_TABS, active, int(18 * s), font, bold, fs)
    y += tabbar_h
    # sub-tabs
    if has_sub:
        if tool == "repeater":
            # a single open request tab "1 ✕" then "+"
            d.text((pad, y + (subbar_h - fs_sm) // 2 - int(1 * s)), "1", fill=_TEXT, font=sbold)
            w1 = d.textlength("1", font=sbold)
            d.text((pad + w1 + int(6 * s), y + (subbar_h - fs_sm) // 2 - int(1 * s)),
                   "✕", fill=_GRAY, font=sfont)
            d.rectangle([pad, y + subbar_h - int(3 * s), pad + w1, y + subbar_h - 1], fill=_ORANGE)
            d.text((pad + w1 + int(28 * s), y + (subbar_h - fs_sm) // 2 - int(1 * s)),
                   "+", fill=_GRAY, font=sfont)
            d.line([0, y + subbar_h, width, y + subbar_h], fill=_SEP)
        else:
            strip(y, subbar_h, _SUB_TABS, "HTTP history", int(16 * s), sfont, sbold, fs_sm)
        y += subbar_h

    # Repeater toolbar: Send + Cancel + arrows + Burp AI + right-aligned Target
    if tool == "repeater":
        by = y + (toolbar_h - int(20 * s)) // 2
        d.rounded_rectangle([pad, by, pad + int(56 * s), by + int(20 * s)],
                            radius=int(3 * s), fill=_ORANGE)
        d.text((pad + int(14 * s), by + (int(20 * s) - fs_sm) // 2), "Send",
               fill=(255, 255, 255), font=sbold)
        tx = pad + int(70 * s)
        for lbl in ("Cancel", "‹", "›", "Burp AI"):
            d.text((tx, y + (toolbar_h - fs_sm) // 2), lbl, fill=_GRAY, font=sfont)
            tx += int(d.textlength(lbl, font=sfont)) + int(16 * s)
        tgt = "Target: " + (urlparse(str(entry.get("url", ""))).scheme + "://" +
                            urlparse(str(entry.get("url", ""))).netloc) + "    HTTP/1"
        d.text((width - d.textlength(tgt, font=sfont) - pad,
                y + (toolbar_h - fs_sm) // 2), tgt, fill=_TEXT, font=sfont)
        d.line([0, y + toolbar_h, width, y + toolbar_h], fill=_SEP)
        y += toolbar_h

    if has_table:
        cols = _LOGGER_COLS if tool == "logger" else _COLS
        vals = logger_row(entry, index) if tool == "logger" else row_values(entry, index)
        # filter bar(s)
        if tool == "logger":
            for txt in ("Capture filter: Logger memory limit set to 100MB | Capturing "
                        "requests up to 1MB; capturing responses up to 1MB",
                        "View filter: Showing all items"):
                d.text((pad, y + (filt_h - fs_sm) // 2), txt, fill=_GRAY, font=sfont)
                d.line([0, y + filt_h, width, y + filt_h], fill=_SEP)
                y += filt_h
        else:
            d.text((pad, y + (filt_h - fs_sm) // 2), "Filter settings: Hiding CSS and "
                   "image content; hiding specific extensions", fill=_GRAY, font=sfont)
            d.line([0, y + filt_h, width, y + filt_h], fill=_SEP)
            y += filt_h

        # columns
        total = sum(wgt for _, wgt in cols)
        xs, cws, acc = [], [], 0.0
        for _, wgt in cols:
            xs.append(int(acc / total * width))
            cws.append(int(wgt / total * width))
            acc += wgt
        d.rectangle([0, y, width, y + colhdr_h], fill=_BAND)
        for (name, _), x, cw in zip(cols, xs, cws):
            d.text((x + pad, y + (colhdr_h - fs_sm) // 2), _clip(d, name, sfont, cw - 2 * pad),
                   fill=_GRAY, font=sfont)
            if x > 0:
                d.line([x, y, x, y + colhdr_h + row_h], fill=_SEP)
        y1 = y + colhdr_h
        d.rectangle([0, y1, width, y1 + row_h], fill=_SEL)
        d.rectangle([0, y1, width, y1 + int(1 * s)], fill=_SEL_EDGE)
        for (name, _), x, cw in zip(cols, xs, cws):
            d.text((x + pad, y1 + (row_h - fs_sm) // 2),
                   _clip(d, vals.get(name, ""), sfont, cw - 2 * pad), fill=_TEXT, font=sfont)
        y = y1 + row_h

    # Request | Response labels above the panes (side-by-side halves)
    d.text((pad, y + (label_h - fs) // 2), "Request", fill=_TEXT, font=bold)
    d.text((width // 2 + pad, y + (label_h - fs) // 2), "Response", fill=_TEXT, font=bold)
    return img


def prepend_history_header(panes_path: str, entry: dict, index: int,
                           scale: float = 2.0, title: str = "",
                           icon_b64: str = "", tool: str = "proxy") -> int:
    """Stack a `tool` chrome header above the panes image at `panes_path`
    (overwrites it). Returns the header height in px."""
    from PIL import Image
    panes = Image.open(panes_path).convert("RGB")
    header = build_header(entry, index, panes.width, scale, title, icon_b64, tool)
    out = Image.new("RGB", (panes.width, panes.height + header.height), (255, 255, 255))
    out.paste(header, (0, 0))
    out.paste(panes, (0, header.height))
    out.save(panes_path)
    return header.height
