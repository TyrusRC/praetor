"""screenshot_gallery — offline visual-triage contact sheet (aquatone-style).

Browser tools drop screenshots at .burp-intel/<domain>/screenshots/<ts>.png but
there is no way to eyeball them together to spot login/admin/staging panels.
This renders a single HTML grid under reports/gallery.html with relative <img>
refs to the screenshots dir (opened locally beside them — a triage aid, not a
shareable artifact).

`render_gallery_html` is pure; `screenshot_gallery` scans the dir + writes.
"""

from __future__ import annotations

import html
from pathlib import Path

from mcp.server.fastmcp import FastMCP


def render_gallery_html(domain: str, shots: list[dict]) -> str:
    """Grid HTML. Each shot: {file, note}. img src is ../screenshots/<file>."""
    e = html.escape
    if not shots:
        cards = '<p class="muted">No screenshots captured yet.</p>'
    else:
        cards = "".join(
            f'<figure class="card">'
            f'<a href="../screenshots/{e(s["file"])}" target="_blank" rel="noopener">'
            f'<img src="../screenshots/{e(s["file"])}" loading="lazy" alt="{e(s.get("note", ""))}"></a>'
            f'<figcaption><b>{e(s["file"])}</b>'
            f'{("<br>" + e(s["note"])) if s.get("note") else ""}</figcaption>'
            f"</figure>"
            for s in shots
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Screenshots — {e(domain)}</title>
<style>
:root{{color-scheme:light dark;--bg:#0b0b0e;--card:#17171c;--fg:#e7e7ea;--muted:#8b8b93;--line:#2a2a31}}
body{{margin:0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}}
.wrap{{max-width:1200px;margin:0 auto;padding:24px}}
h1{{font-size:20px;margin:0 0 16px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px}}
.card{{margin:0;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}}
.card img{{width:100%;height:180px;object-fit:cover;object-position:top;display:block;background:#000}}
figcaption{{padding:8px 10px;font-size:12px;color:var(--muted);word-break:break-all}}
.muted{{color:var(--muted)}}
</style></head>
<body><div class="wrap">
<h1>Screenshots — {e(domain)} ({len(shots)})</h1>
<div class="grid">{cards}</div>
</div></body></html>"""


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def screenshot_gallery(domain: str) -> dict:
        """Build an offline HTML contact sheet of a domain's screenshots.

        Scans .burp-intel/<domain>/screenshots/*.png and writes
        reports/gallery.html — a visual-triage grid to spot login/admin/staging
        panels at a glance. Returns {path, count}.
        """
        shots_dir = Path(".burp-intel") / domain / "screenshots"
        shots = [
            {"file": p.name, "note": ""}
            for p in sorted(shots_dir.glob("*.png"))
        ] if shots_dir.is_dir() else []

        out = Path(".burp-intel") / domain / "reports" / "gallery.html"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_gallery_html(domain, shots), encoding="utf-8")
        return {"path": str(out), "count": len(shots)}
