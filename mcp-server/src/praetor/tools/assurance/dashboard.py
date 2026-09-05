"""generate_posture_dashboard — self-contained offline HTML posture view.

Assembles severity mix + standards heatmap + trend + top findings into a
single HTML file with inline CSS and NO external references (CSP-safe,
air-gap-safe, publishable as an Artifact). Written under
.burp-intel/<domain>/reports/dashboard.html.

`render_dashboard_html` is pure (returns the HTML string) for cheap testing;
`generate_posture_dashboard` is the @mcp.tool that gathers data + writes.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from .._vuln_class import canonical
from ..report.lifecycle import load_intel
from ._standards import STANDARDS
from .coverage_map import build_heatmap, _tested_classes

_SEV_COLOR = {
    "critical": "#7c1d1d",
    "high": "#b91c1c",
    "medium": "#c2610c",
    "low": "#4d7c0f",
}
_STATUS_COLOR = {
    "findings": "#b91c1c",
    "tested": "#4d7c0f",
    "untested": "#3f3f46",
}


def render_dashboard_html(
    domain: str,
    severity_counts: dict[str, int],
    heatmap: dict[str, Any],
    trend: list[dict],
    top_findings: list[dict],
) -> str:
    """Build the offline dashboard HTML. No external URLs, no src= attributes."""
    e = html.escape
    total = sum(severity_counts.get(s, 0) for s in _SEV_COLOR)

    sev_cells = "".join(
        f'<div class="sev"><span class="dot" style="background:{_SEV_COLOR[s]}"></span>'
        f'<b>{severity_counts.get(s, 0)}</b> {s.title()}</div>'
        for s in ("critical", "high", "medium", "low")
    )

    cats = heatmap.get("categories", {})
    cat_rows = "".join(
        f'<tr><td class="cid">{e(cid)}</td><td>{e(row.get("name", ""))}</td>'
        f'<td><span class="pill" style="background:{_STATUS_COLOR.get(row.get("status", "untested"), "#3f3f46")}">'
        f'{e(row.get("status", "untested"))}</span></td>'
        f'<td class="num">{row.get("findings", 0)}</td>'
        f'<td class="num">{row.get("tested", 0)}</td></tr>'
        for cid, row in cats.items()
    )

    trend_rows = "".join(
        f'<tr><td>{e(str(t.get("when", "")))}</td><td class="num">{e(str(t.get("total", "")))}</td>'
        f'<td class="num">{e(str(t.get("delta", "")))}</td></tr>'
        for t in trend
    ) or '<tr><td colspan="3" class="muted">no snapshots yet</td></tr>'

    top_rows = "".join(
        f'<tr><td><span class="pill" style="background:{_SEV_COLOR.get(str(f.get("severity", "")).lower(), "#3f3f46")}">'
        f'{e(str(f.get("severity", "")))}</span></td>'
        f'<td>{e(str(f.get("title", "")))}</td><td>{e(str(f.get("endpoint", "")))}</td></tr>'
        for f in top_findings
    ) or '<tr><td colspan="3" class="muted">no confirmed findings</td></tr>'

    cov = heatmap.get("coverage_pct", 0)
    std_name = heatmap.get("standard_name", heatmap.get("standard", ""))

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Posture — {e(domain)}</title>
<style>
:root{{color-scheme:light dark;--bg:#0b0b0e;--card:#17171c;--fg:#e7e7ea;--muted:#8b8b93;--line:#2a2a31}}
*{{box-sizing:border-box}}
body{{margin:0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}}
.wrap{{max-width:960px;margin:0 auto;padding:24px}}
h1{{font-size:20px;margin:0 0 4px}}.sub{{color:var(--muted);margin:0 0 20px}}
.grid{{display:grid;gap:16px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}}
.card h2{{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:0 0 12px}}
.sevrow{{display:flex;flex-wrap:wrap;gap:20px}}
.sev{{display:flex;align-items:center;gap:8px;font-size:15px}}
.dot{{width:12px;height:12px;border-radius:50%;display:inline-block}}
.gauge{{font-size:34px;font-weight:700}}
table{{width:100%;border-collapse:collapse}}
td,th{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--muted);font-weight:600;font-size:12px}}
.num{{text-align:right;font-variant-numeric:tabular-nums}}
.cid{{font-weight:600;white-space:nowrap}}
.pill{{color:#fff;padding:1px 8px;border-radius:20px;font-size:12px;white-space:nowrap}}
.muted{{color:var(--muted)}}
.overflow{{overflow-x:auto}}
</style></head>
<body><div class="wrap">
<h1>Security Posture — {e(domain)}</h1>
<p class="sub">{total} confirmed finding(s) · {e(str(std_name))} coverage {cov}%</p>
<div class="grid">
  <div class="card"><h2>Severity</h2><div class="sevrow">{sev_cells}</div></div>
  <div class="card"><h2>Coverage — {e(str(std_name))} ({cov}%)</h2>
    <div class="overflow"><table>
      <tr><th>ID</th><th>Category</th><th>Status</th><th class="num">Findings</th><th class="num">Tested</th></tr>
      {cat_rows}
    </table></div></div>
  <div class="card"><h2>Trend</h2><div class="overflow"><table>
      <tr><th>When</th><th class="num">Total</th><th class="num">Δ</th></tr>{trend_rows}
    </table></div></div>
  <div class="card"><h2>Top findings</h2><div class="overflow"><table>
      <tr><th>Severity</th><th>Title</th><th>Endpoint</th></tr>{top_rows}
    </table></div></div>
</div></div></body></html>"""


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def generate_posture_dashboard(
        domain: str, standard: str = "owasp_top10"
    ) -> dict:
        """Write a self-contained offline HTML security-posture dashboard.

        Severity mix + standards-coverage heatmap + snapshot trend + top
        findings. No external references — publishable as an Artifact.

        Returns: {path, coverage_pct, total_findings}.
        """
        if standard not in STANDARDS:
            return {"error": f"unknown standard '{standard}'", "valid": sorted(STANDARDS)}

        findings = [
            f
            for f in load_intel(domain, "findings").get("findings", [])
            if f.get("status") == "confirmed"
        ]
        sev_counts: dict[str, int] = {}
        for f in findings:
            s = str(f.get("severity", "")).lower()
            if s in _SEV_ORDER:
                sev_counts[s] = sev_counts.get(s, 0) + 1

        heatmap = build_heatmap(standard, _tested_classes(domain), findings)

        top = sorted(
            findings, key=lambda f: _SEV_ORDER.get(str(f.get("severity", "")).lower(), 9)
        )[:10]

        trend: list[dict] = []
        snaps = load_intel(domain, "findings").get("_snapshots", [])
        if isinstance(snaps, list):
            trend = snaps[-10:]

        html_str = render_dashboard_html(domain, sev_counts, heatmap, trend, top)

        out = Path(".burp-intel") / domain / "reports" / "dashboard.html"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(html_str, encoding="utf-8")
        return {
            "path": str(out),
            "coverage_pct": heatmap["coverage_pct"],
            "total_findings": len(findings),
        }
