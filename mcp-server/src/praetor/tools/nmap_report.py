"""nmap_report_html — render an nmap scan into an offline HTML exposure report.

The network lane already parses nmap XML into a host/service inventory
(network/_nmap_parse) and get_network_inventory returns it as data. This is the
shareable deliverable: a single self-contained HTML page (inline CSS, no
external refs) summarising hosts, open ports, service/versions, and flagging
non-standard ports — the "low-hanging-fruit at a glance" view. Mirrors the
posture dashboard for the network lane.

`render_nmap_html` is pure; `nmap_report_html` reads the XML + writes.
"""

from __future__ import annotations

import html
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .network._nmap_parse import parse_nmap_xml

# Ports common enough that their presence is unremarkable; anything else on an
# open host is worth a manual look (coffinxp: "vulns hide on non-standard ports").
_COMMON = {21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443}


def render_nmap_html(inventory: dict) -> str:
    """Offline HTML report from a parse_nmap_xml inventory. No external refs."""
    e = html.escape
    hosts = inventory.get("hosts", []) or []
    total_ports = sum(len(h.get("ports", [])) for h in hosts)

    if not hosts:
        rows = '<tr><td colspan="6" class="muted">No hosts up / no open ports.</td></tr>'
    else:
        cells = []
        for h in hosts:
            ip = e(h.get("ip", ""))
            names = e(", ".join(h.get("hostnames", []) or []))
            for p in h.get("ports", []):
                port = p.get("port", "")
                nonstd = port not in _COMMON
                flag = '<span class="pill">non-standard</span>' if nonstd else ""
                svc = e(p.get("service", ""))
                if p.get("tunnel") == "ssl" and "http" in svc:
                    svc += " (tls)"
                prodver = e(" ".join(x for x in (p.get("product", ""), p.get("version", "")) if x))
                cells.append(
                    f'<tr class="{"warn" if nonstd else ""}">'
                    f'<td>{ip}</td><td>{names}</td>'
                    f'<td class="port">{e(str(port))}/{e(p.get("proto", ""))} {flag}</td>'
                    f'<td>{svc}</td><td>{prodver}</td>'
                    f'<td>{e(p.get("state", ""))}</td></tr>'
                )
        rows = "".join(cells)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network exposure — {len(hosts)} host(s)</title>
<style>
:root{{color-scheme:light dark;--bg:#0b0b0e;--card:#17171c;--fg:#e7e7ea;--muted:#8b8b93;--line:#2a2a31;--warn:#c2610c}}
body{{margin:0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}}
.wrap{{max-width:1100px;margin:0 auto;padding:24px}}
h1{{font-size:20px;margin:0 0 4px}}.sub{{color:var(--muted);margin:0 0 18px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}}
.overflow{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse}}
td,th{{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--muted);font-weight:600;font-size:12px}}
.port{{white-space:nowrap;font-variant-numeric:tabular-nums}}
tr.warn td{{background:rgba(194,97,12,.08)}}
.pill{{background:var(--warn);color:#fff;padding:1px 7px;border-radius:20px;font-size:11px;margin-left:6px}}
.muted{{color:var(--muted)}}
</style></head>
<body><div class="wrap">
<h1>Network Exposure Report</h1>
<p class="sub">{len(hosts)} host(s) up · {total_ports} open port(s) · non-standard ports flagged</p>
<div class="card"><div class="overflow"><table>
<tr><th>Host</th><th>Hostnames</th><th>Port</th><th>Service</th><th>Product / Version</th><th>State</th></tr>
{rows}
</table></div></div>
</div></body></html>"""


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def nmap_report_html(xml_path: str, out_path: str = "") -> dict:
        """Render an nmap -oX XML file into an offline HTML exposure report.

        Summarises hosts / open ports / service-versions and flags non-standard
        ports. Self-contained (no external refs). Writes next to the XML (or
        out_path) and returns {path, hosts, open_ports}.
        """
        p = Path(xml_path)
        try:
            xml_text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as ex:
            return {"error": f"cannot read '{xml_path}': {ex}"}
        try:
            inv = parse_nmap_xml(xml_text)
        except ValueError as ex:
            return {"error": str(ex)}

        out = Path(out_path) if out_path else p.with_suffix(".report.html")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_nmap_html(inv), encoding="utf-8")
        hosts = inv.get("hosts", [])
        return {
            "path": str(out),
            "hosts": len(hosts),
            "open_ports": sum(len(h.get("ports", [])) for h in hosts),
        }
