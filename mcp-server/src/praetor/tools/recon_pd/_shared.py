"""ProjectDiscovery recon suite + graphw00f bridge.

Thin wrappers around OSS binaries. Each tool returns 'not installed'
diagnostics with install hint when the binary is absent; otherwise emits
parsed summary.

Tools:
    run_dnsx       DNS resolver / bruteforcer (PD)
    run_naabu      SYN/CONNECT port scanner (PD)
    run_tlsx       TLS metadata grab (PD)
    run_asnmap     ASN -> CIDR expansion (PD)
    run_uncover    Shodan/Censys/Fofa/Quake/Hunter wrapper (PD)
    run_cloudlist  Cloud asset inventory (PD)
    run_notify     Slack/Discord/Teams notifier (PD)
    run_mapcves    CVE -> exploit / nuclei template (PD)
    run_cdncheck   CDN / WAF / cloud-IP classifier (PD)
    run_alterx     Subdomain permutation generator (PD)
    run_graphw00f  GraphQL engine fingerprint
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _check_tool, _run_cmd


def _not_installed(tool: str, hint: str) -> str:
    return f"Error: {tool} not installed.\nInstall: {hint}"


def _parse_jsonl(out: str) -> list[dict]:
    rows: list[dict] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows
