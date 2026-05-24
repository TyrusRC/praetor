"""easm_monitor_loop — one-call EASM sweep with delta vs prior run.

Pipeline:
    subfinder -> httpx (live hosts) -> takeover scan -> persist
    -> diff vs prior snapshot at .burp-intel/<domain>/easm.json

Tools (subfinder, httpx) optional — gracefully skipped if absent.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.notes._helpers import _intel_dir
from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd


async def _subfinder(domain: str, timeout: int) -> list[str]:
    if not _check_tool("subfinder"):
        return []
    out, _, _ = await _run_cmd(
        ["subfinder", "-d", domain, "-silent", "-all"], timeout=timeout, bypass_proxy=True,
    )
    return sorted({line.strip() for line in out.splitlines() if line.strip()})


async def _httpx(hosts: list[str], timeout: int) -> list[dict]:
    if not hosts or not _check_tool("httpx"):
        return [{"host": h, "alive": None} for h in hosts]
    import shlex, tempfile, pathlib
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        for h in hosts:
            fh.write(h + "\n")
        listfile = fh.name
    try:
        out, _, _ = await _run_cmd(
            ["httpx", "-l", listfile, "-silent", "-json", "-status-code", "-title", "-tech-detect"],
            timeout=timeout,
            bypass_proxy=True,
        )
    finally:
        try: pathlib.Path(listfile).unlink()
        except OSError: pass
    rows: list[dict] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            rows.append({
                "host": d.get("input") or d.get("host") or "",
                "url": d.get("url") or "",
                "status_code": d.get("status_code") or d.get("status-code"),
                "title": d.get("title", ""),
                "tech": d.get("tech") or d.get("technologies", []),
                "alive": True,
            })
        except json.JSONDecodeError:
            continue
    return rows


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def easm_monitor_loop(domain: str, timeout: int = 600) -> str:
        """Subfinder + httpx + takeover sweep; persists snapshot + emits delta.

        Args:
            domain: target apex domain (e.g. example.com).
            timeout: per-tool timeout in seconds (default 600).
        """
        snap_dir = _intel_dir(domain)
        snap_dir.mkdir(parents=True, exist_ok=True)
        snap_path = snap_dir / "easm.json"
        prior: dict = {}
        if snap_path.exists():
            try:
                prior = json.loads(snap_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                prior = {}

        subs = await _subfinder(domain, timeout)
        live = await _httpx(subs, timeout) if subs else []

        prior_subs = set(prior.get("subdomains") or [])
        new_subs = sorted(set(subs) - prior_subs)
        gone_subs = sorted(prior_subs - set(subs))

        snapshot = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "subdomains": subs,
            "live": live,
        }
        snap_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")

        lines = [
            f"# easm_monitor_loop — {domain}",
            f"Subdomains: {len(subs)}  (was {len(prior_subs)})",
            f"Live hosts: {sum(1 for r in live if r.get('alive'))}",
            f"NEW subdomains: {len(new_subs)}",
        ]
        for s in new_subs[:30]:
            lines.append(f"  + {s}")
        lines.append(f"REMOVED subdomains: {len(gone_subs)}")
        for s in gone_subs[:20]:
            lines.append(f"  - {s}")
        lines.append("")
        lines.append(f"Snapshot persisted: {snap_path}")
        lines.append("Next: test_subdomain_takeover(subdomains=NEW) on additions.")
        if not subs:
            lines.append("")
            lines.append("Note: subfinder/httpx not detected. Install: go install -v "
                         "github.com/projectdiscovery/{subfinder,httpx}/v2/cmd/...@latest")
        return "\n".join(lines)
