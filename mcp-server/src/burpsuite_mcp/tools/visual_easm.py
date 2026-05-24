"""Visual EASM diff — gowitness screenshot + per-host hash delta.

Captures screenshot per host, hashes the PNG, diffs vs prior snapshot.
Visual regression for EASM monitoring.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.notes._helpers import _intel_dir
from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd


def _hint() -> str:
    return ("Error: gowitness not installed.\n"
            "Install: go install github.com/sensepost/gowitness@latest  |  "
            "https://github.com/sensepost/gowitness")


def _hash_png(path: pathlib.Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except OSError:
        return ""


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def visual_easm_diff(
        domain: str,
        hosts: list[str],
        timeout: int = 600,
    ) -> str:
        """Screenshot each host via gowitness; diff hashes vs prior snapshot.

        Args:
            domain: target apex domain (for intel-dir scoping).
            hosts: list of host URLs to capture.
            timeout: seconds.
        """
        if not _check_tool("gowitness"):
            return _hint()
        if not hosts:
            return "visual_easm_diff: no hosts."

        snap_dir = _intel_dir(domain) / "_visual"
        snap_dir.mkdir(parents=True, exist_ok=True)
        prior_path = snap_dir / "hashes.json"
        prior: dict[str, str] = {}
        if prior_path.exists():
            try:
                prior = json.loads(prior_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass

        listfile = snap_dir / "hosts.txt"
        listfile.write_text("\n".join(hosts) + "\n", encoding="utf-8")
        _, err, rc = await _run_cmd(
            ["gowitness", "scan", "file", "-f", str(listfile),
             "--screenshot-path", str(snap_dir)],
            timeout=timeout, bypass_proxy=True,
        )

        current: dict[str, str] = {}
        for p in snap_dir.glob("*.png"):
            current[p.stem] = _hash_png(p)

        added = sorted(set(current) - set(prior))
        removed = sorted(set(prior) - set(current))
        changed = sorted(
            host for host in (set(prior) & set(current))
            if prior[host] != current[host]
        )

        prior_path.write_text(json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            "hashes": current,
        }, indent=2), encoding="utf-8")

        lines = [
            f"visual_easm_diff [{domain}]: {len(current)} hosts captured",
            f"  added:   {len(added)}",
            f"  removed: {len(removed)}",
            f"  changed: {len(changed)}",
        ]
        for h in changed[:30]:
            lines.append(f"  ~ {h}  ({prior[h]} -> {current[h]})")
        for h in added[:20]:
            lines.append(f"  + {h}  ({current[h]})")
        for h in removed[:20]:
            lines.append(f"  - {h}")
        if rc != 0 and not current:
            lines.append(f"[rc={rc}] {err[:200]}")
        lines.append(f"Snapshots dir: {snap_dir}")
        return "\n".join(lines)
