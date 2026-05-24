"""findings_diff — scan-vs-scan delta over .burp-intel/<domain>/findings.json snapshots.

Compares two snapshots and emits NEW (regression candidates), RESOLVED
(fixes), and PERSISTING sets. Snapshots are zero-cost: tool auto-archives
on read into .burp-intel/<domain>/_snapshots/findings-<iso>.json so the
operator can diff any two timestamps.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.notes._helpers import _load_findings_file, _safe_findings_path


def _snapshot_dir(domain: str) -> Path:
    d = _safe_findings_path(domain).parent / "_snapshots"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _archive_current(domain: str) -> Path | None:
    src = _safe_findings_path(domain)
    if not src.exists():
        return None
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = _snapshot_dir(domain) / f"findings-{ts}.json"
    target.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def _list_snapshots(domain: str) -> list[Path]:
    d = _snapshot_dir(domain)
    return sorted(d.glob("findings-*.json"))


def _findings_list(raw) -> list[dict]:
    """_load_findings_file returns dict or list depending on schema; normalise."""
    if isinstance(raw, dict):
        return raw.get("findings", []) or []
    if isinstance(raw, list):
        return raw
    return []


def _index_by_dedup_key(findings: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for f in findings:
        key = "|".join(str(f.get(k) or "") for k in ("endpoint", "vuln_type", "parameter", "title"))
        out[key] = f
    return out


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def findings_diff(
        domain: str,
        baseline: str = "",
        current: str = "",
        archive_now: bool = True,
    ) -> str:
        """Emit new / resolved / persisting delta between two findings snapshots.

        Args:
            domain: target domain (slug).
            baseline: ISO snapshot timestamp (or 'previous' for second-most-recent).
                Defaults to second-most-recent.
            current: ISO snapshot timestamp (or 'live' for live findings.json).
                Defaults to live.
            archive_now: archive live findings.json into _snapshots/ first
                (so 'live' becomes a permanent snapshot). Default True.
        """
        if archive_now:
            _archive_current(domain)

        snaps = _list_snapshots(domain)
        if not snaps and current != "live":
            return f"No snapshots in .burp-intel/{domain}/_snapshots/."

        def _resolve(key: str, default_idx: int) -> tuple[str, list[dict]]:
            if key in ("live", "", "current"):
                p = _safe_findings_path(domain)
                if not p.exists():
                    return ("live(empty)", [])
                return ("live", _findings_list(_load_findings_file(p)))
            if key == "previous":
                if len(snaps) < 2:
                    return ("previous(unavailable)", [])
                p = snaps[-2]
                return (p.stem.replace("findings-", ""), _findings_list(_load_findings_file(p)))
            for p in snaps:
                if key in p.name:
                    return (p.stem.replace("findings-", ""), _findings_list(_load_findings_file(p)))
            if 0 <= default_idx < len(snaps):
                p = snaps[default_idx]
                return (p.stem.replace("findings-", ""), _findings_list(_load_findings_file(p)))
            return (f"{key}(missing)", [])

        base_label, base_list = _resolve(baseline or "previous", default_idx=-2 if len(snaps) >= 2 else 0)
        cur_label, cur_list = _resolve(current or "live", default_idx=-1)

        base_idx = _index_by_dedup_key(base_list)
        cur_idx = _index_by_dedup_key(cur_list)

        new = [cur_idx[k] for k in cur_idx if k not in base_idx]
        resolved = [base_idx[k] for k in base_idx if k not in cur_idx]
        persisting = [cur_idx[k] for k in cur_idx if k in base_idx]

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        new.sort(key=lambda f: sev_order.get((f.get("severity") or "INFO").upper(), 9))
        resolved.sort(key=lambda f: sev_order.get((f.get("severity") or "INFO").upper(), 9))

        lines = [
            f"# findings_diff — {domain}",
            f"Baseline: {base_label}  ({len(base_list)} findings)",
            f"Current:  {cur_label}   ({len(cur_list)} findings)",
            "",
            f"NEW (regressions): {len(new)}",
        ]
        for f in new[:25]:
            lines.append(
                f"  + [{(f.get('severity') or 'INFO').upper():<8}] {f.get('vuln_type','?')} "
                f"@ {f.get('endpoint','')}  ({f.get('id','')})"
            )
        lines.append("")
        lines.append(f"RESOLVED: {len(resolved)}")
        for f in resolved[:25]:
            lines.append(
                f"  - [{(f.get('severity') or 'INFO').upper():<8}] {f.get('vuln_type','?')} "
                f"@ {f.get('endpoint','')}  ({f.get('id','')})"
            )
        lines.append("")
        lines.append(f"PERSISTING: {len(persisting)}")
        return "\n".join(lines)

    @mcp.tool()
    async def list_findings_snapshots(domain: str) -> str:
        """List archived findings snapshots for a domain."""
        snaps = _list_snapshots(domain)
        if not snaps:
            return f"No snapshots in .burp-intel/{domain}/_snapshots/."
        lines = [f"Snapshots for {domain}:"]
        for p in snaps:
            data = _findings_list(_load_findings_file(p))
            ts = p.stem.replace("findings-", "")
            lines.append(f"  {ts}  ({len(data)} findings)")
        return "\n".join(lines)

    @mcp.tool()
    async def archive_findings_snapshot(domain: str) -> str:
        """Archive current findings.json into _snapshots/findings-<iso>.json."""
        p = _archive_current(domain)
        if p is None:
            return f"No findings.json in .burp-intel/{domain}/ to archive."
        return f"Archived: {p}"
