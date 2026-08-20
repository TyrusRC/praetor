"""hydrate_burp_findings — restore the Burp Findings tab from the store."""

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor import client

from .._helpers import _intel_dir, _safe_findings_path


def register(mcp: FastMCP):
    @mcp.tool()
    async def hydrate_burp_findings(domain: str = "all", include_suspected: bool = False) -> str:
        """Re-populate Burp's in-memory Findings tab from persisted .burp-intel findings. Use after extension reload.

        Args:
            domain: Specific domain to hydrate, or 'all' for every .burp-intel domain
            include_suspected: If True, also restore suspected/stale findings (default: confirmed-only)
        """
        targets: list[Path] = []
        intel_root = _intel_dir()
        if domain == "all":
            if intel_root.exists():
                for d in sorted(intel_root.iterdir()):
                    if d.is_dir() and (d / "findings.json").exists():
                        targets.append(d / "findings.json")
        else:
            p = _safe_findings_path(domain)
            if p.exists():
                targets.append(p)

        if not targets:
            return f"No findings.json found for {domain!r} under .burp-intel/. Nothing to hydrate."

        allowed_statuses = {"confirmed"}
        if include_suspected:
            allowed_statuses |= {"suspected", "stale"}

        restored = 0
        skipped_status = 0
        skipped_gate = 0
        skipped_dup = 0
        gate_errors: list[str] = []

        for path in targets:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            findings = data.get("findings", [])

            for f in findings:
                status = f.get("status", "suspected")
                if status not in allowed_statuses:
                    skipped_status += 1
                    continue

                payload = {
                    "title": f.get("title", ""),
                    "description": f.get("description", ""),
                    "severity": f.get("severity", "INFO"),
                    "endpoint": f.get("endpoint", ""),
                    "evidence_text": f.get("evidence_text", ""),
                    "evidence": f.get("evidence", {}),
                    "vuln_type": f.get("vuln_type", ""),
                    "status": status,
                }
                if f.get("reproductions"):
                    payload["reproductions"] = f["reproductions"]
                if f.get("chain_with"):
                    payload["chain_with"] = f["chain_with"]

                resp = await client.post("/api/notes/findings", json=payload)
                if "error" in resp:
                    err = resp["error"]
                    if "duplicate" in err.lower() or "already" in err.lower():
                        skipped_dup += 1
                    else:
                        skipped_gate += 1
                        if len(gate_errors) < 5:
                            fid = f.get("id", "?")
                            gate_errors.append(f"  {fid} ({f.get('title','')[:40]}): {err[:120]}")
                    continue
                restored += 1

        lines = [
            f"Hydrated Burp Findings tab from {len(targets)} domain(s).",
            f"  Restored:        {restored}",
            f"  Skipped (status not in {sorted(allowed_statuses)}): {skipped_status}",
            f"  Skipped (already in Burp memory):                   {skipped_dup}",
            f"  Skipped (gate rejection — evidence index stale):    {skipped_gate}",
        ]
        if gate_errors:
            lines.append("")
            lines.append("First gate rejections (evidence indices likely no longer resolve):")
            lines.extend(gate_errors)
            lines.append("")
            lines.append("Persistent .burp-intel store unchanged. Re-capture the underlying")
            lines.append("requests via search_history / browser_crawl to make these visible.")

        return "\n".join(lines)
