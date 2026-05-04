"""check_target_freshness — re-fingerprint pages and report drift."""

import hashlib
import json
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

from ._internals import _atomic_write_json, _intel_path, _knowledge_version


def register(mcp: FastMCP):

    @mcp.tool()
    async def check_target_freshness(
        domain: str,
        session: str,
    ) -> str:
        """Re-fingerprint key pages and report what changed since last check.

        Args:
            domain: Target domain
            session: Session name to use for requests
        """
        dir_path = _intel_path(domain)
        fp_path = dir_path / "fingerprint.json"

        if not fp_path.exists():
            return "No fingerprint data stored for this target. Save fingerprint intel first."

        fp_data = json.loads(fp_path.read_text())
        pages = fp_data.get("pages", [])
        if not pages:
            return "Fingerprint file has no pages to check."

        changes = []
        fresh = []
        errors = []

        for page in pages:
            path = page.get("path", "/")
            old_hash = page.get("response_hash", "")
            old_length = page.get("response_length", 0)

            resp = await client.post("/api/session/request", json={
                "session": session,
                "method": "GET",
                "path": path,
            })

            if "error" in resp:
                errors.append(f"  {path}: {resp['error']}")
                continue

            body = resp.get("response_body", "")
            new_hash = "sha256:" + hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]
            new_length = resp.get("response_length", len(body))

            page["response_hash"] = new_hash
            page["response_length"] = new_length
            page["status"] = resp.get("status", 0)
            page["checked_at"] = datetime.now(timezone.utc).isoformat()

            if old_hash and new_hash != old_hash:
                if old_length <= 0:
                    if new_length < 200:
                        fresh.append(f"  {path}: changed (no prior length, new={new_length}B)")
                    else:
                        changes.append(f"  {path}: CHANGED (no prior length, new={new_length}B)")
                else:
                    length_diff = abs(new_length - old_length) / old_length
                    if length_diff < 0.05:
                        fresh.append(f"  {path}: hash changed but length similar (~{length_diff:.0%} diff)")
                    else:
                        changes.append(f"  {path}: CHANGED (length {old_length}→{new_length})")
            else:
                fresh.append(f"  {path}: fresh")

        _atomic_write_json(fp_path, fp_data)

        kv_report = ""
        cov_path = dir_path / "coverage.json"
        if cov_path.exists():
            cov = json.loads(cov_path.read_text())
            stored_kv = cov.get("knowledge_version", "")
            current_kv = _knowledge_version()
            if stored_kv and stored_kv != current_kv:
                kv_report = f"\nKnowledge base: UPDATED (v{stored_kv} → v{current_kv}) — consider re-probing"
            elif stored_kv:
                kv_report = f"\nKnowledge base: current (v{current_kv})"

        lines = [f"Freshness report for {domain}:"]
        if changes:
            lines.append(f"\nChanged ({len(changes)}):")
            lines.extend(changes)
        if fresh:
            lines.append(f"\nFresh ({len(fresh)}):")
            lines.extend(fresh)
        if errors:
            lines.append(f"\nErrors ({len(errors)}):")
            lines.extend(errors)
        if kv_report:
            lines.append(kv_report)
        if not changes and not errors:
            lines.append("\nAll pages unchanged — intel is fresh.")

        return "\n".join(lines)
