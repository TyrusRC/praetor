"""load_target_intel"""

import json
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from praetor.tools.workspace import ensure_workspace
from ._internals import (
    VALID_CATEGORIES,
    _atomic_write_json,
    _deduplicate_finding,
    _empty_structure,
    _ensure_dir,
    _intel_path,
    _knowledge_version,
    _utcnow_iso,
)


def register(mcp: FastMCP):
    @mcp.tool()
    async def load_target_intel(
        domain: str,
        category: str = "all",
        limit: int = 0,
        offset: int = 0,
        sort_by: str = "",
        status_filter: str = "",
        chain_with_open: bool = False,
        fields: str = "",
    ) -> str:
        """Load persistent target intelligence for a domain.

        Args:
            domain: Target domain
            category: 'all' for summary, 'notes' for markdown, or a specific category
            fields: For findings — comma-separated whitelist to project each finding
                to (e.g. 'id,title,severity,status,endpoint,vuln_type'). Empty = full
                objects. Token-lean session-start recall (Spec E1.1); the heavy
                poc_request/evidence/reproductions/description fields are dropped
                unless named.
            limit: For findings/endpoints/coverage — paginate to N entries (0 = all). R24.
            offset: Pagination offset.
            sort_by: For findings — 'severity' (CRITICAL>HIGH>MEDIUM>LOW>INFO) or 'recency' (newest first).
            status_filter: For findings — comma-separated statuses to keep (e.g. 'confirmed,suspected'). Empty = all.
            chain_with_open: For findings — only return findings whose status is suspected/confirmed (chain-relevant).
        """
        dir_path = _intel_path(domain)
        try:
            ensure_workspace(domain)  # Spec 1: scaffold the engagement tree on the intel gate
        except ValueError:
            pass

        if category == "notes":
            notes_path = dir_path / "notes.md"
            if notes_path.exists():
                return notes_path.read_text(encoding="utf-8")
            return "No notes saved for this target."

        if category == "all":
            summary_lines = [f"Target intel for {domain}:"]
            for cat in VALID_CATEGORIES:
                cat_path = dir_path / f"{cat}.json"
                if not cat_path.exists():
                    summary_lines.append(f"  {cat}: (none)")
                    continue
                try:
                    data = json.loads(cat_path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    summary_lines.append(f"  {cat}: (corrupted)")
                    continue
                if cat == "profile":
                    tech = data.get("tech_stack", [])
                    summary_lines.append(f"  profile: tech={', '.join(tech) if tech else 'unknown'}")
                elif cat == "endpoints":
                    endpoints = data.get("endpoints", [])
                    summary_lines.append(f"  endpoints: {len(endpoints)} discovered")
                elif cat == "coverage":
                    entries = data.get("entries", [])
                    kv = data.get("knowledge_version", "?")
                    summary_lines.append(f"  coverage: {len(entries)} entries (knowledge v{kv})")
                elif cat == "findings":
                    findings = data.get("findings", [])
                    by_status: dict[str, int] = {}
                    for f in findings:
                        status = f.get("status", "open")
                        by_status[status] = by_status.get(status, 0) + 1
                    status_str = ", ".join(f"{k}={v}" for k, v in by_status.items())
                    summary_lines.append(f"  findings: {len(findings)} total ({status_str or 'none'})")
                elif cat == "fingerprint":
                    pages = data.get("pages", [])
                    summary_lines.append(f"  fingerprint: {len(pages)} pages tracked")
                elif cat == "patterns":
                    patterns = data.get("patterns", [])
                    summary_lines.append(f"  patterns: {len(patterns)} learned techniques")

            notes_path = dir_path / "notes.md"
            if notes_path.exists():
                summary_lines.append("  notes: saved")
            return "\n".join(summary_lines)

        if category not in VALID_CATEGORIES:
            return f"Error: invalid category '{category}'. Must be one of: all, notes, {', '.join(VALID_CATEGORIES)}"

        cat_path = dir_path / f"{category}.json"
        if not cat_path.exists():
            return json.dumps(_empty_structure(category), separators=(",", ":"))

        data = json.loads(cat_path.read_text(encoding="utf-8"))
        stat = cat_path.stat()
        if "_meta" not in data:
            data["_meta"] = {}
        data["_meta"]["last_modified"] = datetime.fromtimestamp(
            stat.st_mtime, tz=timezone.utc
        ).isoformat()

        # ── R24: filter + sort + paginate findings/endpoints/coverage ──
        if category == "findings":
            findings = data.get("findings", []) or []
            if chain_with_open:
                findings = [f for f in findings if f.get("status", "") in ("suspected", "confirmed")]
            if status_filter:
                allowed = {s.strip() for s in status_filter.split(",") if s.strip()}
                findings = [f for f in findings if f.get("status", "") in allowed]
            if sort_by == "severity":
                sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
                findings.sort(key=lambda f: sev_order.get(str(f.get("severity", "INFO")).upper(), 5))
            elif sort_by == "recency":
                findings.sort(
                    key=lambda f: str(f.get("last_updated") or f.get("created") or ""),
                    reverse=True,
                )
            data["_meta"]["filtered_count"] = len(findings)
            if limit > 0:
                findings = findings[offset:offset + limit]
                data["_meta"]["offset"] = offset
                data["_meta"]["limit"] = limit
            if fields:
                keep = [f.strip() for f in fields.split(",") if f.strip()]
                findings = [{k: f.get(k) for k in keep if k in f} for f in findings]
                data["_meta"]["projected_fields"] = keep
            data["findings"] = findings
        elif category in ("endpoints", "coverage") and limit > 0:
            key = "endpoints" if category == "endpoints" else "entries"
            items = data.get(key, []) or []
            data["_meta"]["filtered_count"] = len(items)
            data[key] = items[offset:offset + limit]
            data["_meta"]["offset"] = offset
            data["_meta"]["limit"] = limit

        # Token-lean (Spec E1.3): compact separators — this is machine-consumed
        # (Rule 20a runs it every session); no human reads the indentation.
        return json.dumps(data, separators=(",", ":"), default=str)

