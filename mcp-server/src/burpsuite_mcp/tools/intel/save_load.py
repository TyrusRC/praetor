"""save_target_intel + load_target_intel + save_target_notes."""

import json
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

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
    async def save_target_intel(
        domain: str,
        category: str,
        data: dict,
    ) -> str:
        """Save persistent target intelligence for a domain.

        Args:
            domain: Target domain
            category: One of: profile, endpoints, coverage, findings, fingerprint, patterns
            data: Category-specific data dict to save
        """
        if category not in VALID_CATEGORIES:
            return f"Error: invalid category '{category}'. Must be one of: {', '.join(VALID_CATEGORIES)}"

        dir_path = _ensure_dir(domain)
        file_path = dir_path / f"{category}.json"
        now = _utcnow_iso()

        if category == "patterns":
            existing = _empty_structure("patterns")
            if file_path.exists():
                try:
                    existing = json.loads(file_path.read_text())
                except (json.JSONDecodeError, OSError):
                    existing = _empty_structure("patterns")
            patterns_list = existing.get("patterns", [])

            new_patterns = data.get("patterns", [data] if "vuln_class" in data else [])
            for pattern in new_patterns:
                if "timestamp" not in pattern:
                    pattern["timestamp"] = now
                key = (pattern.get("vuln_class"), pattern.get("technique"))
                found = False
                for i, existing_p in enumerate(patterns_list):
                    if (existing_p.get("vuln_class"), existing_p.get("technique")) == key:
                        patterns_list[i] = {**existing_p, **pattern}
                        found = True
                        break
                if not found:
                    patterns_list.append(pattern)

            existing["patterns"] = patterns_list
            existing["last_modified"] = now
            _atomic_write_json(file_path, existing)
            return f"Saved pattern(s) for {domain} ({len(patterns_list)} total patterns)"

        if category == "findings":
            existing = _empty_structure("findings")
            if file_path.exists():
                try:
                    existing = json.loads(file_path.read_text())
                except (json.JSONDecodeError, OSError):
                    existing = _empty_structure("findings")
            findings_list = existing.get("findings", [])

            new_findings = data.get("findings", [data] if "endpoint" in data else [])
            for finding in new_findings:
                if "timestamp" not in finding:
                    finding["timestamp"] = now
                findings_list = _deduplicate_finding(findings_list, finding)

            existing_ids = {f.get("id") for f in findings_list if f.get("id")}
            next_num = max((int(fid[1:]) for fid in existing_ids if fid.startswith("f") and fid[1:].isdigit()), default=0) + 1
            for f in findings_list:
                if not f.get("id"):
                    f["id"] = f"f{next_num:03d}"
                    next_num += 1

            existing["findings"] = findings_list
            existing["last_modified"] = now
            _atomic_write_json(file_path, existing)
            return f"Saved {len(new_findings)} finding(s) for {domain} ({len(findings_list)} total)"

        if category == "coverage":
            existing = _empty_structure("coverage")
            if file_path.exists():
                try:
                    existing = json.loads(file_path.read_text())
                except (json.JSONDecodeError, OSError):
                    existing = _empty_structure("coverage")
            entries = existing.get("entries", [])

            new_entries = data.get("entries", [])
            for new_entry in new_entries:
                key = (new_entry.get("endpoint"), new_entry.get("parameter"))
                found = False
                for i, entry in enumerate(entries):
                    if (entry.get("endpoint"), entry.get("parameter")) == key:
                        entries[i] = {**entry, **new_entry}
                        found = True
                        break
                if not found:
                    entries.append(new_entry)

            existing["entries"] = entries
            existing["knowledge_version"] = _knowledge_version()
            existing["last_modified"] = now
            _atomic_write_json(file_path, existing)
            return f"Coverage updated for {domain}: {len(entries)} entries (knowledge v{existing['knowledge_version']})"

        # profile, endpoints, fingerprint: simple overwrite
        data["last_modified"] = now
        _atomic_write_json(file_path, data)
        return f"Saved {category} for {domain}"

    @mcp.tool()
    async def load_target_intel(
        domain: str,
        category: str = "all",
        limit: int = 0,
        offset: int = 0,
        sort_by: str = "",
        status_filter: str = "",
        chain_with_open: bool = False,
    ) -> str:
        """Load persistent target intelligence for a domain.

        Args:
            domain: Target domain
            category: 'all' for summary, 'notes' for markdown, or a specific category
            limit: For findings/endpoints/coverage — paginate to N entries (0 = all). R24.
            offset: Pagination offset.
            sort_by: For findings — 'severity' (CRITICAL>HIGH>MEDIUM>LOW>INFO) or 'recency' (newest first).
            status_filter: For findings — comma-separated statuses to keep (e.g. 'confirmed,suspected'). Empty = all.
            chain_with_open: For findings — only return findings whose status is suspected/confirmed (chain-relevant).
        """
        dir_path = _intel_path(domain)

        if category == "notes":
            notes_path = dir_path / "notes.md"
            if notes_path.exists():
                return notes_path.read_text()
            return "No notes saved for this target."

        if category == "all":
            summary_lines = [f"Target intel for {domain}:"]
            for cat in VALID_CATEGORIES:
                cat_path = dir_path / f"{cat}.json"
                if not cat_path.exists():
                    summary_lines.append(f"  {cat}: (none)")
                    continue
                try:
                    data = json.loads(cat_path.read_text())
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
            return json.dumps(_empty_structure(category), indent=2)

        data = json.loads(cat_path.read_text())
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
            data["findings"] = findings
        elif category in ("endpoints", "coverage") and limit > 0:
            key = "endpoints" if category == "endpoints" else "entries"
            items = data.get(key, []) or []
            data["_meta"]["filtered_count"] = len(items)
            data[key] = items[offset:offset + limit]
            data["_meta"]["offset"] = offset
            data["_meta"]["limit"] = limit

        return json.dumps(data, indent=2, default=str)

    @mcp.tool()
    async def save_target_notes(
        domain: str,
        notes: str,
    ) -> str:
        """Save freeform markdown notes for a target.

        Args:
            domain: Target domain
            notes: Markdown text to save (overwrites existing)
        """
        dir_path = _ensure_dir(domain)
        notes_path = dir_path / "notes.md"
        notes_path.write_text(notes)
        return f"Notes saved for {domain} ({len(notes)} chars)"
