"""save_target_intel + save_target_notes"""

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
        try:
            ensure_workspace(domain)  # Spec 1: scaffold the engagement tree on the intel gate
        except ValueError:
            pass  # invalid domain handled by downstream path guards
        file_path = dir_path / f"{category}.json"
        now = _utcnow_iso()

        if category == "patterns":
            existing = _empty_structure("patterns")
            if file_path.exists():
                try:
                    existing = json.loads(file_path.read_text(encoding="utf-8"))
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
                    existing = json.loads(file_path.read_text(encoding="utf-8"))
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
                    existing = json.loads(file_path.read_text(encoding="utf-8"))
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
        notes_path.write_text(notes, encoding="utf-8")
        return f"Notes saved for {domain} ({len(notes)} chars)"

