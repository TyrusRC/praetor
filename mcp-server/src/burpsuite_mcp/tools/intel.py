"""Persistent target intelligence storage across Claude Code sessions."""

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

INTEL_DIR = Path.cwd() / ".burp-intel"
KNOWLEDGE_DIR = Path(__file__).parent.parent / "knowledge"

VALID_CATEGORIES = ("profile", "endpoints", "coverage", "findings", "fingerprint", "patterns")


def _intel_path(domain: str) -> Path:
    """Return the intel directory path for a domain, with sanitized name."""
    sanitized = re.sub(r'[^a-zA-Z0-9._-]', '_', domain)
    return INTEL_DIR / sanitized


def _ensure_dir(domain: str) -> Path:
    """Create the intel directory for a domain if needed, return its Path."""
    path = _intel_path(domain)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _atomic_write_json(path: Path, data: dict | list) -> None:
    """Write JSON to a temp file then atomically replace the target (prevents corruption)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _knowledge_version() -> str:
    """SHA256 hash (first 12 chars) of all knowledge/*.json files concatenated."""
    h = hashlib.sha256()
    for p in sorted(KNOWLEDGE_DIR.glob("*.json")):
        h.update(p.read_bytes())
    return h.hexdigest()[:12]


def _empty_structure(category: str) -> dict:
    """Return an empty dict matching the schema for each category."""
    if category == "profile":
        return {"domain": "", "tech_stack": [], "frameworks": [], "notes": ""}
    if category == "endpoints":
        return {"endpoints": []}
    if category == "coverage":
        return {"knowledge_version": "", "entries": []}
    if category == "findings":
        return {"findings": []}
    if category == "fingerprint":
        return {"pages": []}
    if category == "patterns":
        return {"patterns": []}
    return {}


def _deduplicate_finding(existing_list: list[dict], new_finding: dict) -> list[dict]:
    """If same endpoint + vulnerability_type + parameter exists, update it; otherwise append."""
    for i, item in enumerate(existing_list):
        if (
            item.get("endpoint") == new_finding.get("endpoint")
            and item.get("vulnerability_type") == new_finding.get("vulnerability_type")
            and item.get("parameter") == new_finding.get("parameter")
        ):
            existing_list[i] = {**item, **new_finding}
            return existing_list
    existing_list.append(new_finding)
    return existing_list


def register(mcp: FastMCP):

    @mcp.tool()
    async def save_target_intel(
        domain: str,
        category: str,
        data: dict,
    ) -> str:
        """Save persistent target intelligence for a domain.

        Stores structured data across Claude Code sessions so you never lose context
        about a target. Data is saved to .burp-intel/<domain>/<category>.json.

        Args:
            domain: Target domain (e.g. 'example.com', 'api.target.com:8443')
            category: One of: profile, endpoints, coverage, findings, fingerprint
            data: Category-specific data dict to save
        """
        if category not in VALID_CATEGORIES:
            return f"Error: invalid category '{category}'. Must be one of: {', '.join(VALID_CATEGORIES)}"

        dir_path = _ensure_dir(domain)
        file_path = dir_path / f"{category}.json"
        now = datetime.now(timezone.utc).isoformat()

        if category == "patterns":
            # Cross-target pattern learning: append new patterns, deduplicate by key
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
                # Deduplicate by vuln_class + technique
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
            # Load existing, deduplicate, auto-assign IDs, auto-timestamp
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

            # Auto-assign IDs
            for i, f in enumerate(findings_list):
                f["id"] = f"f{i + 1:03d}"

            existing["findings"] = findings_list
            existing["last_modified"] = now
            _atomic_write_json(file_path, existing)
            return f"Saved {len(new_findings)} finding(s) for {domain} ({len(findings_list)} total)"

        if category == "coverage":
            # Merge entries by (endpoint, parameter) key, stamp knowledge_version
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
    ) -> str:
        """Load persistent target intelligence for a domain.

        Retrieves previously stored data so you can resume testing without re-discovering
        the target's attack surface.

        Args:
            domain: Target domain (e.g. 'example.com')
            category: 'all' for summary, 'notes' for markdown notes, or a specific category
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
                data = json.loads(cat_path.read_text())
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

        # Specific category
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
        return json.dumps(data, indent=2, default=str)

    @mcp.tool()
    async def check_target_freshness(
        domain: str,
        session: str,
    ) -> str:
        """Check if stored target intel is still fresh by re-fingerprinting key pages.

        Sends GET requests to previously fingerprinted pages, compares response hashes
        and lengths, and reports what has changed. Also checks knowledge base version.

        Args:
            domain: Target domain
            session: Session name to use for requests (must exist via create_session)
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
            new_hash = "sha256:" + hashlib.sha256(body.encode()).hexdigest()[:16]
            new_length = resp.get("response_length", len(body))

            # Update stored fingerprint
            page["response_hash"] = new_hash
            page["response_length"] = new_length
            page["status"] = resp.get("status", 0)
            page["checked_at"] = datetime.now(timezone.utc).isoformat()

            if old_hash and new_hash != old_hash:
                length_diff = abs(new_length - old_length) / max(old_length, 1)
                if length_diff < 0.05:
                    fresh.append(f"  {path}: hash changed but length similar (~{length_diff:.0%} diff)")
                else:
                    changes.append(f"  {path}: CHANGED (length {old_length}→{new_length})")
            else:
                fresh.append(f"  {path}: fresh")

        # Save updated fingerprints
        _atomic_write_json(fp_path, fp_data)

        # Check knowledge version
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

        # Build report
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

    @mcp.tool()
    async def save_target_notes(
        domain: str,
        notes: str,
    ) -> str:
        """Save freeform markdown notes for a target.

        Use this to persist observations, attack ideas, or session summaries
        that don't fit structured categories.

        Args:
            domain: Target domain
            notes: Markdown text to save (overwrites existing notes)
        """
        dir_path = _ensure_dir(domain)
        notes_path = dir_path / "notes.md"
        notes_path.write_text(notes)
        return f"Notes saved for {domain} ({len(notes)} chars)"

    @mcp.tool()
    async def lookup_cross_target_patterns(
        tech_stack: list[str],
        vuln_class: str = "",
    ) -> str:
        """Find attack patterns from OTHER targets that share a similar tech stack.

        Searches all stored target intel for patterns that worked on targets with
        overlapping technology, so techniques from target A inform testing on target B.

        Args:
            tech_stack: Current target's tech stack (e.g. ['PHP', 'Apache', 'MySQL'])
            vuln_class: Optional filter by vulnerability class (e.g. 'sqli', 'xss')
        """
        if not INTEL_DIR.exists():
            return "No target intel stored yet."

        tech_lower = {t.lower() for t in tech_stack}
        matches = []

        for domain_dir in INTEL_DIR.iterdir():
            if not domain_dir.is_dir():
                continue

            # Check tech stack overlap
            profile_path = domain_dir / "profile.json"
            if not profile_path.exists():
                continue

            try:
                profile = json.loads(profile_path.read_text())
            except (json.JSONDecodeError, OSError):
                continue

            other_tech = profile.get("tech_stack", []) + profile.get("frameworks", [])
            other_lower = {t.lower() for t in other_tech}
            overlap = tech_lower & other_lower

            if not overlap:
                continue

            # Load patterns from this target
            patterns_path = domain_dir / "patterns.json"
            if not patterns_path.exists():
                continue

            try:
                patterns_data = json.loads(patterns_path.read_text())
            except (json.JSONDecodeError, OSError):
                continue

            for pattern in patterns_data.get("patterns", []):
                if vuln_class and pattern.get("vuln_class", "").lower() != vuln_class.lower():
                    continue
                matches.append({
                    "source_domain": domain_dir.name,
                    "tech_overlap": list(overlap),
                    **pattern,
                })

        if not matches:
            msg = f"No matching patterns found for tech: {', '.join(tech_stack)}"
            if vuln_class:
                msg += f" (filtered by: {vuln_class})"
            return msg

        # Sort by severity (highest first), then by timestamp (most recent first)
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        matches.sort(key=lambda m: (
            sev_order.get(m.get("severity", "low").lower(), 4),
            m.get("timestamp", ""),
        ))

        lines = [f"Cross-target patterns ({len(matches)} matches):", ""]
        for m in matches[:20]:
            lines.append(f"  [{m.get('severity', '?').upper()}] {m.get('vuln_class', '?')}: {m.get('technique', '?')}")
            lines.append(f"    Source: {m['source_domain']} (overlap: {', '.join(m['tech_overlap'])})")
            if m.get("payload"):
                lines.append(f"    Payload: {m['payload'][:100]}")
            if m.get("endpoint_pattern"):
                lines.append(f"    Endpoint: {m['endpoint_pattern']}")
            if m.get("notes"):
                lines.append(f"    Notes: {m['notes'][:150]}")
            lines.append("")

        if len(matches) > 20:
            lines.append(f"  ... and {len(matches) - 20} more patterns")

        return "\n".join(lines)
