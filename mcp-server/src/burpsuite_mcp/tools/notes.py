"""Tools for saving findings and generating reports."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

INTEL_DIR = Path.cwd() / ".burp-intel"


def _sanitized(domain: str) -> str:
    return re.sub(r'[^a-zA-Z0-9._-]', '_', domain)


def _domain_from_endpoint(endpoint: str) -> str:
    """Best-effort host extraction from an endpoint URL or bare host."""
    if not endpoint:
        return ""
    if "://" in endpoint:
        return urlparse(endpoint).hostname or ""
    # bare /path/... — no host info
    return ""


def _load_findings_file(path: Path) -> dict:
    if not path.exists():
        return {"findings": [], "last_modified": ""}
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {"findings": [], "last_modified": ""}


def _write_findings_file(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def _dedupe_finding(existing: list[dict], new: dict) -> tuple[list[dict], str, int]:
    """Merge `new` into `existing` by (endpoint + title + parameter).

    Returns (updated_list, action, index) where action is 'created' or 'updated'
    and index points at the finding's position in the returned list.
    """
    key_ep = new.get("endpoint", "")
    key_title = new.get("title", "").lower()
    key_param = new.get("parameter", "")

    for i, f in enumerate(existing):
        same_ep = f.get("endpoint", "") == key_ep
        same_title = f.get("title", "").lower() == key_title
        same_param = f.get("parameter", "") == key_param
        if same_ep and same_title and same_param:
            merged = {**f, **new, "id": f.get("id")}
            existing[i] = merged
            return existing, "updated", i
    existing.append(new)
    return existing, "created", len(existing) - 1


def register(mcp: FastMCP):

    @mcp.tool()
    async def save_finding(
        title: str,
        description: str,
        severity: str = "INFO",
        endpoint: str = "",
        evidence: str = "",
        status: str = "suspected",
        domain: str = "",
        parameter: str = "",
        vuln_type: str = "",
    ) -> str:
        """Save a pentest finding/vulnerability note.

        Persists to BOTH:
          1. Burp's in-memory FindingsStore (gone on extension reload)
          2. .burp-intel/<domain>/findings.json (survives reload; rule 16)

        Findings are deduplicated by (endpoint + title + parameter). A second
        save_finding with the same key updates the entry instead of creating a
        duplicate (rule 23).

        Args:
            title: Short finding title (e.g. "SQL Injection in login form")
            description: Detailed description of the vulnerability
            severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO
            endpoint: Affected URL/endpoint
            evidence: Proof (request/response snippets, payloads used)
            status: Finding status — 'suspected', 'confirmed', 'stale', or 'likely_false_positive'
            domain: Target domain for persistent storage. If empty, extracted
                    from endpoint host. When neither is available, the finding
                    is only stored in Burp memory and you get a warning.
            parameter: Parameter name (used for dedup key)
            vuln_type: Vulnerability class (e.g. 'xss', 'sqli'). Stored with
                       the finding for future cross-target pattern lookup.
        """
        resolved_domain = domain or _domain_from_endpoint(endpoint)

        # Dedupe against persistent store first
        dedup_action = "created"
        saved_id = ""
        if resolved_domain:
            findings_path = INTEL_DIR / _sanitized(resolved_domain) / "findings.json"
            store = _load_findings_file(findings_path)
            now = datetime.now(timezone.utc).isoformat()
            new_entry = {
                "title": title,
                "description": description,
                "severity": severity,
                "endpoint": endpoint,
                "evidence": evidence,
                "status": status,
                "parameter": parameter,
                "vuln_type": vuln_type,
                "last_updated": now,
            }
            existing_list = store.get("findings", [])
            updated_list, dedup_action, idx = _dedupe_finding(existing_list, new_entry)
            if dedup_action == "created":
                existing_ids = {f.get("id", "") for f in updated_list if f.get("id")}
                next_num = 1
                while f"f{next_num:03d}" in existing_ids:
                    next_num += 1
                updated_list[idx]["id"] = f"f{next_num:03d}"
                updated_list[idx]["created"] = now
            saved_id = updated_list[idx].get("id", "")
            store["findings"] = updated_list
            store["last_modified"] = now
            _write_findings_file(findings_path, store)

        # Mirror to Burp's in-memory store (best effort)
        data = await client.post("/api/notes/findings", json={
            "title": title,
            "description": description,
            "severity": severity,
            "endpoint": endpoint,
            "evidence": evidence,
            "status": status,
        })
        burp_id = data.get("id", "?") if "error" not in data else "?"

        if not resolved_domain:
            return (
                f"Finding saved to Burp in-memory only [{severity}] {title} (Burp ID: {burp_id}).\n"
                "Warning: no domain passed and could not derive from endpoint. "
                "Finding will be lost on Burp reload. Pass `domain=...` to persist."
            )

        action_label = "Updated" if dedup_action == "updated" else "Saved"
        return (
            f"{action_label} [{severity}] {title}\n"
            f"  Persistent ID: {saved_id} ({resolved_domain})\n"
            f"  Burp ID: {burp_id}\n"
            f"  Location: .burp-intel/{_sanitized(resolved_domain)}/findings.json"
        )

    @mcp.tool()
    async def get_findings(endpoint: str = "") -> str:
        """Get all saved pentest findings, optionally filtered by endpoint URL."""
        params = {}
        if endpoint:
            params["endpoint"] = endpoint

        data = await client.get("/api/notes/findings", params=params)
        if "error" in data:
            return f"Error: {data['error']}"

        findings = data.get("findings", [])
        if not findings:
            return "No findings saved yet."

        lines = [f"Saved Findings ({data.get('total', 0)}):\n"]
        for f in findings:
            lines.append(f"[{f.get('severity')}] #{f.get('id')} - {f.get('title')}")
            if f.get("endpoint"):
                lines.append(f"  Endpoint: {f['endpoint']}")
            if f.get("description"):
                lines.append(f"  {f['description'][:200]}")
            lines.append("")

        return "\n".join(lines)

    @mcp.tool()
    async def export_report(format: str = "markdown") -> str:
        """Export all findings as a pentest report.

        Args:
            format: 'markdown' or 'json'
        """
        data = await client.get("/api/notes/export", params={"format": format})
        if "error" in data:
            return f"Error: {data['error']}"

        if format == "json":
            return str(data)
        return data.get("content", "No findings to export.")
