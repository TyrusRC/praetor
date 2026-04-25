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
        evidence: dict,
        severity: str = "INFO",
        endpoint: str = "",
        evidence_text: str = "",
        reproductions: list[dict] | None = None,
        chain_with: list[str] | None = None,
        status: str = "suspected",
        domain: str = "",
        parameter: str = "",
        vuln_type: str = "",
        confidence: float = 0.5,
    ) -> str:
        """Save a pentest finding/vulnerability note. ZERO-NOISE GATE.

        The Burp extension HARD-REJECTS findings without verified evidence:
          - `evidence` MUST be a dict with at least one of:
              {"logger_index": <int>}
              {"proxy_history_index": <int>}
              {"collaborator_interaction_id": "<str>"}
            and the index/ID MUST resolve against live Burp data.
          - For timing/blind vuln_types (sqli_blind, sqli_time, ssrf_blind,
            race_condition, request_smuggling, ssti_blind,
            command_injection_blind, xxe_blind), `reproductions` MUST be a list
            of >= 2 dicts of shape:
              {"logger_index": <int>, "elapsed_ms": <int>, "status_code": <int>}
          - If `vuln_type` (or `title`) matches the NEVER SUBMIT list (missing
            security headers, self-XSS, OPTIONS enabled, etc. — see hunting.md),
            `chain_with` MUST be a non-empty list of existing finding IDs.

        The server returns a 400 with a clear remediation message when any check
        fails — propagate it back to the caller.

        Args:
            title: Short finding title (e.g. "SQL Injection in login form").
            description: Detailed description of the vulnerability.
            evidence: Required. {"logger_index": int} OR {"proxy_history_index": int}
                      OR {"collaborator_interaction_id": str}. Combine if you have
                      more than one.
            severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO.
            endpoint: Affected URL/endpoint.
            evidence_text: Freeform proof string (req/resp snippets, payloads).
                           Goes into the report; not used for validation.
            reproductions: Required for timing/blind vuln_types. List of >=2 dicts:
                           [{"logger_index": int, "elapsed_ms": int, "status_code": int}, ...]
            chain_with: Required for NEVER SUBMIT vuln_types. List of existing
                        finding IDs that turn this into a reportable chain.
            status: 'suspected', 'confirmed', 'stale', or 'likely_false_positive'.
            domain: Target domain for persistent .burp-intel storage.
            parameter: Parameter name (used for dedup key).
            vuln_type: Vulnerability class (e.g. 'sqli', 'xss', 'sqli_blind').
            confidence: 0.0–1.0 score. RED highlight only at >= 0.9.
        """
        try:
            confidence = max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            confidence = 0.5

        resolved_domain = domain or _domain_from_endpoint(endpoint)

        # Persistent .burp-intel store (unchanged behavior)
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
                "evidence_text": evidence_text,
                "evidence": evidence,
                "reproductions": reproductions or [],
                "chain_with": chain_with or [],
                "status": status,
                "parameter": parameter,
                "vuln_type": vuln_type,
                "confidence": round(confidence, 2),
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

        # Burp in-memory mirror — this is where the zero-noise gate lives.
        payload = {
            "title": title,
            "description": description,
            "severity": severity,
            "endpoint": endpoint,
            "evidence_text": evidence_text,
            "evidence": evidence,
            "vuln_type": vuln_type,
            "status": status,
        }
        if reproductions:
            payload["reproductions"] = reproductions
        if chain_with:
            payload["chain_with"] = chain_with

        data = await client.post("/api/notes/findings", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"
        burp_id = data.get("id", "?")

        if not resolved_domain:
            return (
                f"Finding saved to Burp in-memory only [{severity}] {title} (Burp ID: {burp_id}).\n"
                "Warning: no domain passed and could not derive from endpoint. "
                "Finding will be lost on Burp reload. Pass `domain=...` to persist."
            )

        action_label = "Updated" if dedup_action == "updated" else "Saved"
        return (
            f"{action_label} [{severity}] c={confidence:.2f} {title}\n"
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
