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
        force_recon_gate: bool = False,
        human_verified: bool = False,
        overrides: list[str] | None = None,
    ) -> str:
        """Save a pentest finding. Requires prior assess_finding() call. Burp hard-rejects missing evidence.

        Args:
            title: Short finding title
            description: Detailed vulnerability description
            evidence: Dict with logger_index, proxy_history_index, or collaborator_interaction_id
            severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO
            endpoint: Affected URL/endpoint
            evidence_text: Freeform proof string for the report
            reproductions: Required for timing/blind vuln_types (>=2 dicts with logger_index/elapsed_ms/status_code)
            chain_with: Required for NEVER SUBMIT vuln_types — list of finding IDs for the chain
            status: suspected, confirmed, stale, or likely_false_positive
            domain: Target domain for persistent .burp-intel storage
            parameter: Parameter name (dedup key)
            vuln_type: Vulnerability class (e.g. sqli, xss, sqli_blind)
            confidence: 0.0-1.0 score
            force_recon_gate: Bypass the session-start recon gate (Rule 20a). Only use if recon is already in flight in this session and not yet persisted.
            human_verified: Operator confirmed visually in Burp UI / browser DevTools. Logged in finding metadata (R19).
            overrides: Audit-trailed gate bypasses (R20). Each entry "<gate>:<reason>". Stored in finding entry as 'overrides' for review.
        """
        try:
            confidence = max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            confidence = 0.5

        resolved_domain = domain or _domain_from_endpoint(endpoint)

        # ── Rule 20a: recon gate ──────────────────────────────────
        # Refuse to persist findings for domains where no recon has been
        # recorded. Empty `.burp-intel/<domain>/` = operator skipped session-
        # start intel; saving here would create a phantom history with no
        # context. force_recon_gate=True overrides for in-flight recon.
        # R20 unified override: 'recon_gate' in overrides also bypasses gate.
        override_set = {(o.split(":", 1)[0] if ":" in o else o).strip().lower()
                        for o in (overrides or [])}
        skip_recon_gate = force_recon_gate or "recon_gate" in override_set
        if resolved_domain and not skip_recon_gate:
            from burpsuite_mcp.tools.intel import recon_gate_check
            gate_err = recon_gate_check(resolved_domain)
            if gate_err is not None:
                return f"RECON GATE: {gate_err}"

        # ── R25: chain_with validator ─────────────────────────────
        # Reject chain_with referencing findings that are likely_false_positive
        # or stale. Force re-verification before chain.
        if chain_with and resolved_domain:
            try:
                findings_path = INTEL_DIR / _sanitized(resolved_domain) / "findings.json"
                if findings_path.exists():
                    existing = _load_findings_file(findings_path).get("findings", [])
                    by_id = {f.get("id", ""): f for f in existing if f.get("id")}
                    bad_chain: list[str] = []
                    for cid in chain_with:
                        anchor = by_id.get(cid)
                        if anchor is None:
                            bad_chain.append(f"{cid} (not found)")
                            continue
                        anchor_status = anchor.get("status", "")
                        if anchor_status in ("likely_false_positive", "stale"):
                            bad_chain.append(f"{cid} ({anchor_status})")
                    if bad_chain:
                        return (
                            f"CHAIN GATE: chain_with references dead anchors: "
                            f"{', '.join(bad_chain)}. Re-verify each before chaining, "
                            f"or pass overrides=['q4_dedup:reviewed'] only after manual confirmation."
                        )
            except (OSError, ValueError):
                pass  # best-effort

        # ZERO-NOISE GATE — call Burp first. If the server rejects (missing
        # evidence index, NEVER SUBMIT without chain, missing reproductions),
        # we MUST NOT persist anything to .burp-intel/findings.json. Otherwise
        # rejected findings accumulate locally and get re-loaded next session,
        # wasting tokens on phantom "confirmed" findings.
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
            return f"Error (gate rejected — nothing persisted): {data['error']}"
        burp_id = data.get("id", "?")

        # Gate passed — now safe to persist locally.
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
                "human_verified": human_verified,
                "overrides": list(overrides or []),
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
        """Get all saved pentest findings, optionally filtered by endpoint URL.

        Args:
            endpoint: Filter by endpoint URL substring (empty = all)
        """
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
    async def hydrate_burp_findings(domain: str = "all", include_suspected: bool = False) -> str:
        """Re-populate Burp's in-memory Findings tab from persisted .burp-intel findings. Use after extension reload.

        Args:
            domain: Specific domain to hydrate, or 'all' for every .burp-intel domain
            include_suspected: If True, also restore suspected/stale findings (default: confirmed-only)
        """
        targets: list[Path] = []
        if domain == "all":
            if INTEL_DIR.exists():
                for d in sorted(INTEL_DIR.iterdir()):
                    if d.is_dir() and (d / "findings.json").exists():
                        targets.append(d / "findings.json")
        else:
            p = INTEL_DIR / _sanitized(domain) / "findings.json"
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
                data = json.loads(path.read_text())
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
