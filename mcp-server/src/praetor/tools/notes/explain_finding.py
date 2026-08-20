"""explain_finding — structured proof + chain hints for a saved finding.

Assembles proof block, severity rationale, and sibling chain candidates
from local findings.json. No external calls; Claude narrates over the
structured output.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ._helpers import (
    _domain_from_endpoint,
    _find_by_id,
    _format_proof_for_review,
    _load_findings_file,
    _safe_findings_path,
)

_NEVER_SUBMIT_HINTS = {
    "missing_security_header", "self_xss", "csrf_logout", "open_redirect",
    "mixed_content", "username_enumeration", "email_enumeration",
    "rate_limit", "info_disclosure", "version_disclosure",
}

_CHAIN_TARGETS = {
    "open_redirect": ["oauth", "csrf", "xss"],
    "info_disclosure": ["idor", "auth_bypass", "ssrf"],
    "csrf": ["account_takeover", "mass_assignment"],
    "xss": ["account_takeover", "csrf"],
    "ssrf": ["cloud_metadata", "rce_detection"],
    "host_header": ["cache_poisoning", "password_reset"],
    "subdomain_takeover": ["cookie_scope", "csp_bypass", "oauth"],
}


def _severity_rationale(f: dict) -> str:
    sev = (f.get("severity") or "INFO").upper()
    vt = f.get("vuln_type") or ""
    if sev in {"CRITICAL", "HIGH"}:
        return f"Severity {sev} justified by direct exploit impact for class '{vt}'."
    if sev == "MEDIUM":
        return f"Severity {sev} — requires specific preconditions or partial chain."
    if sev == "LOW":
        return f"Severity {sev} — limited impact unchained."
    return "Severity INFO — likely informational; chain required for impact (Rule 17)."


def _chain_candidates(target_findings: list[dict], origin: dict) -> list[dict]:
    vt = (origin.get("vuln_type") or "").lower()
    wanted = _CHAIN_TARGETS.get(vt, [])
    if not wanted:
        return []
    out: list[dict] = []
    for f in target_findings:
        if f.get("id") == origin.get("id"):
            continue
        ft = (f.get("vuln_type") or "").lower()
        if any(w in ft or ft in w for w in wanted):
            if f.get("status") in {"confirmed", "suspected"}:
                out.append({
                    "id": f.get("id"),
                    "vuln_type": ft,
                    "title": f.get("title", "")[:80],
                    "endpoint": f.get("endpoint", ""),
                })
    return out[:10]


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def explain_finding(finding_id: str, domain: str = "") -> str:
        """Return structured proof + chain hints for a saved finding.

        Args:
            finding_id: persistent finding ID (e.g. 'f-001a2b').
            domain: optional explicit domain. Auto-resolved if omitted.
        """
        domain = (domain or "").strip()
        if not domain:
            try:
                base = _safe_findings_path("")
                root = base.parent
            except Exception:
                root = None
            if root is not None and root.exists():
                for child in root.iterdir():
                    if not child.is_dir():
                        continue
                    p = child / "findings.json"
                    if not p.exists():
                        continue
                    findings = _load_findings_file(p)
                    _, f = _find_by_id(findings, finding_id)
                    if f is not None:
                        domain = child.name
                        break
        if not domain:
            return f"Error: finding {finding_id!r} not found in any .burp-intel/<domain>/."

        path = _safe_findings_path(domain)
        findings = _load_findings_file(path)
        _, f = _find_by_id(findings, finding_id)
        if f is None:
            return f"Error: finding {finding_id!r} not found in domain {domain!r}."

        if not domain:
            domain = _domain_from_endpoint(f.get("endpoint", ""))

        proof = _format_proof_for_review(f)
        rationale = _severity_rationale(f)
        chain = _chain_candidates(findings, f)

        lines = [
            f"# explain_finding — {finding_id}",
            "",
            "## Proof",
            proof,
            "",
            "## Severity rationale",
            rationale,
        ]

        vt = (f.get("vuln_type") or "").lower()
        if vt in _NEVER_SUBMIT_HINTS:
            lines += [
                "",
                "## NEVER-SUBMIT class",
                f"Vuln class '{vt}' is informative-alone. Reportable only when chained.",
                "Run explore_issue() to surface chain probe suggestions.",
            ]

        if chain:
            lines += ["", "## Chain candidates (sibling findings)"]
            for c in chain:
                lines.append(f"  - {c['id']} [{c['vuln_type']}] {c['title']} @ {c['endpoint']}")
            lines.append("")
            lines.append("Consider save_finding(chain_with=[...]) once chain is verified.")
        else:
            lines += [
                "",
                "## Chain candidates",
                "None found. Run explore_issue() for class-specific follow-up probes.",
            ]

        return "\n".join(lines)
