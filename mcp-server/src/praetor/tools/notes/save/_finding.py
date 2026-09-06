"""save_finding — the gated write path for a pentest finding (Rule 10c).

Thin orchestration: validation gates live in _gates.py (pure, error-or-None);
the Burp submit + local persist + Organizer hook live in _persist.py.
"""

from mcp.server.fastmcp import FastMCP

from praetor.tools.report.severity import cvss4_for_finding

from .._helpers import _domain_from_endpoint
from . import _gates
from ._persist import handle_false_positive, submit_and_persist


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
        impact: str = "",
        remediation: str = "",
        poc_request: str = "",
        reproduction_steps: list[str] | None = None,
        cwe: str = "",
        cvss_vector: str = "",
        force_recon_gate: bool = False,
        human_verified: bool = False,
        overrides: list[str] | None = None,
    ) -> str:
        """Save a pentest finding. Requires prior assess_finding(). Burp hard-rejects missing evidence.

        The report renders only what is stored here. A field left empty is a
        section the deliverable omits — it is never filled in later from
        recollection, which is how reports end up describing a PoC nobody ran.

        Args:
            title: Short finding title.
            description: Detailed vulnerability description.
            evidence: Dict with logger_index, proxy_history_index, or collaborator_interaction_id.
            severity: CRITICAL/HIGH/MEDIUM/LOW/INFO. Operator-locked — wins over advisor's inferred severity.
            endpoint: Affected URL/endpoint.
            evidence_text: Freeform proof string for the report.
            reproductions: Required for timing/blind vuln_types (>=3 dicts with logger_index/elapsed_ms/status_code, per Rule 10a).
            chain_with: Required for NEVER-SUBMIT vuln_types — list of finding IDs for the chain.
            status: suspected/confirmed/stale/likely_false_positive.
            domain: Target domain for persistent .burp-intel storage.
            parameter: Parameter name (dedup key).
            vuln_type: Vuln class (e.g. sqli, xss, sqli_blind).
            confidence: 0.0-1.0 score.
            impact: What an attacker GAINS — whose data, which action, what they
                obtain that they could not get legitimately. Required for
                MEDIUM and above: a finding that cannot state this is what
                programs close as Informative.
            remediation: The fix, specific to this endpoint/parameter.
            poc_request: Raw HTTP request that demonstrates the issue.
            reproduction_steps: Cold-start steps a triager can follow.
            cwe: CWE id (e.g. 'CWE-89'). Blank falls back to the class map.
            cvss_vector: Explicit CVSS 4.0 vector. Blank derives one from
                vuln_type + evidence shape flags; the derived band is
                cross-checked against `severity`.
            force_recon_gate: Bypass session-start recon gate (Rule 20a); only if recon is in flight and not yet persisted.
            human_verified: Operator confirmed visually in Burp/DevTools. Logged in metadata.
            overrides: Audit-trailed gate bypasses (R20), each "<gate>:<reason>".
        """
        # Severity is operator-locked. Validate but don't auto-adjust.
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        severity_upper = (severity or "INFO").upper()
        if severity_upper not in valid_severities:
            return (
                f"Error: invalid severity '{severity}'. Must be one of: "
                f"{', '.join(sorted(valid_severities))}. Operator owns severity choice; "
                f"see user-override skill for guidance."
            )
        severity = severity_upper

        try:
            confidence = max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            confidence = 0.5

        # Tool-call format guard (malformed parameter block → empty fields).
        leak_err = _gates.evidence_leak_gate(evidence_text)
        if leak_err is not None:
            return leak_err

        resolved_domain = domain or _domain_from_endpoint(endpoint)

        # ── Status='likely_false_positive' shortcut ────────────────────
        if (status or "").lower() == "likely_false_positive":
            return await handle_false_positive(
                resolved_domain, endpoint, vuln_type, title, parameter
            )

        override_set = {(o.split(":", 1)[0] if ":" in o else o).strip().lower()
                        for o in (overrides or [])}

        # ── Pre-persist validation gates (error string aborts the save) ──
        never_err = _gates.never_submit_gate(vuln_type, chain_with, override_set)
        if never_err is not None:
            return never_err

        info_err = _gates.info_gate(severity, title, override_set)
        if info_err is not None:
            return info_err

        impact_err = _gates.impact_gate(severity, impact, override_set)
        if impact_err is not None:
            return impact_err

        cvss4_vector, cvss4_severity = cvss4_for_finding(
            vuln_type, evidence=evidence if isinstance(evidence, dict) else {},
            explicit_vector=cvss_vector,
        )
        cvss_err = _gates.severity_cvss_gate(
            severity, cvss4_vector, cvss4_severity, vuln_type, title, override_set
        )
        if cvss_err is not None:
            return cvss_err

        systemic_err = _gates.systemic_gate(
            resolved_domain, status, vuln_type, endpoint, parameter, title, override_set
        )
        if systemic_err is not None:
            return systemic_err

        recon_err = _gates.recon_gate(resolved_domain, force_recon_gate, override_set)
        if recon_err is not None:
            return recon_err

        chain_err = _gates.chain_with_gate(chain_with, resolved_domain)
        if chain_err is not None:
            return chain_err

        # ── Zero-noise submit to Burp, then local persist + Organizer hook ──
        return await submit_and_persist(
            title=title,
            description=description,
            severity=severity,
            endpoint=endpoint,
            evidence_text=evidence_text,
            evidence=evidence,
            vuln_type=vuln_type,
            status=status,
            reproductions=reproductions,
            chain_with=chain_with,
            human_verified=human_verified,
            overrides=overrides,
            parameter=parameter,
            confidence=confidence,
            impact=impact,
            remediation=remediation,
            poc_request=poc_request,
            reproduction_steps=reproduction_steps,
            cwe=cwe,
            cvss4_vector=cvss4_vector,
            cvss4_severity=cvss4_severity,
            resolved_domain=resolved_domain,
        )
