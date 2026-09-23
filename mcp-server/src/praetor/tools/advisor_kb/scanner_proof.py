"""Scanner-provenance gate: an unverified scanner hit is not a finding.

Policy: "scanner output with no proof-of-impact" is ineligible. The existing
gates do not catch it for impact-inherent classes — Q3 auto-passes RCE / SQLi /
IDOR / SSRF / ... (the class IS the impact), and Q5 passes whenever the
scanner's own pasted output happens to contain a class keyword ("sql syntax
error", "__schema", "uid=") — which scanner output routinely does. The result
is a finding whose ONLY basis is a scanner's verdict, with nothing the operator
independently reproduced.

This gate fires when the evidence is sourced from a named scanner AND carries
no independent proof of impact: no captured request handle (proxy_history_index), no
reproductions[], no resolved OOB / Collaborator interaction, not human_verified,
and no attacker-capability / concrete-asset wording. It downgrades to NEEDS MORE
EVIDENCE and names the next proof — replay the candidate request yourself and
cite the confirming proxy_history_index. A scanner's verdict is a lead, not a finding.

Override: overrides=['scanner_proof:<reason>'] (audit-trailed).
"""

from ..advisor._context import AssessContext
from . import CheckResult
from .q3_impact import _ASSET_SIGNALS, _CAPABILITY_SIGNALS
from .q5_evidence import _OOB_MARKERS


# Named scanners / automated-tool provenance. Multi-char, tool-specific tokens
# only — no bare "scan"/"zap"/"vega" that collide with ordinary prose. Each
# entry means "this evidence is repeating what a tool reported."
_SCANNER_SIGNALS = (
    "nuclei", "nikto", "wpscan", "acunetix", "nessus", "openvas",
    "qualys", "wapiti", "arachni", "w3af", "skipfish", "detectify",
    "invicti", "netsparker", "owasp zap", "zap alert", "zap scan",
    "burp scanner", "burp active scan", "active scan flagged",
    "scanner reported", "scanner flagged", "scanner detected",
    "scanner alert", "scanner says", "automated scan flagged",
    "sast flagged", "dast flagged", "template matched", "nuclei template",
    "plugin id", "plugin output", "scan result flagged",
)


async def check(ctx: AssessContext) -> CheckResult:
    """Reject a scanner-sourced claim that nothing independently corroborates."""
    if "scanner_proof" in ctx.override_set:
        ctx.issues.append(
            "SCANNER-PROOF OVERRIDE: unverified-scanner gate bypassed"
        )
        return {"passed": True, "reason": "override", "evidence": {}}

    # Already sunk, or operator-confirmed by hand — nothing to add.
    if ctx.verdict == "DO NOT REPORT":
        return {"passed": True, "reason": "already-rejected", "evidence": {}}
    if ctx.human_verified:
        return {"passed": True, "reason": "human_verified", "evidence": {}}

    # Detect provenance on the ORIGINAL prose only. evidence_lower is augmented
    # with server-derived markers; keeping this to the operator's own text means
    # a derived marker can never introduce (or mask) a scanner name.
    prose = (ctx.evidence or "").lower()
    if not any(s in prose for s in _SCANNER_SIGNALS):
        return {"passed": True, "reason": "not-scanner-sourced", "evidence": {}}

    # Any independent corroboration lifts it above a bare scanner verdict:
    #  - a captured request handle (proxy_history_index → real response, cross-checked)
    #  - replay entries in reproductions[]
    #  - a resolved OOB / Collaborator interaction
    #  - explicit attacker-capability or concrete-asset wording
    has_handle = ctx.proxy_history_index is not None and ctx.proxy_history_index >= 0
    has_repros = bool(ctx.reproductions)
    has_oob = any(m in ctx.evidence_lower for m in _OOB_MARKERS)
    haystack = " ".join(
        p for p in (ctx.evidence_lower, (ctx.business_context or "").lower()) if p
    )
    has_capability = any(s in haystack for s in _CAPABILITY_SIGNALS) or any(
        s in haystack for s in _ASSET_SIGNALS
    )
    if has_handle or has_repros or has_oob or has_capability:
        return {"passed": True, "reason": "independent-proof", "evidence": {}}

    ctx.issues.append(
        "SCANNER OUTPUT, NO PROOF OF IMPACT: the evidence only repeats a "
        "scanner's own hit — nothing here was independently reproduced. An "
        "unverified scanner claim is ineligible (no proof-of-impact).\n"
        "      Next proof: replay the candidate request yourself "
        "(resend_with_modification) and pass the confirming proxy_history_index=<N>, "
        "add reproductions=[{proxy_history_index, ...}], resolve an OOB/Collaborator "
        "interaction, or pass human_verified=True after confirming in Burp.\n"
        "      A scanner's verdict is a lead, not a finding."
    )
    ctx.verdict = "NEEDS MORE EVIDENCE"
    return {"passed": False, "reason": "unverified-scanner", "evidence": {}}
