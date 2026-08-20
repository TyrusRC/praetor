"""Confidence + severity inference + program-policy floor.

Runs LAST. Consumes ctx.verdict, ctx.issues, ctx.weak_evidence, ctx.impact_boost
to set ctx.suggested_confidence, ctx.inferred_severity, ctx.severity_color.
"""

from ._context import AssessContext


_SEV_TO_COLOR = {
    "CRITICAL": "RED",
    "HIGH": "RED",
    "MEDIUM": "ORANGE",
    "LOW": "YELLOW",
    "INFO": "GRAY",
}

# Class-aware severity band. Before this map every clean finding was inferred
# MEDIUM — an RCE and a reflected XSS came back with the same suggestion, so
# real bugs were consistently under-sold and the operator saw a wall of
# lookalike MEDIUMs. The band is the CEILING the class can reach with strong
# evidence; weak evidence still knocks it down. Severity remains
# operator-owned at save_finding; this is the suggestion only.
_CLASS_SEVERITY_BAND = {
    "CRITICAL": {
        "rce", "command_injection", "code_injection", "deserialization",
        "sqli", "sqli_blind", "sqli_time", "sqli_error", "sqli_union",
        "ssti", "ssti_blind", "auth_bypass", "login_bypass",
        "account_takeover", "ato", "privilege_escalation",
        "exposed_credentials", "cloud_metadata_ssrf", "jwt_alg_none",
        "subdomain_takeover", "file_upload_rce",
    },
    "HIGH": {
        "idor", "bola", "bfla", "bopla", "broken_object_level_auth",
        "broken_function_level_auth", "id_enumeration", "mass_assignment",
        "ssrf", "ssrf_blind", "xxe", "xxe_blind", "path_traversal", "lfi",
        "xss_stored", "request_smuggling", "cache_poisoning",
        "race_condition", "business_logic", "mfa_bypass", "2fa_bypass",
        "saml_xsw", "jwt_kid", "jwt_forge", "password_reset_takeover",
        "prototype_pollution", "secret_leak", "nosqli", "rfi",
    },
    "MEDIUM": {
        "xss", "xss_reflected", "csrf", "cors", "cors_misconfiguration",
        "open_redirect", "host_header_injection", "crlf_injection",
        "websocket", "graphql", "rate_limit_missing", "clickjacking",
    },
}

_SEV_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def _class_band(ctx) -> str:
    """Ceiling severity for the finding's class. MEDIUM when unmapped."""
    for band, members in _CLASS_SEVERITY_BAND.items():
        if ctx.vuln_lower in members or ctx.q2_class_root in members:
            return band
    return "MEDIUM"


def _cap(value: str, ceiling: str) -> str:
    return value if _SEV_ORDER.index(value) <= _SEV_ORDER.index(ceiling) else ceiling


def finalize_severity(ctx: AssessContext) -> None:
    """Compute suggested_confidence, inferred_severity, severity_color.

    Also applies program-policy confidence floor (may downgrade verdict +
    append a PROGRAM POLICY ENFORCED issue).
    """
    if ctx.verdict == "DO NOT REPORT":
        ctx.suggested_confidence = 0.05
    elif ctx.verdict == "NEEDS MORE EVIDENCE":
        penalty = max(0, len(ctx.issues) - 1) * 0.05
        ctx.suggested_confidence = max(0.40, 0.65 - penalty + ctx.impact_boost)
    elif not ctx.issues:
        ctx.suggested_confidence = min(1.0, 0.92 + ctx.impact_boost)
    else:
        ctx.suggested_confidence = min(1.0, 0.80 + ctx.impact_boost)

    # Program-policy confidence floor
    if ctx.verdict == "REPORT" and ctx.program_confidence_floor > 0:
        if ctx.suggested_confidence < ctx.program_confidence_floor:
            ctx.issues.append(
                f"PROGRAM POLICY ENFORCED: program '{ctx.program.get('slug', '?')}' "
                f"sets confidence_floor={ctx.program_confidence_floor:.2f}; "
                f"current confidence is {ctx.suggested_confidence:.2f}. "
                f"This is a POLICY downgrade, not an evidence problem — "
                f"either strengthen evidence to meet the floor, OR override "
                f"with set_program_policy() if the floor itself is wrong."
            )
            ctx.verdict = "NEEDS MORE EVIDENCE"

    band = _class_band(ctx)
    if ctx.verdict == "DO NOT REPORT":
        ctx.inferred_severity = "INFO"
    elif ctx.weak_evidence:
        # Weak evidence caps at LOW regardless of class — an unproven RCE is
        # not a CRITICAL, it is an unproven claim.
        ctx.inferred_severity = "LOW"
    elif ctx.verdict == "NEEDS MORE EVIDENCE":
        ctx.inferred_severity = _cap("MEDIUM", band)
    else:
        # Clean pass: the class band is the suggestion, nudged up one step
        # when impact scoring found real amplifiers (auth'd session, sensitive
        # data class, kill-switch endpoint, sequential IDs).
        sev = band
        if ctx.impact_boost >= 0.15 and band != "CRITICAL":
            sev = _SEV_ORDER[min(len(_SEV_ORDER) - 1, _SEV_ORDER.index(band) + 1)]
        ctx.inferred_severity = sev
    ctx.severity_color = _SEV_TO_COLOR.get(ctx.inferred_severity, "YELLOW")

    # Bug-bounty reality check: a LOW/INFO submission is a triager's
    # Informative queue. Say so and name the escalation, rather than letting
    # the operator file it and get it closed.
    if ctx.verdict == "REPORT" and ctx.inferred_severity in ("LOW", "INFO"):
        ctx.impact_notes.append(
            "SUBMIT-AS-IS RISK: LOW/INFO findings are closed Informative by most "
            "programs. Before submitting, spend one cycle on escalation — what "
            "does this ENABLE? (propose_chains / research_attack_vector). Report "
            "the chain, not the primitive."
        )
