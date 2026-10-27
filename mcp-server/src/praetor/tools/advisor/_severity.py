"""Impact-first severity inference + confidence scoring.

Runs LAST. Severity starts from PROVEN IMPACT, not from the vuln class name.
A theoretical RCE without a confirmed exploit is MEDIUM; a confirmed SQLi that
reads PII from a production banking app is CRITICAL. The class name sets the
ceiling, not the floor — exploit maturity, environment, attack path, and data
accessed determine where inside that range the finding lands.

Rule 14b: "Rate on business impact, not on how hard the bug was to find."
"""

from ._context import AssessContext


_SEV_TO_COLOR = {
    "CRITICAL": "RED",
    "HIGH": "RED",
    "MEDIUM": "ORANGE",
    "LOW": "YELLOW",
    "INFO": "GRAY",
}

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

_REAL_DATA_SIGNALS = (
    "pii", "personal", "credentials", "password", "credit card", "ssn",
    "financial", "payment", "patient", "medical", "phi", "hipaa",
    "token", "secret", "api_key", "private key", "session",
    "email address", "phone number", "bank", "account number",
)

_SCANNER_ONLY_SIGNALS = (
    "nuclei", "nikto", "wpscan", "nessus", "zap", "openvas",
    "scanner", "template-id", "matched-at",
)

_STAGING_SIGNALS = ("staging", "dev", "test", "sandbox", "localhost", "127.0.0.1")


def _class_ceiling(ctx) -> str:
    """Maximum severity the vuln class can reach with perfect evidence."""
    for band, members in _CLASS_SEVERITY_BAND.items():
        if ctx.vuln_lower in members or ctx.q2_class_root in members:
            return band
    return "MEDIUM"


def _sev_idx(s: str) -> int:
    return _SEV_ORDER.index(s) if s in _SEV_ORDER else 2


def _cap(value: str, ceiling: str) -> str:
    return value if _sev_idx(value) <= _sev_idx(ceiling) else ceiling


def _bump(value: str, steps: int = 1) -> str:
    idx = min(len(_SEV_ORDER) - 1, _sev_idx(value) + steps)
    return _SEV_ORDER[idx]


def _exploit_maturity(ctx: AssessContext) -> str:
    """Determine exploit maturity from evidence.

    Returns: 'confirmed', 'reproduced', 'suspected', 'scanner_only'.
    """
    if ctx.exploit_demonstrated:
        return "confirmed"
    repro_count = len(ctx.reproductions) if ctx.reproductions else 0
    if repro_count >= 3:
        return "reproduced"
    ev = ctx.evidence_lower
    if any(s in ev for s in _SCANNER_ONLY_SIGNALS):
        if not ctx.proxy_history_index or ctx.proxy_history_index < 0:
            return "scanner_only"
    if ctx.human_verified:
        return "confirmed"
    if repro_count >= 1:
        return "reproduced"
    return "suspected"


def _env_context(ctx: AssessContext) -> str:
    """Determine environment: 'production', 'internal', 'staging', 'unknown'."""
    env = (ctx.environment or "").lower()
    exp = (ctx.network_exposure or "").lower()

    if any(s in env for s in _STAGING_SIGNALS):
        return "staging"
    if "production" in env or "prod" in env:
        if exp in ("internal", "ip_allowlist", "vpn_only", "vpn", "intranet",
                    "adjacent", "local", "host_local"):
            return "internal"
        return "production"
    if exp in ("internal", "ip_allowlist", "vpn_only", "vpn", "intranet",
               "adjacent", "local", "host_local"):
        return "internal"
    if env:
        return "production"
    return "unknown"


def _has_real_data_impact(ctx: AssessContext) -> bool:
    """True when evidence mentions real sensitive data accessed."""
    ev = ctx.evidence_lower
    return any(s in ev for s in _REAL_DATA_SIGNALS)


def _exposure_band_drop(ctx) -> int:
    """CVSS-measured band drop for non-internet-facing surfaces."""
    exp = (getattr(ctx, "network_exposure", "") or "").strip()
    if not exp:
        return 0
    try:
        from praetor.tools.advisor import _cvss4
        cls = ctx.q2_class_root or ctx.vuln_lower
        base = _cvss4.severity_band(_cvss4.build_vector(cls, {}))
        adj = _cvss4.severity_band(
            _cvss4.build_vector(cls, {"network_exposure": exp}))
    except Exception:
        return 0

    def _norm(b: str) -> str:
        b = (b or "").upper()
        return "INFO" if b in ("NONE", "") else b

    order = {s: i for i, s in enumerate(_SEV_ORDER)}
    return max(0, order.get(_norm(base), 0) - order.get(_norm(adj), 0))


def finalize_severity(ctx: AssessContext) -> None:
    """Impact-first severity inference.

    Flow:
    1. Confidence from verdict + evidence quality.
    2. Exploit maturity sets the BASE (not the class name).
    3. Class ceiling caps the base.
    4. Attack path (chain_with, kill-switch) can boost.
    5. Real data impact can boost.
    6. Environment adjusts (production/internal/staging).
    7. CVSS exposure drops for non-internet-facing.
    """

    # ── 1. Confidence ──
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

    # ── Early exit: not reportable ──
    if ctx.verdict == "DO NOT REPORT":
        ctx.inferred_severity = "INFO"
        ctx.severity_color = "GRAY"
        return

    ceiling = _class_ceiling(ctx)
    maturity = _exploit_maturity(ctx)
    env = _env_context(ctx)

    # ── 2. Exploit maturity sets the BASE ──
    if maturity == "confirmed":
        sev = ceiling
        ctx.impact_notes.append(f"Exploit confirmed: full class ceiling ({ceiling}) applies.")
    elif maturity == "reproduced":
        sev = ceiling
        ctx.impact_notes.append(
            f"Exploit reproduced ({len(ctx.reproductions)}x): "
            f"class ceiling ({ceiling}) applies."
        )
    elif maturity == "scanner_only":
        sev = _cap("LOW", ceiling)
        ctx.impact_notes.append(
            "Scanner-only evidence (no independent replay): capped at LOW. "
            "Replay the request and cite the confirming proxy_history_index."
        )
    elif ctx.weak_evidence:
        sev = "LOW"
        ctx.impact_notes.append("Weak evidence: capped at LOW until confirmed.")
    else:
        sev = _cap("MEDIUM", ceiling)
        ctx.impact_notes.append(
            f"Suspected (not yet confirmed): capped at MEDIUM. "
            f"Confirm with exploit_demonstrated or >=3 reproductions for {ceiling}."
        )

    # ── 3. Attack path boost (chain_with) ──
    if ctx.chain_with and len(ctx.chain_with) > 0 and maturity in ("confirmed", "reproduced"):
        old = sev
        sev = _cap(_bump(sev), ceiling)
        if sev != old:
            ctx.impact_notes.append(
                f"Chained attack path ({len(ctx.chain_with)} linked findings): "
                f"{old} → {sev}."
            )

    # ── 4. Kill-switch endpoint boost ──
    kill_switches = ctx.biz_data.get("kill_switches") or [] if ctx.biz_data else []
    if kill_switches and maturity in ("confirmed", "reproduced"):
        ep = (ctx.endpoint or "").lower()
        for ks in kill_switches:
            if str(ks).lower() in ep:
                old = sev
                sev = _cap("CRITICAL", "CRITICAL")
                if sev != old:
                    ctx.impact_notes.append(
                        f"Kill-switch endpoint '{ks}' + confirmed exploit: "
                        f"CRITICAL floor."
                    )
                break

    # ── 5. Real data impact boost ──
    if _has_real_data_impact(ctx) and maturity in ("confirmed", "reproduced"):
        old = sev
        sev = _cap(_bump(sev), "CRITICAL")
        if sev != old:
            ctx.impact_notes.append(
                f"Real sensitive data accessed (PII/credentials/financial): "
                f"{old} → {sev}."
            )

    # ── 6. Impact-boost from _impact.py (biz context, grey-box, sequential IDs) ──
    if ctx.impact_boost >= 0.15 and sev != "CRITICAL" and maturity in ("confirmed", "reproduced"):
        old = sev
        sev = _cap(_bump(sev), ceiling)
        if sev != old:
            ctx.impact_notes.append(
                f"Business-context amplifiers (+{ctx.impact_boost:.0%}): {old} → {sev}."
            )

    # ── 7. Environment adjustment ──
    if env == "staging":
        old = sev
        sev = _cap(sev, "MEDIUM")
        if sev != old:
            ctx.impact_notes.append(
                f"Staging/dev environment: no real user impact, capped at MEDIUM "
                f"(was {old})."
            )
    elif env == "internal":
        drop = _exposure_band_drop(ctx)
        if drop:
            old = sev
            idx = max(0, _sev_idx(sev) - drop)
            sev = _SEV_ORDER[idx]
            if sev != old:
                ctx.impact_notes.append(
                    f"Internal/gated network ({ctx.network_exposure}): "
                    f"CVSS Modified Attack Vector lowers {old} → {sev}."
                )
    elif env == "unknown" and maturity not in ("confirmed", "reproduced"):
        old = sev
        sev = _cap(sev, _SEV_ORDER[max(0, _sev_idx(ceiling) - 1)])
        if sev != old:
            ctx.impact_notes.append(
                f"Unknown environment + unconfirmed: penalized {old} → {sev}. "
                f"Set environment= or confirm the exploit for the full band."
            )

    ctx.inferred_severity = sev
    ctx.severity_color = _SEV_TO_COLOR.get(sev, "YELLOW")

    # Bug-bounty reality check
    if ctx.verdict == "REPORT" and sev in ("LOW", "INFO"):
        ctx.impact_notes.append(
            "SUBMIT-AS-IS RISK: LOW/INFO findings are closed Informative by most "
            "programs. Before submitting, spend one cycle on escalation — what "
            "does this ENABLE? (propose_chains / research_attack_vector). Report "
            "the chain, not the primitive."
        )
