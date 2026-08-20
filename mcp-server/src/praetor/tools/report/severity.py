"""Honest severity capping + CVSS 4.0 vector hints.

CVSS 4.0 metric reference:
  Base: AV (N/A/L/P), AC (L/H), AT (N/P), PR (N/L/H), UI (N/P/A)
        VC/VI/VA (H/L/N) — Vulnerable System impact
        SC/SI/SA (H/L/N) — Subsequent System impact
  Calculator: https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator
"""

CVSS4_CALCULATOR_URL = "https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator"

# Severity caps for vulnerability classes that are informative at best
# (hunting.md NEVER SUBMIT list + low-impact classes). A hunter can still
# submit if they've escalated via chain-findings, but the solo report severity
# is capped so the triager sees an honest label.
# Caps are applied via VULN_TYPE FIRST (exact match on the canonical vuln_type
# string), then a narrow title-substring fallback. The previous bare-substring
# match captured legitimate XSS findings whose title incidentally said
# "missing security header" or "info disclosure", silently capping a real bug
# to INFO/LOW. The two-tier approach keeps the operator's labelled vuln_type
# authoritative.
SEVERITY_CAPS_BY_VULN_TYPE = {
    "clickjacking": "LOW",
    "missing_security_header": "INFO",
    "missing_csp": "INFO",
    "missing_hsts": "INFO",
    "missing_x_frame_options": "INFO",
    "cookie_flag": "INFO",
    "cookie_without_secure": "INFO",
    "cookie_without_httponly": "INFO",
    "csrf_logout": "INFO",
    "mixed_content": "INFO",
    "rate_limit_missing": "LOW",
    "stack_trace": "LOW",
    "information_disclosure": "LOW",
    "info_disclosure": "LOW",
    "user_enumeration": "LOW",
    "username_enumeration": "LOW",
    "email_enumeration": "LOW",
    "referrer_policy_missing": "INFO",
    "spf": "INFO",
    "dmarc": "INFO",
    "dkim": "INFO",
    "content_spoofing": "LOW",
    "text_injection": "INFO",
    "self_xss": "INFO",
    "tabnabbing": "INFO",
    "autocomplete_off_missing": "INFO",
    "options_method_enabled": "INFO",
    "version_disclosure": "LOW",
    "idn_homograph": "INFO",
    "open_redirect_no_chain": "LOW",
    "open_redirect": "LOW",
    "cors_no_credentials": "LOW",
}

# Title-substring caps — applied ONLY when the operator did not pass an explicit
# vuln_type. Conservative list (clear-cut categories that operators rarely mis-tag).
SEVERITY_CAPS_BY_TITLE = {
    "self-xss": "INFO",
    "self xss": "INFO",
    "spf record": "INFO",
    "dmarc record": "INFO",
    "dkim record": "INFO",
}

# Backward-compat alias for any older callers reaching SEVERITY_CAPS directly.
SEVERITY_CAPS = SEVERITY_CAPS_BY_VULN_TYPE

SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

# Platform severity tiers (HackerOne's scheme, which Bugcrowd/Intigriti track
# closely). The CVSS vector maps technical exploitability to a band; the tier is
# what a triager actually pays against, adjusted for the program's own assets.
#
# Note the floor: the scale starts at LOW. There is no INFO tier — an
# informational observation is not a low-severity finding, it is not a finding.
# That is why save_finding refuses INFO rather than filing it.
SEVERITY_TIERS = {
    "LOW": "minimal impact, hard to exploit, or limited information disclosure",
    "MEDIUM": "moderate security compromise, restricted access, or standard "
              "rate-limiting issues",
    "HIGH": "significant data exposure, privilege escalation, or a core "
            "component bypass",
    "CRITICAL": "remote code execution, full system compromise, or direct "
                "unauthenticated access to sensitive data",
}


def tier_guidance(exclude_info: bool = True) -> str:
    """Render the tier definitions for a gate message."""
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    lines = [f"    {t:9}{SEVERITY_TIERS[t]}" for t in order]
    if not exclude_info:
        lines.insert(0, "    INFO     not a severity tier — not a finding")
    return "\n".join(lines)


def severity_sort_key(severity: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(severity.upper(), 5)


def sort_findings_by_risk(findings: list[dict]) -> list[dict]:
    """Order findings worst-first: severity band, then CVSS band, then confidence.

    Applied on every write so a severity change reorders the board immediately.
    Ties fall back to the finding ID, keeping the order stable across saves.
    """
    def key(f: dict):
        return (
            severity_sort_key(str(f.get("severity") or "INFO")),
            severity_sort_key(str(f.get("cvss4_severity") or f.get("severity") or "INFO")),
            -float(f.get("confidence") or 0.0),
            str(f.get("id") or ""),
        )
    return sorted(findings, key=key)


def honest_severity(claimed: str, vuln_type: str, title: str, evidence: str, impact: str) -> tuple[str, str]:
    """Return (capped_severity, note). Honest-severity enforcement per Rule 21.

    Two-tier cap: vuln_type exact match wins; if no vuln_type or no match,
    fall back to a tight title-substring set. This avoids the previous
    behaviour of capping a real XSS to INFO because its title incidentally
    contained "missing security header" / "info disclosure" / etc.

    If the finding shows chain evidence, the cap is relaxed one step.
    """
    claimed_up = (claimed or "MEDIUM").upper()
    if claimed_up not in SEVERITY_RANK:
        claimed_up = "MEDIUM"

    chain_hint = any(w in f"{evidence} {impact}".lower() for w in
                     ("chained with", "escalated via", "chain ->", "chain to",
                      "→ account takeover", "→ ato", "led to ato",
                      "framed funds-transfer", "framed 2fa", "framed oauth consent"))

    cap = None
    matched_key = None

    # Tier 1: exact vuln_type match (operator-controlled label is authoritative)
    vt = (vuln_type or "").strip().lower()
    if vt and vt in SEVERITY_CAPS_BY_VULN_TYPE:
        cap = SEVERITY_CAPS_BY_VULN_TYPE[vt]
        matched_key = vt

    # Tier 2: title-substring fallback ONLY when no vuln_type (or vuln_type didn't match)
    if cap is None:
        title_l = (title or "").lower()
        for key, c in SEVERITY_CAPS_BY_TITLE.items():
            if key in title_l:
                cap = c
                matched_key = key
                break

    if cap is None:
        return claimed_up, ""

    cap_up = cap
    if chain_hint:
        ranks = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        cap_up = ranks[min(ranks.index(cap) + 1, 4)]
    if SEVERITY_RANK[claimed_up] > SEVERITY_RANK[cap_up]:
        note = f"Severity capped at {cap_up} ({matched_key} alone is informative; requested {claimed_up})"
        return cap_up, note
    return claimed_up, ""


# CVSS 4.0 qualitative bands -> Praetor severity labels.
_BAND_TO_SEVERITY = {
    "Critical": "CRITICAL",
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "None": "INFO",
}


def cvss4_for_finding(
    vuln_type: str,
    evidence: dict | None = None,
    explicit_vector: str = "",
) -> tuple[str, str]:
    """Return (vector, severity_label) for a finding.

    The vector is derived from the vulnerability class and the finding's own
    shape flags (requires_auth, requires_interaction, oob_only,
    subsequent_impact) — never from the severity label. Deriving the vector
    from the severity made the two agree by construction and told the reader
    nothing; a vector that disagrees with the claimed severity is the signal
    worth having.

    `explicit_vector` wins when it parses; an unparseable one falls back to the
    derived vector rather than propagating a malformed string into a report.
    """
    from praetor.tools.advisor import _cvss4

    vector = ""
    if explicit_vector:
        try:
            _cvss4.parse_vector(explicit_vector)
            vector = explicit_vector
        except ValueError:
            vector = ""
    if not vector:
        vector = _cvss4.build_vector(vuln_type or "", evidence=evidence or {})

    try:
        band = _cvss4.severity_band(vector)
    except ValueError:
        return vector, ""
    return vector, _BAND_TO_SEVERITY.get(band, "")


def severity_cap_for(vuln_type: str, title: str = "") -> str:
    """Return the honest-severity cap for a class, or '' when uncapped."""
    vt = (vuln_type or "").strip().lower()
    if vt and vt in SEVERITY_CAPS_BY_VULN_TYPE:
        return SEVERITY_CAPS_BY_VULN_TYPE[vt]
    title_l = (title or "").lower()
    for key, cap in SEVERITY_CAPS_BY_TITLE.items():
        if key in title_l:
            return cap
    return ""


# The band comes from _cvss4.band_from_macrovector, which the module documents
# as APPROXIMATE — exact numeric scoring needs FIRST's full reference table.
# Measured against known shapes it lands within one band (an unauthenticated
# VC:L leak reads Medium where policy says LOW; a PR:L VC:H IDOR reads Medium
# where triagers pay HIGH). Gating on a one-band gap would therefore fight the
# approximation instead of the operator, and would block the authorization and
# injection findings this tool exists to produce. Two bands apart is a real
# disagreement: no rounding error turns an INFO-shaped vector into a HIGH claim.
CVSS_BAND_TOLERANCE = 1


def severity_cvss_conflict(claimed: str, cvss_severity: str, cap: str = "") -> str:
    """Describe a claimed-severity / CVSS-band disagreement. '' when consistent.

    Inflation conflicts once the gap exceeds the scorer's tolerance: claiming
    HIGH on an INFO-shaped vector is what Rule 14 bans and what a triager
    downgrades on sight.

    Understatement is additionally exempt for capped classes. CVSS 4.0 scores
    any unauthenticated network-reachable confidentiality leak Medium, so an
    honest-severity cap (info disclosure -> LOW, missing header -> INFO) sits
    below its own vector by design. Treating that as an error would force every
    capped class *up* a band — the exact inflation the cap exists to prevent.
    """
    claimed_up = (claimed or "").upper()
    if not cvss_severity or claimed_up not in SEVERITY_RANK:
        return ""
    delta = SEVERITY_RANK[claimed_up] - SEVERITY_RANK[cvss_severity]
    if abs(delta) <= CVSS_BAND_TOLERANCE:
        return ""
    if delta < 0:
        cap_up = (cap or "").upper()
        if cap_up in SEVERITY_RANK and SEVERITY_RANK[claimed_up] <= SEVERITY_RANK[cap_up]:
            return ""
        return (
            f"severity {claimed_up} is {abs(delta)} bands below the CVSS 4.0 "
            f"vector, which scores {cvss_severity}"
        )
    return (
        f"severity {claimed_up} is {delta} bands above the CVSS 4.0 "
        f"vector, which scores {cvss_severity}"
    )
