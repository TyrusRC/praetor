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


def severity_sort_key(severity: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(severity.upper(), 5)


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


def cvss_v4_vector(severity: str) -> str:
    """Return a CVSS 4.0 base vector hint for each severity band.

    Reporters MUST replace with target-specific metrics (AT, PR, UI,
    SC/SI/SA) using the calculator. These are floor-level placeholders.
    """
    sev = severity.upper()
    if sev == "CRITICAL":
        return "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    if sev == "HIGH":
        return "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    if sev == "MEDIUM":
        return "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
    if sev == "LOW":
        return "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
    return "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
