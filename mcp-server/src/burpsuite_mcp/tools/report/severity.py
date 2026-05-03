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
SEVERITY_CAPS = {
    # key (substring of vuln_type/title) → max allowed severity
    "clickjacking": "LOW",
    "missing security header": "INFO",
    "missing header": "INFO",
    "cookie flag": "INFO",
    "cookie without secure": "INFO",
    "cookie without httponly": "INFO",
    "csrf on logout": "INFO",
    "csrf on non-state": "INFO",
    "mixed content": "INFO",
    "rate limit": "LOW",
    "stack trace": "LOW",
    "information disclosure": "LOW",
    "info disclosure": "LOW",
    "user enumeration": "LOW",
    "username enumeration": "LOW",
    "email enumeration": "LOW",
    "referrer-policy": "INFO",
    "spf": "INFO",
    "dmarc": "INFO",
    "dkim": "INFO",
    "content spoofing": "LOW",
    "text injection": "INFO",
    "self-xss": "INFO",
    "self xss": "INFO",
    "tabnabbing": "INFO",
    "autocomplete": "INFO",
    "options method": "INFO",
    "version disclosure": "LOW",
    "idn homograph": "INFO",
    "open redirect": "LOW",   # MEDIUM only when chained — caller passes the chain context
}

SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def severity_sort_key(severity: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(severity.upper(), 5)


def honest_severity(claimed: str, vuln_type: str, title: str, evidence: str, impact: str) -> tuple[str, str]:
    """Return (capped_severity, note). Honest-severity enforcement per Rule 21.

    If the finding shows chain evidence, the cap is relaxed one step.
    """
    claimed_up = (claimed or "MEDIUM").upper()
    if claimed_up not in SEVERITY_RANK:
        claimed_up = "MEDIUM"

    haystack = f"{vuln_type} {title}".lower()
    chain_hint = any(w in f"{evidence} {impact}".lower() for w in
                     ("chained with", "escalated via", "chain ->", "chain to", "→ account takeover"))

    for key, cap in SEVERITY_CAPS.items():
        if key in haystack:
            cap_up = cap
            if chain_hint:
                ranks = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
                cap_up = ranks[min(ranks.index(cap) + 1, 4)]
            if SEVERITY_RANK[claimed_up] > SEVERITY_RANK[cap_up]:
                note = f"Severity capped at {cap_up} ({key} alone is informative; requested {claimed_up})"
                return cap_up, note
            return claimed_up, ""
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
