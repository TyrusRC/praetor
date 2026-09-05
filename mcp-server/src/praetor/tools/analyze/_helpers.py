"""Security-header scoring constant + helper for analyze tools."""

from praetor import client


# Security header scoring with severity and description
_SECURITY_HEADERS = {
    "Content-Security-Policy": {"severity": "HIGH", "desc": "Prevents XSS and data injection attacks"},
    "Strict-Transport-Security": {"severity": "HIGH", "desc": "Enforces HTTPS connections"},
    "X-Content-Type-Options": {"severity": "MEDIUM", "desc": "Prevents MIME-type sniffing"},
    "X-Frame-Options": {"severity": "MEDIUM", "desc": "Prevents clickjacking attacks"},
    "Permissions-Policy": {"severity": "LOW", "desc": "Controls browser feature access"},
    "Referrer-Policy": {"severity": "LOW", "desc": "Controls referrer information leakage"},
    "X-XSS-Protection": {"severity": "INFO", "desc": "Legacy XSS filter (deprecated but shows awareness)"},
    "Cross-Origin-Opener-Policy": {"severity": "LOW", "desc": "Isolates browsing context"},
    "Cross-Origin-Resource-Policy": {"severity": "LOW", "desc": "Controls cross-origin resource loading"},
}


def _score_security_headers(present: list[str], missing: list[str]) -> str:
    """Generate security header score card."""
    lines = ["\nSECURITY HEADER SCORE:"]
    score = 0
    total = len(_SECURITY_HEADERS)

    for header, info in _SECURITY_HEADERS.items():
        found = any(header.lower() in p.lower() for p in present)
        if found:
            score += 1
            lines.append(f"  + {header}")
        else:
            lines.append(f"  - {header}: MISSING ({info['severity']}) -- {info['desc']}")

    pct = (score / total * 100) if total > 0 else 0
    if pct >= 80:
        grade = "A"
    elif pct >= 60:
        grade = "B"
    elif pct >= 40:
        grade = "C"
    elif pct >= 20:
        grade = "D"
    else:
        grade = "F"

    lines.append(f"\n  Grade: {grade} ({score}/{total} headers present)")

    high_missing = [h for h, info in _SECURITY_HEADERS.items()
                    if info["severity"] == "HIGH" and not any(h.lower() in p.lower() for p in present)]
    if high_missing:
        lines.append(f"  Reportable: Missing {', '.join(high_missing)}")

    return "\n".join(lines)
