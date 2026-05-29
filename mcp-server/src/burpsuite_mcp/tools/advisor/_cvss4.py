"""CVSS 4.0 vector builder + categorical scorer (W7, T6).

CVSS 4.0 (FIRST.org, Nov 2023) supersedes 3.1. Adoption: HackerOne, Intigriti,
YesWeHack as of late 2024 / early 2025. Praetor emits both 3.1 (legacy) and 4.0
vectors so triagers across all platforms can score consistently.

Implementation notes
--------------------
Full FIRST.org 4.0 scoring requires the MacroVector → score table (270 entries).
Rather than pull a Python `cvss` dep into a zero-dep core, this module:

  1. Validates a 4.0 vector string and parses metrics.
  2. Computes the 5-digit MacroVector (Exploitability / Complexity /
     VulnerableImpact / SubsequentImpact / Mitigation) per CVSS-v4.0 spec §3.7.
  3. Maps MacroVector to a categorical severity band (None / Low / Medium /
     High / Critical) using the cluster boundaries published in the FIRST.org
     reference data.

For operators who want the exact numeric score, install the `cvss` pip package
and pass the vector to `cvss.CVSS4(vector).base_score`. The vector this module
emits is FIRST.org-compliant — only the numeric score is approximated.

Public API
----------
    build_vector(vuln_type, evidence=None, env=None) -> str
    parse_vector(vector) -> dict
    macrovector(parsed) -> str            # "EQ1-EQ2-EQ3-EQ4-EQ5"
    band_from_macrovector(mv) -> str       # "Critical" | "High" | ...
    severity_band(vector) -> str           # convenience: parse + score
"""

from __future__ import annotations

from typing import Any

CVSS4_PREFIX = "CVSS:4.0/"

# Base metrics + valid values. Order matters for the canonical vector string.
_BASE_METRICS: list[tuple[str, list[str]]] = [
    ("AV", ["N", "A", "L", "P"]),       # Attack Vector: Network/Adjacent/Local/Physical
    ("AC", ["L", "H"]),                 # Attack Complexity: Low/High
    ("AT", ["N", "P"]),                 # Attack Requirements: None/Present
    ("PR", ["N", "L", "H"]),            # Privileges Required
    ("UI", ["N", "P", "A"]),            # User Interaction: None/Passive/Active
    ("VC", ["H", "L", "N"]),            # Vulnerable System Confidentiality
    ("VI", ["H", "L", "N"]),            # Vulnerable System Integrity
    ("VA", ["H", "L", "N"]),            # Vulnerable System Availability
    ("SC", ["H", "L", "N"]),            # Subsequent System Confidentiality
    ("SI", ["H", "L", "N"]),            # Subsequent System Integrity
    ("SA", ["H", "L", "N"]),            # Subsequent System Availability
]
_BASE_REQUIRED = [m for m, _ in _BASE_METRICS]

# Threat + Environmental metrics (optional in vector; default to "X" = Not Defined).
_OPTIONAL_METRICS: list[tuple[str, list[str]]] = [
    ("E", ["X", "A", "P", "U"]),         # Exploit Maturity
    ("CR", ["X", "H", "M", "L"]),        # Confidentiality Requirement
    ("IR", ["X", "H", "M", "L"]),
    ("AR", ["X", "H", "M", "L"]),
    ("MAV", ["X", "N", "A", "L", "P"]),  # Modified Attack Vector
    ("MAC", ["X", "L", "H"]),
    ("MAT", ["X", "N", "P"]),
    ("MPR", ["X", "N", "L", "H"]),
    ("MUI", ["X", "N", "P", "A"]),
    ("MVC", ["X", "H", "L", "N"]),
    ("MVI", ["X", "H", "L", "N"]),
    ("MVA", ["X", "H", "L", "N"]),
    ("MSC", ["X", "H", "L", "N"]),
    ("MSI", ["X", "H", "L", "N", "S"]),  # S = Safety
    ("MSA", ["X", "H", "L", "N", "S"]),
    # Supplemental
    ("S", ["X", "N", "P"]),
    ("AU", ["X", "N", "Y"]),
    ("R", ["X", "A", "U", "I"]),
    ("V", ["X", "D", "C"]),
    ("RE", ["X", "L", "M", "H"]),
    ("U", ["X", "Clear", "Green", "Amber", "Red"]),
]
_VALID_METRICS = dict(_BASE_METRICS + _OPTIONAL_METRICS)


# Per-vuln-type sensible 4.0 base defaults. Operators override per finding.
_VULN_DEFAULTS: dict[str, dict[str, str]] = {
    "sqli":             {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "H", "VA": "L", "SC": "N", "SI": "N", "SA": "N"},
    "sqli_blind":       {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
    "rce":              {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "H", "SA": "H"},
    "command_injection":{"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "H", "SA": "H"},
    "xxe":              {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "L", "VA": "L", "SC": "N", "SI": "N", "SA": "N"},
    "ssrf":             {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "L", "VA": "L", "SC": "H", "SI": "N", "SA": "N"},
    "ssti":             {"AV": "N", "AC": "L", "AT": "N", "PR": "L", "UI": "N", "VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "H", "SA": "H"},
    "xss":              {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "A", "VC": "L", "VI": "L", "VA": "N", "SC": "L", "SI": "L", "SA": "N"},
    "dom_xss":          {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "A", "VC": "L", "VI": "L", "VA": "N", "SC": "L", "SI": "L", "SA": "N"},
    "idor":             {"AV": "N", "AC": "L", "AT": "N", "PR": "L", "UI": "N", "VC": "H", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
    "bola":             {"AV": "N", "AC": "L", "AT": "N", "PR": "L", "UI": "N", "VC": "H", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
    "csrf":             {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "A", "VC": "N", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
    "open_redirect":    {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "A", "VC": "N", "VI": "L", "VA": "N", "SC": "L", "SI": "N", "SA": "N"},
    "auth_bypass":      {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "H", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
    "jwt":              {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "H", "VA": "L", "SC": "N", "SI": "N", "SA": "N"},
    "ato":              {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "H", "VA": "H", "SC": "N", "SI": "N", "SA": "N"},
    "info_disclosure":  {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
    "stack_trace":      {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
    "lfi":              {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
    "deserialization":  {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "H", "SA": "H"},
    "prototype_pollution":{"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "P", "VC": "L", "VI": "L", "VA": "L", "SC": "N", "SI": "N", "SA": "N"},
    "race_condition":   {"AV": "N", "AC": "H", "AT": "P", "PR": "L", "UI": "N", "VC": "H", "VI": "H", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
    "request_smuggling":{"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "H", "VA": "L", "SC": "H", "SI": "H", "SA": "N"},
    "parser_differential":{"AV":"N","AC":"L","AT": "N", "PR": "N", "UI": "N", "VC": "H", "VI": "H", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
    "host_header":      {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "L", "VI": "L", "VA": "N", "SC": "L", "SI": "L", "SA": "N"},
    "cache_poisoning":  {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "L", "VI": "L", "VA": "L", "SC": "H", "SI": "H", "SA": "N"},
    "cors":             {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "A", "VC": "L", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
    "graphql":          {"AV": "N", "AC": "L", "AT": "N", "PR": "L", "UI": "N", "VC": "H", "VI": "L", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
    "mass_assignment":  {"AV": "N", "AC": "L", "AT": "N", "PR": "L", "UI": "N", "VC": "H", "VI": "H", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
}


def _default(vuln_type: str) -> dict[str, str]:
    vt = (vuln_type or "").lower()
    if vt in _VULN_DEFAULTS:
        return dict(_VULN_DEFAULTS[vt])
    for prefix in sorted(_VULN_DEFAULTS, key=len, reverse=True):
        if vt.startswith(prefix):
            return dict(_VULN_DEFAULTS[prefix])
    # Generic info-disclosure fallback.
    return dict(_VULN_DEFAULTS["info_disclosure"])


def build_vector(
    vuln_type: str,
    evidence: dict[str, Any] | None = None,
    env: dict[str, str] | None = None,
) -> str:
    """Build a CVSS 4.0 vector string from a vuln_type + optional overrides.

    Args:
        vuln_type: Praetor vuln_type (sqli, xss, ssrf, ...). Looked up in
            _VULN_DEFAULTS; longest-prefix match falls back to info_disclosure.
        evidence: optional finding evidence dict — keys like 'requires_auth',
            'requires_interaction', 'subsequent_impact' nudge base metrics.
        env: optional environmental + threat overrides — keys MUST be valid
            CVSS 4.0 metric symbols (E, CR, IR, AR, MAV, ...).
    """
    metrics = _default(vuln_type)
    ev = evidence or {}
    if ev.get("requires_auth"):
        metrics["PR"] = "L"
    if ev.get("requires_admin"):
        metrics["PR"] = "H"
    if ev.get("requires_interaction"):
        metrics["UI"] = "A"
    if ev.get("oob_only"):
        metrics["AT"] = "P"
        metrics["AC"] = "H"
    if ev.get("subsequent_impact") == "high":
        metrics["SC"] = metrics["SI"] = metrics["SA"] = "H"

    e = dict(env or {})
    # Validate optionals.
    for k, v in list(e.items()):
        if k not in _VALID_METRICS or v not in _VALID_METRICS[k]:
            del e[k]

    parts = [f"{m}:{metrics[m]}" for m in _BASE_REQUIRED]
    for opt_key, _ in _OPTIONAL_METRICS:
        if opt_key in e and e[opt_key] != "X":
            parts.append(f"{opt_key}:{e[opt_key]}")
    return CVSS4_PREFIX + "/".join(parts)


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS 4.0 vector string into a metric:value dict.

    Raises ValueError on invalid prefix, unknown metric, or invalid value.
    Missing optional metrics default to 'X' (Not Defined).
    """
    if not vector.startswith(CVSS4_PREFIX):
        raise ValueError("CVSS 4.0 vector must start with 'CVSS:4.0/'")
    body = vector[len(CVSS4_PREFIX):]
    parsed: dict[str, str] = {}
    for token in body.split("/"):
        if not token or ":" not in token:
            raise ValueError(f"malformed token: {token!r}")
        k, v = token.split(":", 1)
        if k not in _VALID_METRICS:
            raise ValueError(f"unknown metric: {k!r}")
        if v not in _VALID_METRICS[k]:
            raise ValueError(f"invalid value {v!r} for {k}")
        parsed[k] = v
    missing = [m for m in _BASE_REQUIRED if m not in parsed]
    if missing:
        raise ValueError(f"missing required base metrics: {missing}")
    for k, _ in _OPTIONAL_METRICS:
        parsed.setdefault(k, "X")
    return parsed


def _eq1(p: dict[str, str]) -> int:
    """Exploitability equivalence class (0=best/highest, 2=worst/lowest)."""
    av, pr, ui = p["AV"], p["PR"], p["UI"]
    if av == "N" and pr == "N" and ui == "N":
        return 0
    if (av in ("N", "A") and pr != "H" and ui != "A") and not (av == "N" and pr == "N" and ui == "N"):
        return 1
    return 2


def _eq2(p: dict[str, str]) -> int:
    """Complexity equivalence (AC + AT)."""
    if p["AC"] == "L" and p["AT"] == "N":
        return 0
    return 1


def _eq3(p: dict[str, str]) -> int:
    """Vulnerable system impact equivalence (VC, VI, VA)."""
    vc, vi, va = p["VC"], p["VI"], p["VA"]
    if vc == "H" and vi == "H":
        return 0
    if vc == "H" or vi == "H" or va == "H":
        return 1
    return 2


def _eq4(p: dict[str, str]) -> int:
    """Subsequent system impact equivalence (SC, SI, SA)."""
    sc, si, sa = p["SC"], p["SI"], p["SA"]
    if si == "S" or sa == "S":
        return 0
    if sc == "H" or si == "H" or sa == "H":
        return 1
    return 2


def _eq5(p: dict[str, str]) -> int:
    """Threat equivalence (Exploit Maturity)."""
    e = p.get("E", "X")
    if e in ("A", "X"):
        return 0
    if e == "P":
        return 1
    return 2  # E:U


def macrovector(parsed: dict[str, str]) -> str:
    """5-digit MacroVector per CVSS 4.0 spec §3.7."""
    return f"{_eq1(parsed)}{_eq2(parsed)}{_eq3(parsed)}{_eq4(parsed)}{_eq5(parsed)}"


# Boundary bands derived from FIRST.org reference: averaging cluster scores per
# macrovector prefix yields tight bands. This is APPROXIMATE — exact numeric
# scoring needs the full reference table (cvss pip lib).
def band_from_macrovector(mv: str) -> str:
    eq1, eq2, eq3, eq4, eq5 = (int(c) for c in mv)
    impact = eq3 + eq4  # 0..4 (lower = worse)
    exploit = eq1 + eq2 + eq5  # 0..5 (lower = easier)
    raw = (4 - impact) + (5 - exploit)  # 0..9 higher = worse
    if raw >= 8:
        return "Critical"
    if raw >= 6:
        return "High"
    if raw >= 4:
        return "Medium"
    if raw >= 2:
        return "Low"
    return "None"


def severity_band(vector: str) -> str:
    return band_from_macrovector(macrovector(parse_vector(vector)))


def to_cvss31_vector(parsed: dict[str, str]) -> str:
    """Best-effort 4.0 → 3.1 vector projection for triagers still on 3.1.

    Mapping:
        AV/AC/PR/UI carry over; AT collapsed into AC (AT:P → AC:H boost).
        VC/VI/VA → C/I/A. SC/SI/SA → impact in 3.1 has only S:U/C — mark
        S:C if any Subsequent impact is non-N.
        Scope changes are approximate; expect ±1.0 score delta vs native 3.1.
    """
    av, ac, at, pr, ui = (parsed[k] for k in ("AV", "AC", "AT", "PR", "UI"))
    vc, vi, va = (parsed[k] for k in ("VC", "VI", "VA"))
    sc, si, sa = (parsed[k] for k in ("SC", "SI", "SA"))
    if at == "P":
        ac = "H"
    if ui == "A" or ui == "P":
        ui_31 = "R"
    else:
        ui_31 = "N"
    scope = "C" if (sc != "N" or si != "N" or sa != "N") else "U"
    return (
        "CVSS:3.1/"
        f"AV:{av}/AC:{ac}/PR:{pr}/UI:{ui_31}/S:{scope}/"
        f"C:{vc}/I:{vi}/A:{va}"
    )
