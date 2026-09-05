"""CVSS 4.0 metric tables + vuln-class defaults (data for _cvss4)."""

from __future__ import annotations

CVSS4_PREFIX = "CVSS:4.0/"


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


# Common spellings that carry the same shape as an existing entry. Without
# these, _default() silently fell through to the info_disclosure floor and
# scored an arbitrary-file-read or a stored XSS as a low-confidentiality leak —
# a wrong vector printed with full confidence next to the finding.
_VULN_ALIASES = {
    "path_traversal": "lfi",
    "directory_traversal": "lfi",
    "arbitrary_file_read": "lfi",
    "file_read": "lfi",
    "rfi": "lfi",
    "xss_reflected": "xss",
    "xss_stored": "xss",
    "reflected_xss": "xss",
    "stored_xss": "xss",
    "sqli_error": "sqli",
    "sqli_union": "sqli",
    "sqli_time": "sqli_blind",
    "nosqli": "sqli",
    "bola": "idor",
    "bfla": "idor",
    "broken_object_level_auth": "idor",
    "broken_function_level_auth": "idor",
    "id_enumeration": "idor",
    "account_takeover": "ato",
    "auth_bypass_403_to_200": "auth_bypass",
    "login_bypass": "auth_bypass",
    "privilege_escalation": "auth_bypass",
    "code_injection": "rce",
    "open_redirect_no_chain": "open_redirect",
    "verbose_error": "info_disclosure",
    "information_disclosure": "info_disclosure",
}
