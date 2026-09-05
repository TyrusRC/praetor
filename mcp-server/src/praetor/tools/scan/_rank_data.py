"""rank_attack_targets — scoring weights, endpoint/param scorers, vuln-class map.

Data + pure helpers extracted from rank_targets.py; the tool logic stays there
and re-exports these names.
"""

from __future__ import annotations

import json
from typing import Any

from praetor.tools.notes._helpers import _intel_dir, _sanitized

from ._helpers import _classify_param_risk

_ENDPOINT_PATH_WEIGHT: dict[str, int] = {
    "admin": 35, "manage": 30, "dashboard": 25, "internal": 35,
    "payment": 35, "checkout": 30, "billing": 30, "subscription": 28,
    "transfer": 35, "withdraw": 35, "refund": 30,
    "login": 30, "signin": 28, "signup": 22, "register": 22, "auth": 28,
    "oauth": 32, "token": 30, "password": 30, "reset": 30, "verify": 25,
    "upload": 25, "download": 22, "import": 22, "export": 22,
    "graphql": 20, "rpc": 18, "api": 8,
    "user": 12, "account": 15, "profile": 12,
    "settings": 15, "config": 18, "preferences": 12,
    "search": 8, "query": 8, "filter": 8,
}

_METHOD_WEIGHT: dict[str, int] = {
    "POST": 15, "PUT": 15, "PATCH": 15, "DELETE": 12,
    "GET": 5, "HEAD": 1, "OPTIONS": 0,
}

_LOCATION_WEIGHT: dict[str, int] = {
    "body_json": 15, "body_form": 12, "body_xml": 12,
    "query": 8, "cookie": 5, "header": 6, "path": 14,
}


def _endpoint_score(path: str) -> tuple[int, list[str]]:
    """Score endpoint path + return matched keywords (for explainability)."""
    p = path.lower()
    score = 0
    hits: list[str] = []
    for kw, w in _ENDPOINT_PATH_WEIGHT.items():
        if f"/{kw}" in p or f"{kw}/" in p or f"-{kw}" in p or f"_{kw}" in p:
            score += w
            hits.append(kw)
    return score, hits


def _param_score(name: str) -> tuple[int, list[str]]:
    risks = _classify_param_risk(name)
    if risks == ["BASELINE_PROBE"]:
        return 4, []
    return 8 + 6 * len(risks), risks


def _load_endpoints(domain: str) -> list[dict[str, Any]]:
    path = _intel_dir() / _sanitized(domain) / "endpoints.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    if isinstance(data, list):
        return data
    return data.get("endpoints") or data.get("targets") or []


# vuln_class user token → uppercase substring that should appear in _classify_param_risk output
_VULN_CLASS_TOKEN_MAP = {
    "sqli": "SQLI", "xss": "XSS", "idor": "IDOR", "ssrf": "SSRF",
    "open_redirect": "REDIRECT", "redirect": "REDIRECT", "lfi": "LFI",
    "rce": "CMDI", "cmdi": "CMDI", "command_injection": "CMDI", "ssti": "SSTI",
    "xxe": "XXE", "upload": "UPLOAD", "file_upload": "UPLOAD",
    "deserialization": "DESERIALIZATION", "nosql": "NOSQL", "jwt": "JWT",
    "auth": "AUTH", "authentication": "AUTHENTICATION", "mass_assignment": "MASS",
    "bfla": "MASS", "graphql": "GRAPHQL", "prototype_pollution": "PROTOTYPE",
    "pp": "PROTOTYPE", "oauth": "OAUTH", "oidc": "OAUTH", "cache_key": "CACHE",
    "saml": "SAML", "business_logic": "BUSINESS", "web_llm": "WEB/LLM",
    "llm": "WEB/LLM", "host_header": "HOST", "second_order": "SECOND",
    "ldap": "LDAP", "ldap_injection": "LDAP", "xpath": "XPATH",
    "xpath_injection": "XPATH", "ssi": "SSI", "ssi_injection": "SSI",
    "xslt": "XSLT", "xslt_injection": "XSLT", "css_injection": "CSS",
    "idor_uuid": "UUID",
}


def _vuln_class_to_risk_token(cls: str) -> str:
    """Map a user vuln_class token to the substring that should appear in classify output."""
    if cls in _VULN_CLASS_TOKEN_MAP:
        return _VULN_CLASS_TOKEN_MAP[cls]
    return cls.upper().replace("_", "/")


def _matches_vuln_class(risks: list[str], token: str) -> bool:
    """True if any risk label contains the target token (substring, uppercase)."""
    if not risks or risks == ["BASELINE_PROBE"]:
        return False
    return any(token in r for r in risks)
