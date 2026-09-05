"""Canonical security-standard checklists + class->category rollup.

The assurance heatmap answers "what did we NOT test" against a *fixed*
checklist, so every category of a standard is listed even when no Praetor
vuln class touched it. Class->category resolution reuses the already-tested
`framework_tags` (alias + suffix resolution) and, for API Top 10 / compliance
control codes, `data/compliance_mappings.json`.

Data only + pure functions. No Burp client, no network.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from .._framework_map import framework_tags
from .._vuln_class import canonical

# Authoritative checklists. Order is display order.
STANDARDS: dict[str, dict[str, Any]] = {
    "owasp_top10": {
        "name": "OWASP Top 10 (2021)",
        "categories": {
            "A01": "Broken Access Control",
            "A02": "Cryptographic Failures",
            "A03": "Injection",
            "A04": "Insecure Design",
            "A05": "Security Misconfiguration",
            "A06": "Vulnerable and Outdated Components",
            "A07": "Identification and Authentication Failures",
            "A08": "Software and Data Integrity Failures",
            "A09": "Security Logging and Monitoring Failures",
            "A10": "Server-Side Request Forgery (SSRF)",
        },
    },
    "api_top10": {
        "name": "OWASP API Security Top 10 (2023)",
        "categories": {
            "API1": "Broken Object Level Authorization",
            "API2": "Broken Authentication",
            "API3": "Broken Object Property Level Authorization",
            "API4": "Unrestricted Resource Consumption",
            "API5": "Broken Function Level Authorization",
            "API6": "Unrestricted Access to Sensitive Business Flows",
            "API7": "Server Side Request Forgery",
            "API8": "Security Misconfiguration",
            "API9": "Improper Inventory Management",
            "API10": "Unsafe Consumption of APIs",
        },
    },
    "wstg": {
        "name": "OWASP WSTG v4.2",
        "categories": {
            "INFO": "Information Gathering",
            "CONF": "Configuration and Deployment Management",
            "IDNT": "Identity Management",
            "ATHN": "Authentication",
            "ATHZ": "Authorization",
            "SESS": "Session Management",
            "INPV": "Input Validation",
            "ERRH": "Error Handling",
            "CRYP": "Cryptography",
            "BUSL": "Business Logic",
            "CLNT": "Client-side",
            "APIT": "API Testing",
        },
    },
}

_COMPLIANCE_PATH = (
    Path(__file__).resolve().parent.parent.parent / "data" / "compliance_mappings.json"
)


@lru_cache(maxsize=1)
def _compliance() -> dict[str, dict[str, Any]]:
    """vuln_type -> {owasp, pci_dss_v4, soc2_t2, hipaa, gdpr, cwe}. Fail-safe empty."""
    try:
        data = json.loads(_COMPLIANCE_PATH.read_text())
        return data.get("mappings", {}) or {}
    except (OSError, ValueError):
        return {}


def _owasp_codes(vuln_class: str) -> list[str]:
    """All OWASP/API codes for a class, from framework map + compliance file."""
    codes: list[str] = []
    web = framework_tags(vuln_class).get("owasp") or ""
    if web:
        codes.append(web)
    entry = _compliance().get(canonical(vuln_class)) or {}
    for code in entry.get("owasp", []) or []:
        codes.append(code)
    return codes


def category_of(standard: str, vuln_class: str) -> str | None:
    """Roll a Praetor vuln class up to a standard's category id, or None.

    Raises KeyError for an unknown standard so callers fail loudly.
    """
    if standard not in STANDARDS:
        raise KeyError(standard)

    if standard == "wstg":
        wstg = framework_tags(vuln_class).get("wstg") or ""
        if not wstg:
            return None
        # WSTG-INPV-05 -> INPV
        parts = wstg.split("-")
        cat = parts[1] if len(parts) >= 2 else ""
        return cat if cat in STANDARDS["wstg"]["categories"] else None

    prefix = "API" if standard == "api_top10" else "A"
    for code in _owasp_codes(vuln_class):
        # "A03:2021-Injection" -> "A03"; "API1:2023" -> "API1"
        head = code.split(":")[0].strip()
        if standard == "api_top10" and head.startswith("API"):
            return head if head in STANDARDS["api_top10"]["categories"] else None
        if standard == "owasp_top10" and head.startswith("A") and not head.startswith("API"):
            return head if head in STANDARDS["owasp_top10"]["categories"] else None
    return None
