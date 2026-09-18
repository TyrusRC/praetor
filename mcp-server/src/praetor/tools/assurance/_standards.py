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
        "name": "OWASP Top 10 (2025)",
        "categories": {
            "A01": "Broken Access Control",
            "A02": "Security Misconfiguration",
            "A03": "Software Supply Chain Failures",
            "A04": "Cryptographic Failures",
            "A05": "Injection",
            "A06": "Insecure Design",
            "A07": "Authentication Failures",
            "A08": "Software or Data Integrity Failures",
            "A09": "Security Logging and Alerting Failures",
            "A10": "Mishandling of Exceptional Conditions",
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
    "mastg": {
        "name": "OWASP MASVS v2 (Mobile / MASTG)",
        "categories": {
            "STORAGE": "Data Storage",
            "CRYPTO": "Cryptography",
            "AUTH": "Authentication and Authorization",
            "NETWORK": "Network Communication",
            "PLATFORM": "Platform Interaction",
            "CODE": "Code Quality",
            "RESILIENCE": "Resilience Against Reverse Engineering and Tampering",
            "PRIVACY": "Privacy",
        },
    },
    "ai_testing": {
        "name": "OWASP AI Testing Guide",
        "categories": {
            "APP": "AI Application Testing",
            "MODEL": "AI Model Testing",
            "INFRA": "AI Infrastructure Testing",
            "DATA": "AI Data Testing",
        },
    },
}

# The framework map still tags classes with OWASP Top 10 2021 codes; the 2025
# revision renumbered and merged categories (SSRF folded into A01; Components ->
# Software Supply Chain A03; Misconfig A05->A02; etc.). Translate on read so the
# rollup keeps working without re-tagging every vuln class.
_OWASP_2021_TO_2025 = {
    "A01": "A01", "A02": "A04", "A03": "A05", "A04": "A06", "A05": "A02",
    "A06": "A03", "A07": "A07", "A08": "A08", "A09": "A09", "A10": "A01",
}

# Keyword -> category rollups for the mobile (MASVS) and AI standards, since the
# framework map does not yet carry masvs/ai tags. Matched against the canonical
# vuln-class name. Best-effort: a class that matches nothing stays untested (an
# explicit checklist gap), never mis-bucketed.
_MASTG_KEYWORDS: dict[str, tuple[str, ...]] = {
    "STORAGE": ("storage", "backup", "logcat", "keychain", "sharedpref", "sqlite_plain"),
    "CRYPTO": ("crypto", "cipher", "hardcoded_key", "weak_random", "insecure_hash"),
    "AUTH": ("auth", "biometric", "oauth", "jwt", "session"),
    "NETWORK": ("pinning", "tls", "cleartext", "mitm", "network", "cert"),
    "PLATFORM": ("intent", "deeplink", "exported", "webview", "ipc", "clipboard", "screenshot"),
    "CODE": ("code_quality", "debuggable", "obfusc", "memory_corruption", "injection"),
    "RESILIENCE": ("root", "jailbreak", "tamper", "reverse", "frida", "hook", "emulator", "anti_debug"),
    "PRIVACY": ("privacy", "pii", "consent", "tracking", "permission"),
}
_AI_KEYWORDS: dict[str, tuple[str, ...]] = {
    "APP": ("prompt_injection", "jailbreak", "system_prompt_leak", "llm", "insecure_output",
            "excessive_agency", "agentic", "sensitive_disclosure", "hallucination"),
    "MODEL": ("evasion", "model_poison", "membership_inference", "inversion", "adversarial",
              "robustness", "goal_alignment"),
    "INFRA": ("supply_chain", "plugin", "resource_exhaust", "model_theft", "fine_tuning"),
    "DATA": ("training_data", "data_exfil", "data_leak", "dataset", "data_minimization"),
}


def _keyword_category(keywords: dict[str, tuple[str, ...]], vuln_class: str,
                      valid: dict[str, str]) -> str | None:
    cls = (vuln_class or "").lower()
    for cat, kws in keywords.items():
        if cat in valid and any(k in cls for k in kws):
            return cat
    return None

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

    if standard == "mastg":
        masvs = framework_tags(vuln_class).get("masvs") or ""
        if masvs:  # MASVS-STORAGE-1 -> STORAGE
            parts = masvs.split("-")
            cat = parts[1] if len(parts) >= 2 else ""
            if cat in STANDARDS["mastg"]["categories"]:
                return cat
        return _keyword_category(_MASTG_KEYWORDS, vuln_class,
                                 STANDARDS["mastg"]["categories"])

    if standard == "ai_testing":
        ai = framework_tags(vuln_class).get("ai") or ""
        if ai and ai in STANDARDS["ai_testing"]["categories"]:
            return ai
        return _keyword_category(_AI_KEYWORDS, vuln_class,
                                 STANDARDS["ai_testing"]["categories"])

    for code in _owasp_codes(vuln_class):
        # "A03:2021-Injection" -> "A03"; "API1:2023" -> "API1"
        head = code.split(":")[0].strip()
        if standard == "api_top10" and head.startswith("API"):
            return head if head in STANDARDS["api_top10"]["categories"] else None
        if standard == "owasp_top10" and head.startswith("A") and not head.startswith("API"):
            # framework map tags with 2021 codes; the checklist is 2025.
            head = _OWASP_2021_TO_2025.get(head, head)
            return head if head in STANDARDS["owasp_top10"]["categories"] else None
    return None
