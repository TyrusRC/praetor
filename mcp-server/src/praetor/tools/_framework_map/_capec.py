"""CWE → primary CAPEC attack-pattern derivation (no per-row edits).

CAPEC ids are derived 1:1 from the primary CWE already stored in each
FRAMEWORK_MAP row, so the 43 topical rows never change. A CWE with no clean,
single primary attack pattern is deliberately absent → the resolver returns ""
and no `capec:` tag is emitted. Ids are real MITRE CAPEC v3.9 entries.
"""

from __future__ import annotations

# CWE -> the single most representative CAPEC attack pattern.
_CWE_CAPEC: dict[str, str] = {
    "CWE-22": "CAPEC-126",    # Path Traversal
    "CWE-78": "CAPEC-88",     # OS Command Injection
    "CWE-79": "CAPEC-63",     # Cross-Site Scripting
    "CWE-89": "CAPEC-66",     # SQL Injection
    "CWE-90": "CAPEC-136",    # LDAP Injection
    "CWE-91": "CAPEC-250",    # XML Injection
    "CWE-93": "CAPEC-105",    # HTTP Request Splitting (CRLF)
    "CWE-94": "CAPEC-242",    # Code Injection
    "CWE-200": "CAPEC-116",   # Excavation / information exposure
    "CWE-235": "CAPEC-460",   # HTTP Parameter Pollution
    "CWE-285": "CAPEC-122",   # Privilege Abuse
    "CWE-287": "CAPEC-115",   # Authentication Bypass
    "CWE-327": "CAPEC-97",     # Cryptanalysis
    "CWE-345": "CAPEC-148",   # Content Spoofing
    "CWE-347": "CAPEC-473",   # Signature Spoofing (JWT/SAML)
    "CWE-350": "CAPEC-141",   # Cache Poisoning (host-header trust)
    "CWE-352": "CAPEC-62",    # Cross-Site Request Forgery
    "CWE-362": "CAPEC-26",    # Leveraging Race Conditions
    "CWE-434": "CAPEC-650",   # Upload a Web Shell to a Web Server
    "CWE-444": "CAPEC-33",    # HTTP Request Smuggling
    "CWE-502": "CAPEC-586",   # Object Injection (deserialization)
    "CWE-540": "CAPEC-116",   # Excavation (info in source)
    "CWE-601": "CAPEC-194",   # Fake the Source of Data (open redirect)
    "CWE-611": "CAPEC-221",   # XML External Entities
    "CWE-613": "CAPEC-60",    # Reusing Session IDs
    "CWE-639": "CAPEC-122",   # Privilege Abuse (IDOR)
    "CWE-644": "CAPEC-105",   # HTTP Request Splitting (header injection)
    "CWE-799": "CAPEC-125",   # Flooding (rate-limit absence)
    "CWE-840": "CAPEC-212",   # Functionality Misuse (business logic)
    "CWE-863": "CAPEC-122",   # Privilege Abuse (incorrect authorization)
    "CWE-915": "CAPEC-77",    # Manipulating User-Controlled Variables (mass assignment)
    "CWE-918": "CAPEC-664",   # Server-Side Request Forgery
    "CWE-1321": "CAPEC-77",   # Manipulating User-Controlled Variables (prototype pollution)
    "CWE-1336": "CAPEC-242",  # Code Injection (SSTI)
    "CWE-1385": "CAPEC-62",   # Cross-Site WebSocket Hijacking (CSRF-class)
}


def capec_for_cwe(cwe: str) -> str:
    """Return the primary CAPEC id for a CWE id, or "" when none is mapped."""
    if not cwe:
        return ""
    return _CWE_CAPEC.get(cwe.strip().upper(), "")
