"""Row constructor + default row for the framework lookup table (helpers only)."""

from __future__ import annotations

from typing import Any


_DEFAULT_ROW: dict[str, Any] = {
    "attack_ck": [],      # list[str] of MITRE ATT&CK / ATLAS technique IDs
    "attack_name": "",    # human name of the primary technique
    "wstg": "",           # OWASP WSTG test id (or "")
    "owasp": "",          # OWASP Top 10 2021 category
    "cwe": "",            # primary CWE id
    "detection": {},      # {sigma, spl, kql}
}


def _row(
    attack_ck: list[str],
    attack_name: str,
    wstg: str,
    owasp: str,
    cwe: str,
    sigma: str,
    spl: str,
    kql: str,
) -> dict[str, Any]:
    return {
        "attack_ck": attack_ck,
        "attack_name": attack_name,
        "wstg": wstg,
        "owasp": owasp,
        "cwe": cwe,
        "detection": {"sigma": sigma, "spl": spl, "kql": kql},
    }

