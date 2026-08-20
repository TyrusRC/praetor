"""Framework tagging + blue-team detection pairing for Praetor findings (W34-b).

ONE lookup table keyed by `vuln_type`. Turns a red-team finding into a
purple-team deliverable: each class carries its MITRE ATT&CK technique,
OWASP WSTG test id, OWASP Top 10 2021 category, primary CWE, and a paired
Sigma / Splunk-SPL / Microsoft-KQL detection rule describing how a defender
spots THIS attack in web / proxy / WAF logs.

Design (lazy/surgical): the 150 KB JSON files are NOT edited. This module is
pure data + a fuzzy resolver so consumers (report builder, SARIF exporter)
call one function.

Sources:
  - MITRE ATT&CK Enterprise v15 technique IDs (real IDs only). Web LLM classes
    use MITRE ATLAS (AML.T*) which is the ATT&CK-aligned adversarial-ML matrix.
  - OWASP WSTG v4.2 test ids (WSTG-<category>-<nn>).
  - OWASP Top 10 2021.
  - CWE primary weakness.

`framework_tags(vuln_type)` resolves exact → alias → suffix-strip → prefix
fallback, and always returns a well-formed row (empty defaults if unknown).
"""


from __future__ import annotations

from typing import Any

from ._data import FRAMEWORK_MAP, _ALIASES, _DEFAULT_ROW, _STRIP_SUFFIXES


def framework_tags(vuln_type: str) -> dict[str, Any]:
    """Return the framework-tagging row for a Praetor ``vuln_type``.

    Resolution order:
      1. exact match in FRAMEWORK_MAP
      2. alias table
      3. suffix stripping (``sqli_blind`` -> ``sqli``), re-checking map + aliases
      4. first-token prefix (``sqli_something`` -> ``sqli``)
    Always returns a well-formed row; unknown classes get empty defaults so
    callers never KeyError. Returned dict is a shallow-independent copy.

    Args:
        vuln_type: finding vuln_type / vulnerability class (case-insensitive).
    """
    if not vuln_type or not isinstance(vuln_type, str):
        return _copy_row(_DEFAULT_ROW)

    key = vuln_type.strip().lower()

    row = _lookup(key)
    if row is not None:
        return _copy_row(row)

    # 3. progressively strip known suffixes.
    stripped = key
    changed = True
    while changed:
        changed = False
        for suf in _STRIP_SUFFIXES:
            if stripped.endswith(suf) and len(stripped) > len(suf):
                stripped = stripped[: -len(suf)]
                changed = True
                row = _lookup(stripped)
                if row is not None:
                    return _copy_row(row)

    # 4. first-token prefix fallback (e.g. "sqli_second_order" -> "sqli").
    if "_" in key:
        head = key.split("_", 1)[0]
        row = _lookup(head)
        if row is not None:
            return _copy_row(row)

    return _copy_row(_DEFAULT_ROW)


def _lookup(key: str) -> dict[str, Any] | None:
    """Exact or alias lookup. Returns the shared row (caller must copy)."""
    if key in FRAMEWORK_MAP:
        return FRAMEWORK_MAP[key]
    alias = _ALIASES.get(key)
    if alias and alias in FRAMEWORK_MAP:
        return FRAMEWORK_MAP[alias]
    return None


def _copy_row(row: dict[str, Any]) -> dict[str, Any]:
    """Independent copy so mutation by a caller never corrupts the table."""
    return {
        "attack_ck": list(row["attack_ck"]),
        "attack_name": row["attack_name"],
        "wstg": row["wstg"],
        "owasp": row["owasp"],
        "cwe": row["cwe"],
        "detection": dict(row["detection"]),
    }


def attack_tag_list(vuln_type: str) -> list[str]:
    """SARIF/tag-friendly flat tags: ``['attack:T1190','wstg:WSTG-INPV-05','cwe:CWE-89']``."""
    row = framework_tags(vuln_type)
    tags = [f"attack:{t}" for t in row["attack_ck"]]
    if row["wstg"]:
        tags.append(f"wstg:{row['wstg']}")
    if row["cwe"]:
        tags.append(f"cwe:{row['cwe']}")
    return tags

__all__ = ["framework_tags", "attack_tag_list", "FRAMEWORK_MAP"]
