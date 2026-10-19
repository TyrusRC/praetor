"""Systemic-duplicate detection for save_finding: an existing live
finding of the same class at a different endpoint.

Checks both the on-disk findings.json AND Burp's in-memory store so
parallel subagents cannot race past the gate.
"""

from praetor.tools._vuln_class import canonical

from praetor.tools.notes._helpers import _load_findings_file, _safe_findings_path


async def _load_burp_findings() -> list[dict]:
    """Best-effort load of Burp's in-memory finding store."""
    try:
        from praetor import client
        data = await client.get("/api/notes/findings")
        if isinstance(data, dict) and "error" not in data:
            return data.get("findings", [])
    except Exception:
        pass
    return []


def _find_systemic_sibling_sync(
    findings: list[dict], vuln_type: str, endpoint: str, parameter: str,
) -> dict | None:
    """Core check against a merged findings list."""
    canon = canonical(vuln_type)
    if not canon:
        return None
    same_class = [
        f for f in findings
        if canonical(f.get("vuln_type", "")) == canon
        and (f.get("status") or "") not in ("likely_false_positive", "stale")
    ]
    if not same_class:
        return None
    if any(f.get("endpoint", "") == endpoint and f.get("parameter", "") == parameter
           for f in same_class):
        return None
    first = min(same_class, key=lambda f: str(f.get("created") or f.get("id") or ""))
    return {**first, "_endpoints": sorted({
        f"{f.get('endpoint', '')} ({f.get('parameter') or 'no parameter'})"
        for f in same_class
    })}


async def _find_systemic_sibling(
    domain: str, vuln_type: str, endpoint: str, parameter: str, title: str
) -> dict | None:
    """An existing live finding of the same class at a DIFFERENT endpoint.

    Checks both on-disk findings.json and Burp's in-memory store so
    parallel subagents see each other's recently saved findings.

    Returns the earliest such finding annotated with ``_endpoints``, or
    None when the class is new or this is an exact-match (endpoint+param).
    """
    findings: list[dict] = []
    try:
        path = _safe_findings_path(domain)
        if path.exists():
            findings = _load_findings_file(path).get("findings", [])
    except (OSError, ValueError):
        pass

    burp_findings = await _load_burp_findings()
    seen = {(f.get("endpoint", ""), f.get("vuln_type", ""), f.get("parameter", ""))
            for f in findings}
    for bf in burp_findings:
        key = (bf.get("endpoint", ""), bf.get("vuln_type", ""), bf.get("parameter", ""))
        if key not in seen:
            findings.append(bf)
            seen.add(key)

    return _find_systemic_sibling_sync(findings, vuln_type, endpoint, parameter)
