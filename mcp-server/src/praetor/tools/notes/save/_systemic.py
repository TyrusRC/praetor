"""Systemic-duplicate detection for save_finding: an existing live
finding of the same class at a different endpoint."""

from praetor.tools._vuln_class import canonical

from praetor.tools.notes._helpers import _load_findings_file, _safe_findings_path


def _find_systemic_sibling(
    domain: str, vuln_type: str, endpoint: str, parameter: str, title: str
) -> dict | None:
    """An existing live finding of the same class at a DIFFERENT endpoint.

    Returns the earliest such finding (the one that would be the distinct
    report), annotated with `_endpoints` listing every location it already
    covers. None when the class is new to this target, or when this is the same
    endpoint — that case is the existing exact-match dedup, not a systemic one.
    """
    canon = canonical(vuln_type)
    if not canon:
        return None
    try:
        path = _safe_findings_path(domain)
        if not path.exists():
            return None
        findings = _load_findings_file(path).get("findings", [])
    except (OSError, ValueError):
        return None

    same_class = [
        f for f in findings
        if canonical(f.get("vuln_type", "")) == canon
        and (f.get("status") or "") not in ("likely_false_positive", "stale")
    ]
    if not same_class:
        return None
    # Same endpoint AND parameter is the ordinary duplicate the dedup key
    # already merges — let it through to _dedupe_finding.
    if any(f.get("endpoint", "") == endpoint and f.get("parameter", "") == parameter
           for f in same_class):
        return None

    first = min(same_class, key=lambda f: str(f.get("created") or f.get("id") or ""))
    return {**first, "_endpoints": sorted({
        f"{f.get('endpoint', '')} ({f.get('parameter') or 'no parameter'})"
        for f in same_class
    })}
