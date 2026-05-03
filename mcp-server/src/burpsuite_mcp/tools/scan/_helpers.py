"""Shared scan helpers: knowledge loading, parameter classification, target formatting."""

import json
from functools import lru_cache

from ._constants import KNOWLEDGE_DIR, _PARAM_RISK_MAP, _REFERENCE_ONLY


@lru_cache(maxsize=16)
def _load_knowledge(category: str) -> dict | None:
    """Load and cache a single knowledge base file."""
    f = KNOWLEDGE_DIR / f"{category}.json"
    if not f.exists():
        return None
    try:
        with open(f) as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None


def _load_all_knowledge(categories: list[str] | None = None) -> list[dict]:
    """Load all knowledge base files with probes, optionally filtered by category."""
    if not KNOWLEDGE_DIR.exists():
        return []
    available = [f.stem for f in KNOWLEDGE_DIR.glob("*.json") if f.stem not in _REFERENCE_ONLY]
    if categories:
        available = [c for c in available if c in categories]
    result = []
    for cat in available:
        kb = _load_knowledge(cat)
        if kb and kb.get("contexts"):
            result.append(kb)
    return result


def _matches_param(param_lower: str, target: str) -> bool:
    """Word-boundary-aware match for short parameter names."""
    if param_lower == target:
        return True
    if len(target) <= 3:
        return (
            param_lower.startswith(target + "_") or
            param_lower.endswith("_" + target) or
            f"_{target}_" in param_lower
        )
    return target in param_lower


def _classify_param_risk(param_name: str) -> list[str]:
    """Classify a parameter's vulnerability risk based on its name.

    R14: Returns at minimum ['BASELINE_PROBE'] for unknown params so every
    user-supplied parameter gets at least a baseline test pass.
    """
    if not param_name:
        return []
    name = param_name.lower()
    risks: list[str] = []
    for vuln_type, names in _PARAM_RISK_MAP.items():
        if name in names or any(_matches_param(name, n) for n in names):
            risks.append(vuln_type.replace("_", "/").upper())
    if not risks:
        risks.append("BASELINE_PROBE")
    return risks


def _compact_targets(targets: list[dict]) -> str:
    """Format targets as compact JSON for Claude to copy-paste."""
    items = []
    for t in targets[:15]:
        items.append(json.dumps({
            "method": t.get("method", "GET"),
            "path": t.get("path", ""),
            "parameter": t.get("parameter", ""),
            "baseline_value": t.get("baseline_value", "1"),
            "location": t.get("location", "query"),
        }, separators=(",", ":")))
    result = "[" + ",".join(items) + "]"
    if len(targets) > 15:
        result += f"  # ... and {len(targets) - 15} more"
    return result
