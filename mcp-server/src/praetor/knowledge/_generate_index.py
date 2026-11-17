#!/usr/bin/env python3
"""Generate _kb_index.json from knowledge-base JSON files and the WSTG/CWE map.

Reads every *.json (non-underscore-prefixed) in this directory, merges with
the WSTG/CWE/chain/prerequisite mappings from _wstg_cwe_map.py, and writes
a machine-readable index.

Run standalone:
    cd mcp-server/src/praetor/knowledge
    python3 -I _generate_index.py

Or from project root:
    python3 -I -m praetor.knowledge._generate_index
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Reference-only categories (not auto-probed). Keep in sync with
# tools/scan/_constants.py::_REFERENCE_ONLY. Read from there at runtime
# when importable; fall back to a snapshot when running standalone.
_REFERENCE_ONLY_SNAPSHOT: set[str] = {
    "captcha_bypass", "ci_actions_injection", "dependency_confusion",
    "desktop_electron", "h2_continuation_flood", "http2_connect_portscan",
    "http3_quic", "http_desync", "kubernetes_exposed", "race_condition",
    "request_smuggling", "soapwn", "source_code_exposure", "tech_vulns",
    "web_cache_poisoning_dos", "xs_leak", "zip_slip",
}


def _reference_only_set() -> set[str]:
    """Load the authoritative REFERENCE_ONLY set, or fall back to snapshot."""
    try:
        from praetor.tools.scan._constants import _REFERENCE_ONLY  # type: ignore[import-untyped]
        return set(_REFERENCE_ONLY)
    except ImportError:
        return _REFERENCE_ONLY_SNAPSHOT


def _load_map() -> dict:
    """Load the WSTG/CWE mapping dict."""
    # Try importable path first (when run as module).
    try:
        from praetor.knowledge._wstg_cwe_map import WSTG_CWE_MAP  # type: ignore[import-untyped]
        return dict(WSTG_CWE_MAP)
    except ImportError:
        pass
    # Fall back to same-directory import (standalone run).
    here = Path(__file__).resolve().parent
    sys.path.insert(0, str(here))
    from _wstg_cwe_map import WSTG_CWE_MAP  # type: ignore[import-not-found]
    return dict(WSTG_CWE_MAP)


def _extract_tech_stack(data: dict) -> list[str]:
    """Collect unique tech_match values across all contexts, lowercased."""
    techs: set[str] = set()
    contexts = data.get("contexts", {})
    if not isinstance(contexts, dict):
        return []
    for ctx in contexts.values():
        if not isinstance(ctx, dict):
            continue
        for t in ctx.get("tech_match", []):
            if isinstance(t, str) and t.strip():
                techs.add(t.strip().lower())
    return sorted(techs)


def _extract_top_severity(data: dict) -> str:
    """Highest probe severity across all contexts."""
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    best = -1
    best_name = ""
    contexts = data.get("contexts", {})
    if not isinstance(contexts, dict):
        return best_name
    for ctx in contexts.values():
        if not isinstance(ctx, dict):
            continue
        for probe in ctx.get("probes", []):
            sev = (probe.get("severity") or "").lower()
            if order.get(sev, -1) > best:
                best = order[sev]
                best_name = sev
    return best_name


def _context_count(data: dict) -> int:
    """Number of contexts in the KB file."""
    contexts = data.get("contexts", {})
    return len(contexts) if isinstance(contexts, dict) else 0


def _merge_chains(kb_chains: list, map_chains: list) -> list[str]:
    """Union of chain_with from KB file and from the map, deduplicated."""
    seen: set[str] = set()
    out: list[str] = []
    for c in list(kb_chains) + list(map_chains):
        if isinstance(c, str) and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def generate_index(kb_dir: Path | None = None) -> list[dict]:
    """Build the index from KB files + WSTG/CWE map. Returns the entry list."""
    if kb_dir is None:
        kb_dir = Path(__file__).resolve().parent

    wstg_map = _load_map()
    ref_only = _reference_only_set()
    entries: list[dict] = []

    for fp in sorted(kb_dir.glob("*.json")):
        if fp.name.startswith("_"):
            continue
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue

        cat = data.get("category", fp.stem)
        mapping = wstg_map.get(cat, {})

        kb_chains = data.get("chain_with", [])
        if not isinstance(kb_chains, list):
            kb_chains = []
        map_chains = mapping.get("chains_with", [])

        entry = {
            "category": cat,
            "file": fp.name,
            "description": (data.get("description") or "").strip(),
            "owasp_id": mapping.get("owasp_id", ""),
            "cwe_ids": mapping.get("cwe_ids", []),
            "chains_with": _merge_chains(kb_chains, map_chains),
            "prerequisites": mapping.get("prerequisites", []),
            "tech_stack": _extract_tech_stack(data),
            "top_severity": _extract_top_severity(data),
            "context_count": _context_count(data),
            "is_reference_only": cat in ref_only,
        }
        entries.append(entry)

    return entries


def main() -> None:
    """Generate and write _kb_index.json."""
    kb_dir = Path(__file__).resolve().parent
    entries = generate_index(kb_dir)
    out_path = kb_dir / "_kb_index.json"
    out_path.write_text(
        json.dumps(entries, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    # Summary stats.
    mapped = sum(1 for e in entries if e["owasp_id"])
    chained = sum(1 for e in entries if e["chains_with"])
    ref = sum(1 for e in entries if e["is_reference_only"])
    print(f"Wrote {len(entries)} entries to {out_path.name}")
    print(f"  WSTG-mapped: {mapped}  with chains: {chained}  reference-only: {ref}")


if __name__ == "__main__":
    main()
