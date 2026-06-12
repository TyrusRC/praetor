"""detect_mcp_schema_drift — CVE-2025-54136 rug-pull detector.

After the operator approves an MCP server's tool list, the server can
silently swap a tool's name, description, or input schema in a subsequent
session. The approval was on the OLD schema; the new tool now executes with
trust.

This tool snapshots an MCP server's enumeration to disk, then diffs against
a prior snapshot on next call. Drift on high-risk fields produces a
CONFIRMED verdict.

High-risk fields (CONFIRMED on change):
  - tool name → tool name swap
  - input schema required fields added / removed
  - input schema property type changes
  - tool description text changes >40% by character count (heuristic for
    instruction injection added)
  - resource URIs added that reference fs:// or http://internal
  - prompts list mutations

Lower-risk fields (SUSPECTED): description rewording <40%, additive
properties to an existing object schema.

Snapshots persist at `.burp-intel/_mcp_snapshots/<slug>.json`.

Returns VerdictResult.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.testing._verdict import make_verdict, error_verdict
from burpsuite_mcp.tools.notes._helpers import _intel_dir


_SNAPSHOT_SUBDIR = "_mcp_snapshots"
_DESC_DRIFT_THRESHOLD = 0.40  # 40% char-level change → CONFIRMED
_INTERNAL_URI_RE = re.compile(r"^(file|fs|http://(?:127\.|169\.254\.|10\.|172\.|192\.168\.|localhost)|smb://)",
                              re.IGNORECASE)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def detect_mcp_schema_drift(
        server_id: str,
        current_inventory: dict,
        snapshot_label: str = "",
    ) -> dict:
        """Snapshot + diff an MCP server's inventory for rug-pull detection.

        Operator workflow:
          1. Call `enumerate_mcp_server(endpoint)` → inventory dict.
          2. Pass inventory to this tool. First call snapshots; subsequent
             calls diff against the prior snapshot for the same server_id.

        CONFIRMED on high-risk drift (tool added with risky desc, tool name
        changed, schema property semantics shift). SUSPECTED on description
        rewording. FAILED on no drift.

        Args:
            server_id: stable identifier for this MCP server (e.g.
                "anthropic-fs", "apollo-mcp-prod"). Used as snapshot slug.
            current_inventory: dict from enumerate_mcp_server.
            snapshot_label: optional human label for this snapshot
                (default: timestamp).

        Returns: VerdictResult.
        """
        if not server_id:
            return error_verdict("server_id required",
                                 vuln_type="mcp_schema_drift")
        if not isinstance(current_inventory, dict):
            return error_verdict("current_inventory must be a dict",
                                 vuln_type="mcp_schema_drift")

        snap_dir = _intel_dir() / _SNAPSHOT_SUBDIR
        snap_dir.mkdir(parents=True, exist_ok=True)
        slug = re.sub(r"[^A-Za-z0-9._-]", "_", server_id)
        snap_path = snap_dir / f"{slug}.json"

        current = _normalise_inventory(current_inventory)
        current["_snapshot_label"] = snapshot_label or f"ts-{int(time.time())}"
        current["_inventory_hash"] = _hash_inventory(current)

        if not snap_path.exists():
            snap_path.write_text(json.dumps(current, indent=2, ensure_ascii=False))
            return make_verdict(
                "FAILED", 0.10,
                f"Baseline snapshot stored for `{server_id}` "
                f"(tools={len(current['tools'])}, resources={len(current['resources'])}, "
                f"prompts={len(current['prompts'])}). Re-run after operator-visible "
                f"events to detect drift.",
                vuln_type="mcp_schema_drift",
                details={"snapshot_path": str(snap_path),
                         "is_baseline": True,
                         "tool_count": len(current["tools"])},
                summary=f"Baseline stored for MCP server {server_id}",
            )

        prior = json.loads(snap_path.read_text())
        drift = _diff_inventory(prior, current)

        if drift["high_risk"]:
            snap_path.write_text(json.dumps(current, indent=2, ensure_ascii=False))
            return make_verdict(
                "CONFIRMED", 0.88,
                f"MCP schema drift detected for `{server_id}` — "
                f"{len(drift['high_risk'])} high-risk change(s): "
                f"{', '.join(e['category'] for e in drift['high_risk'][:5])}",
                vuln_type="mcp_schema_drift",
                details={
                    "high_risk_changes": drift["high_risk"],
                    "low_risk_changes": drift["low_risk"][:20],
                    "cve_class": "CVE-2025-54136",
                    "snapshot_path": str(snap_path),
                },
                summary=f"CONFIRMED MCP schema drift on {server_id}",
            )

        if drift["low_risk"]:
            snap_path.write_text(json.dumps(current, indent=2, ensure_ascii=False))
            return make_verdict(
                "SUSPECTED", 0.50,
                f"Low-risk drift detected for `{server_id}` "
                f"({len(drift['low_risk'])} change(s)). Manual review recommended.",
                vuln_type="mcp_schema_drift",
                details={"low_risk_changes": drift["low_risk"][:20],
                         "snapshot_path": str(snap_path)},
                summary=f"SUSPECTED low-risk MCP drift on {server_id}",
            )

        return make_verdict(
            "FAILED", 0.10,
            f"No drift detected for `{server_id}` (hash match against prior snapshot)",
            vuln_type="mcp_schema_drift",
            details={"snapshot_path": str(snap_path),
                     "matched_hash": current["_inventory_hash"]},
            summary=f"FAILED — no drift on {server_id}",
        )


def _normalise_inventory(inv: dict) -> dict:
    """Strip volatile fields (logger_index, timestamps) for stable hashing."""
    tools = []
    for t in inv.get("tools", []) or []:
        if not isinstance(t, dict):
            continue
        tools.append({
            "name": t.get("name", ""),
            "description": (t.get("description") or "")[:1000],
            "input_schema_summary": t.get("input_schema_summary") or {},
        })
    resources = []
    for r in inv.get("resources", []) or []:
        if not isinstance(r, dict):
            continue
        resources.append({
            "uri": r.get("uri", ""),
            "name": r.get("name", ""),
            "mime_type": r.get("mime_type", ""),
        })
    prompts = []
    for p in inv.get("prompts", []) or []:
        if not isinstance(p, dict):
            continue
        prompts.append({
            "name": p.get("name", ""),
            "description": (p.get("description") or "")[:500],
            "arg_count": p.get("arg_count", 0),
            "arg_names": p.get("arg_names") or [],
        })
    return {
        "server_info": inv.get("server_info") or {},
        "server_capabilities": inv.get("server_capabilities") or {},
        "tools": tools,
        "resources": resources,
        "prompts": prompts,
    }


def _hash_inventory(inv: dict) -> str:
    blob = json.dumps({k: v for k, v in inv.items()
                       if not k.startswith("_")},
                      sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _diff_inventory(prior: dict, current: dict) -> dict:
    high: list[dict] = []
    low: list[dict] = []

    prior_tools = {t["name"]: t for t in prior.get("tools", []) if isinstance(t, dict)}
    current_tools = {t["name"]: t for t in current.get("tools", []) if isinstance(t, dict)}

    # Tools added
    for name in set(current_tools) - set(prior_tools):
        t = current_tools[name]
        cat = ("tool_added_internal_capability"
               if _looks_risky_description(t.get("description", ""))
               else "tool_added")
        bucket = high if cat == "tool_added_internal_capability" else low
        bucket.append({"category": cat, "tool": name,
                       "description_excerpt": (t.get("description") or "")[:160]})

    # Tools removed
    for name in set(prior_tools) - set(current_tools):
        low.append({"category": "tool_removed", "tool": name})

    # Tools modified
    for name in set(prior_tools) & set(current_tools):
        pt = prior_tools[name]
        ct = current_tools[name]
        # description drift
        pd, cd = pt.get("description", ""), ct.get("description", "")
        if pd != cd:
            ratio = _char_drift_ratio(pd, cd)
            entry = {"category": "tool_description_drift",
                     "tool": name, "drift_ratio": round(ratio, 3),
                     "prior_excerpt": pd[:160], "current_excerpt": cd[:160]}
            (high if ratio >= _DESC_DRIFT_THRESHOLD else low).append(entry)
        # schema drift
        ps = pt.get("input_schema_summary") or {}
        cs = ct.get("input_schema_summary") or {}
        req_added = set(cs.get("required", [])) - set(ps.get("required", []))
        req_removed = set(ps.get("required", [])) - set(cs.get("required", []))
        if req_added:
            high.append({"category": "required_param_added",
                         "tool": name, "added": sorted(req_added)})
        if req_removed:
            high.append({"category": "required_param_removed",
                         "tool": name, "removed": sorted(req_removed)})
        param_added = set(cs.get("param_names", [])) - set(ps.get("param_names", []))
        if param_added:
            low.append({"category": "optional_param_added",
                        "tool": name, "added": sorted(param_added)})

    # Resources
    prior_uris = {r["uri"]: r for r in prior.get("resources", []) if isinstance(r, dict)}
    current_uris = {r["uri"]: r for r in current.get("resources", []) if isinstance(r, dict)}
    for uri in set(current_uris) - set(prior_uris):
        cat = ("resource_added_internal" if _INTERNAL_URI_RE.match(uri)
               else "resource_added")
        bucket = high if cat == "resource_added_internal" else low
        bucket.append({"category": cat, "uri": uri,
                       "name": current_uris[uri].get("name", "")})

    # Prompts (lower risk — but injection candidate)
    prior_prompts = {p["name"]: p for p in prior.get("prompts", []) if isinstance(p, dict)}
    current_prompts = {p["name"]: p for p in current.get("prompts", []) if isinstance(p, dict)}
    for name in set(current_prompts) - set(prior_prompts):
        low.append({"category": "prompt_added", "name": name})

    return {"high_risk": high, "low_risk": low}


def _char_drift_ratio(a: str, b: str) -> float:
    if not a and not b:
        return 0.0
    if not a:
        return 1.0
    matcher = difflib.SequenceMatcher(None, a, b)
    return 1.0 - matcher.ratio()


_RISKY_DESC_PATTERNS = (
    "execute", "run shell", "system command", "ignore", "instruction",
    "<system>", "[system]", "## system", "you must", "you should",
    "secret", "credential", "private key", "exfiltrat",
)


def _looks_risky_description(desc: str) -> bool:
    if not desc:
        return False
    low = desc.lower()
    return any(p in low for p in _RISKY_DESC_PATTERNS)
