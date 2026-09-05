"""SAST → DAST risk-rank handoff (W22-e).

Wires opengrep / semgrep source findings into endpoint risk ranking. Output
shape lets discover_attack_surface and auto_probe prioritise endpoints
backed by source-code evidence of dangerous sinks.

Two tools:
  - sast_to_endpoint_risk(opengrep_json) — pure transformer: given an
    opengrep --json blob (path or inline string), returns ranked endpoints
    with vuln-class hints derived from rule IDs + nearest route decorator
    extracted from the source file.
  - risk_rank_endpoints(target_path, framework_hint) — one-shot: runs
    opengrep against target_path, then transforms.

Rule-ID → vuln-class mapping covers the common opengrep / semgrep registry
rulesets (p/owasp-top-ten, p/security-audit, language-specific). Unknown
rule IDs fall back to a "generic" class so they still get ranked.

Framework route extraction (regex-based, no AST — keeps the file zero-dep):
  - Flask / Quart: @app.route("/path") | @bp.route("/path", methods=[...])
  - FastAPI / Starlette: @app.get("/path") @router.post("/path")
  - Django: urlpatterns = [path("path", view)] (best-effort)
  - Express: app.get("/path", handler) | router.post("/path", handler)
  - Spring: @GetMapping("/path") @RequestMapping("/path")
  - Rails: nearest get/post/put/delete in config/routes.rb
  - Next.js: app/<route>/route.ts | pages/api/<route>.ts (filesystem-derived)
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from praetor.tools.intel._internals import (
    _atomic_write_json,
    _empty_structure,
    _intel_path,
)
from praetor.tools.recon._common import _check_tool, _run_cmd


# Source route inventory (W36-P4). Extensions we regex for framework routes,

from ._sast_routes import (  # re-exported (package __init__ copies _impl surface)
    _SOURCE_EXTS, _SKIP_DIRS, _ROUTE_PATTERNS, _classify_rule,
    _route_from_match, _walk_back_for_route, _dedupe_routes,
)


def _aggregate_endpoints(findings: list[dict], source_root: Path) -> list[dict[str, Any]]:
    """Group findings by inferred endpoint, sum risk, dedupe vuln classes."""
    buckets: dict[tuple[str, str], dict[str, Any]] = {}
    orphans: list[dict] = []
    for f in findings:
        rid = f.get("check_id") or ""
        path = f.get("path") or ""
        line = (f.get("start") or {}).get("line") or 0
        sev = ((f.get("extra") or {}).get("severity") or "").upper()
        vtype, base = _classify_rule(rid)
        # Severity multiplier on opengrep's own grade.
        mult = {"ERROR": 1.4, "WARNING": 1.0, "INFO": 0.6}.get(sev, 1.0)
        risk = int(round(base * mult))
        abs_path = (source_root / path) if not Path(path).is_absolute() else Path(path)
        route = _walk_back_for_route(abs_path, line)
        evidence = {
            "rule": rid,
            "file": path,
            "line": line,
            "severity": sev,
            "vuln_type": vtype,
            "risk_unit": risk,
            "framework": route.get("framework", ""),
            "snippet": (((f.get("extra") or {}).get("lines") or "")[:200]),
        }
        if not route:
            evidence["endpoint_inferred"] = False
            orphans.append(evidence)
            continue
        key = (route["method"], route["path"])
        bucket = buckets.setdefault(key, {
            "method": route["method"],
            "path": route["path"],
            "framework": route["framework"],
            "risk_score": 0,
            "vuln_classes": [],
            "evidence": [],
        })
        bucket["risk_score"] += risk
        if vtype not in bucket["vuln_classes"]:
            bucket["vuln_classes"].append(vtype)
        bucket["evidence"].append(evidence)
    ranked = sorted(buckets.values(), key=lambda b: -b["risk_score"])
    return ranked + ([{"endpoint": "(unmapped)", "orphans": orphans}] if orphans else [])


def _parse_opengrep_blob(blob: str) -> list[dict]:
    try:
        report = json.loads(blob)
    except json.JSONDecodeError:
        return []
    return report.get("results") or []


def _scan_source_tree(root: Path, max_files: int) -> tuple[list[dict[str, str]], int]:
    """Walk `root`, regex each source file for framework route definitions.

    Returns (routes, files_scanned). Each route: {method, path, framework,
    source: "<file>:<line>"}. Prunes _SKIP_DIRS and caps at max_files.

    NOTE: regex heuristic, not a full AST/import-graph parse. Misses routes
    built dynamically (loops, add_url_rule, decorator factories, string
    concatenation) and blueprint URL prefixes; over-matches commented-out
    decorators. Upgrade path: per-language AST (ast / tree-sitter) or OWASP
    Noir (already wired via check_recon_tools) for exact extraction.
    """
    routes: list[dict[str, str]] = []
    files_scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if files_scanned >= max_files:
                return routes, files_scanned
            if os.path.splitext(fn)[1] not in _SOURCE_EXTS:
                continue
            fp = Path(dirpath) / fn
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files_scanned += 1
            for framework, pattern in _ROUTE_PATTERNS:
                for m in pattern.finditer(text):
                    route = _route_from_match(framework, m)
                    if not route or not route.get("path"):
                        continue
                    route["source"] = f"{fp}:{text.count(chr(10), 0, m.start()) + 1}"
                    routes.append(route)
    return routes, files_scanned



def _merge_routes_into_endpoints(domain: str, routes: list[dict[str, str]]) -> tuple[int, int]:
    """Merge inventory routes into <domain>/endpoints.json, dedup by (method, path).

    Reuses the canonical intel store (_intel_path + _empty_structure + atomic
    write) — does NOT create a new store. Returns (added, total).
    """
    dir_path = _intel_path(domain)
    dir_path.mkdir(parents=True, exist_ok=True)
    fp = dir_path / "endpoints.json"
    data = _empty_structure("endpoints")
    if fp.exists():
        try:
            loaded = json.loads(fp.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (json.JSONDecodeError, OSError):
            data = _empty_structure("endpoints")
    endpoints = data.get("endpoints") or []
    existing: set[tuple[str, str]] = set()
    for ep in endpoints:
        method = (ep.get("method") or "GET").upper()
        path = ep.get("path") or ep.get("url") or ""
        existing.add((method, path))
    added = 0
    for r in routes:
        key = (r["method"].upper(), r["path"])
        if key in existing:
            continue
        existing.add(key)
        endpoints.append({
            "method": r["method"].upper(),
            "path": r["path"],
            "framework": r.get("framework", ""),
            "source": r.get("source", ""),
            "discovered_via": "source_route_inventory",
        })
        added += 1
    data["endpoints"] = endpoints
    _atomic_write_json(fp, data)
    return added, len(endpoints)
