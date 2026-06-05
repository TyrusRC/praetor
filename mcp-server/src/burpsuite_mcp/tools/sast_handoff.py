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
import re
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd


# Rule-ID substrings → Praetor vuln_type. Order matters: first match wins.
_RULE_VULN_MAP: list[tuple[str, str, int]] = [
    # (substring, vuln_type, base_risk_score)
    ("sql-injection", "sqli", 9),
    ("sqli", "sqli", 9),
    ("ssrf", "ssrf", 9),
    ("ssti", "ssti", 9),
    ("server-side-template", "ssti", 9),
    ("xss", "xss", 7),
    ("cross-site-script", "xss", 7),
    ("command-injection", "rce", 10),
    ("os-command", "rce", 10),
    ("rce", "rce", 10),
    ("path-traversal", "lfi", 8),
    ("lfi", "lfi", 8),
    ("file-inclusion", "lfi", 8),
    ("xxe", "xxe", 8),
    ("xml-external-entity", "xxe", 8),
    ("deserialization", "deserialization", 9),
    ("unsafe-deserial", "deserialization", 9),
    ("pickle", "deserialization", 9),
    ("open-redirect", "open_redirect", 5),
    ("unvalidated-redirect", "open_redirect", 5),
    ("hardcoded-secret", "secret_disclosure", 7),
    ("hardcoded-credential", "secret_disclosure", 7),
    ("hardcoded-password", "secret_disclosure", 7),
    ("jwt", "jwt", 7),
    ("weak-crypto", "weak_crypto", 5),
    ("weak-hash", "weak_crypto", 5),
    ("md5", "weak_crypto", 4),
    ("insecure-cookie", "insecure_cookie", 4),
    ("csrf", "csrf", 5),
    ("cors", "cors_misconfig", 5),
    ("ldap-injection", "ldap_injection", 8),
    ("nosql-injection", "nosql_injection", 8),
    ("prototype-pollution", "prototype_pollution", 8),
    ("regex-dos", "redos", 6),
    ("redos", "redos", 6),
    ("mass-assignment", "mass_assignment", 7),
    ("graphql", "graphql", 7),
]


# Route decorator regexes per framework. Each yields (method, path) when matched.
_ROUTE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Flask / Quart
    ("flask", re.compile(
        r'@(?:[\w.]+\.)?route\s*\(\s*["\']([^"\']+)["\']'
        r'(?:[^)]*?methods\s*=\s*\[([^\]]+)\])?',
        re.I | re.S,
    )),
    # FastAPI / Starlette / Sanic
    ("fastapi", re.compile(
        r'@(?:[\w.]+\.)?(get|post|put|patch|delete|head|options)\s*\(\s*["\']([^"\']+)["\']',
        re.I,
    )),
    # Express / Koa / Fastify (JS)
    ("express", re.compile(
        r'\b(?:app|router|fastify)\.(get|post|put|patch|delete|head|options|all)\s*\(\s*["\']([^"\']+)["\']',
        re.I,
    )),
    # Spring (Java/Kotlin)
    ("spring_method", re.compile(
        r'@(Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*["\']([^"\']+)["\']',
    )),
    # Rails (config/routes.rb)
    ("rails", re.compile(
        r'\b(get|post|put|patch|delete)\s+["\']([^"\']+)["\']',
        re.I,
    )),
]


def _classify_rule(rule_id: str) -> tuple[str, int]:
    rid = rule_id.lower()
    for needle, vtype, base in _RULE_VULN_MAP:
        if needle in rid:
            return vtype, base
    return "generic_sink", 3


def _walk_back_for_route(file_path: Path, line: int, lookback: int = 30) -> dict[str, str]:
    """Read up to `lookback` lines before `line` looking for a route decorator.

    Returns {method, path, framework} or empty dict if none found.
    """
    if not file_path.exists() or not file_path.is_file():
        return {}
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}
    start = max(0, line - lookback)
    end = min(len(lines), line)
    snippet = "\n".join(lines[start:end])
    for framework, pattern in _ROUTE_PATTERNS:
        m = pattern.search(snippet)
        if not m:
            continue
        if framework == "flask":
            path = m.group(1)
            methods_raw = (m.group(2) or "").upper()
            method = "GET"
            for verb in ("POST", "PUT", "PATCH", "DELETE"):
                if verb in methods_raw:
                    method = verb
                    break
            return {"framework": framework, "method": method, "path": path}
        elif framework == "fastapi":
            return {"framework": framework, "method": m.group(1).upper(), "path": m.group(2)}
        elif framework == "express":
            method = m.group(1).upper()
            if method == "ALL":
                method = "ANY"
            return {"framework": framework, "method": method, "path": m.group(2)}
        elif framework == "spring_method":
            verb = m.group(1).upper()
            method = "GET" if verb == "REQUEST" else verb.upper()
            return {"framework": "spring", "method": method, "path": m.group(2)}
        elif framework == "rails":
            return {"framework": framework, "method": m.group(1).upper(), "path": m.group(2)}
    # Next.js / Remix filesystem route fallback.
    path_str = str(file_path)
    if "/app/" in path_str and path_str.endswith(("route.ts", "route.js", "route.tsx", "route.jsx")):
        seg = path_str.split("/app/", 1)[1].rsplit("/", 1)[0]
        return {"framework": "nextjs_app_router", "method": "ANY", "path": "/" + seg}
    if "/pages/api/" in path_str:
        api_path = path_str.split("/pages/api/", 1)[1].rsplit(".", 1)[0]
        return {"framework": "nextjs_pages_api", "method": "ANY", "path": "/api/" + api_path}
    return {}


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


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def sast_to_endpoint_risk(
        opengrep_json: str,
        source_root: str = "",
        max_endpoints: int = 50,
    ) -> dict:
        """Transform an opengrep --json blob into endpoint risk ranking.

        Args:
            opengrep_json: Path to opengrep --json output file, OR the JSON
                string itself (auto-detected by leading '{').
            source_root: Directory the opengrep run targeted. Required for
                walking back from finding line to nearest route decorator.
                If empty, route inference falls back to filesystem-only
                (Next.js app/pages routes).
            max_endpoints: Cap on returned ranked endpoints (default 50).

        Returns a dict:
          {
            "total_findings": N,
            "ranked_endpoints": [
              {"method": "POST", "path": "/api/login", "framework": "fastapi",
               "risk_score": 17, "vuln_classes": ["sqli","xss"],
               "evidence": [...]}, ...
            ],
            "orphans": [...]   # findings without resolvable route
          }
        """
        blob = opengrep_json
        if blob and not blob.lstrip().startswith("{"):
            p = Path(blob).expanduser()
            if p.exists():
                blob = p.read_text(encoding="utf-8", errors="replace")
            else:
                return {"error": f"opengrep_json path not found: {opengrep_json}"}
        findings = _parse_opengrep_blob(blob)
        if not findings:
            return {"total_findings": 0, "ranked_endpoints": [], "orphans": []}

        root = Path(source_root).expanduser() if source_root else Path(".")
        ranked_with_orphans = _aggregate_endpoints(findings, root)

        # Separate orphans tail.
        ranked: list[dict] = []
        orphans: list[dict] = []
        for entry in ranked_with_orphans:
            if "orphans" in entry:
                orphans = entry["orphans"]
            else:
                ranked.append(entry)
        return {
            "total_findings": len(findings),
            "ranked_endpoints": ranked[:max_endpoints],
            "orphans": orphans[:50],
            "next_step": (
                "Feed ranked_endpoints into auto_probe(categories=<vuln_classes>) "
                "ordered by risk_score, or into discover_attack_surface as risk "
                "priors. High-risk source-trace findings warrant immediate DAST."
            ),
        }

    @mcp.tool()
    async def risk_rank_endpoints(
        target_path: str,
        extra_configs: list[str] | None = None,
        timeout: int = 600,
        max_endpoints: int = 50,
    ) -> dict:
        """One-shot: run opengrep against target_path + transform to ranked
        endpoints (W22-e SAST → DAST handoff).

        Args:
            target_path: Source root (a repo / app dir).
            extra_configs: opengrep --config values. Default:
                p/owasp-top-ten + p/security-audit.
            timeout: Max seconds for the opengrep run.
            max_endpoints: Cap on returned ranked endpoints.

        Returns same shape as sast_to_endpoint_risk + an "opengrep_summary"
        block with raw counters for the operator.
        """
        if not _check_tool("opengrep") and not _check_tool("semgrep"):
            return {
                "error": (
                    "opengrep / semgrep not installed. Install: "
                    "https://github.com/opengrep/opengrep#installation"
                ),
            }
        tool = "opengrep" if _check_tool("opengrep") else "semgrep"

        target = Path(target_path).expanduser()
        if not target.exists():
            return {"error": f"target path not found: {target_path}"}

        configs = extra_configs or ["p/owasp-top-ten", "p/security-audit"]
        cmd = [tool, "scan"]
        for c in configs:
            cmd += ["--config", c]
        cmd += ["--metrics", "off", "--json", str(target)]

        stdout, stderr, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        if not stdout:
            return {"error": f"{tool} produced no output (rc={rc})",
                    "stderr": stderr[:500]}
        findings = _parse_opengrep_blob(stdout)
        if not findings:
            return {"total_findings": 0, "ranked_endpoints": [], "orphans": [],
                    "tool": tool}

        ranked_with_orphans = _aggregate_endpoints(findings, target)
        ranked: list[dict] = []
        orphans: list[dict] = []
        for entry in ranked_with_orphans:
            if "orphans" in entry:
                orphans = entry["orphans"]
            else:
                ranked.append(entry)

        # Opengrep summary (counters).
        by_sev: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        for f in findings:
            sev = ((f.get("extra") or {}).get("severity") or "?").upper()
            by_sev[sev] = by_sev.get(sev, 0) + 1
            rid = f.get("check_id") or "?"
            by_rule[rid] = by_rule.get(rid, 0) + 1

        return {
            "tool": tool,
            "target": str(target),
            "total_findings": len(findings),
            "opengrep_summary": {
                "by_severity": by_sev,
                "top_rules": dict(sorted(by_rule.items(), key=lambda kv: -kv[1])[:10]),
            },
            "ranked_endpoints": ranked[:max_endpoints],
            "orphans": orphans[:50],
            "next_step": (
                "Feed ranked_endpoints into auto_probe(categories=<vuln_classes>) "
                "ordered by risk_score. High-risk source-trace endpoints warrant "
                "immediate DAST."
            ),
        }
