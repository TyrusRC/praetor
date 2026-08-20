"""sast_handoff — MCP tools (helpers split into _impl.py)."""

from mcp.server.fastmcp import FastMCP
from ._impl import (
    _aggregate_endpoints,
    _dedupe_routes,
    _merge_routes_into_endpoints,
    _parse_opengrep_blob,
    _scan_source_tree,
)


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
    async def inventory_source_routes(
        source_dir: str,
        domain: str = "",
        max_files: int = 5000,
    ) -> dict:
        """Inventory API routes from SOURCE CODE (W36-P4, Invicti parity).

        Regex-scans a source tree for framework route definitions and (if a
        domain is given) MERGES them into <domain>/endpoints.json — the same
        store discover_attack_surface / crawl / JS extraction feed. Grey/white-
        box: discover endpoints the crawler never reached.

        Frameworks: Flask/Quart (@app.route), FastAPI/Starlette/Sanic
        (@app.get / @router.post / ...), Express/Koa/Fastify
        (app.get / router.post / ...), Spring (@GetMapping / @PostMapping /
        @RequestMapping / ...), Rails (config/routes.rb verbs).

        NOTE: regex heuristic, not a full AST — misses dynamically-built routes
        (loops, add_url_rule, blueprint prefixes) and may over-match commented
        decorators. For exact extraction use OWASP Noir (check_recon_tools).

        Args:
            source_dir: Repo / app directory to scan.
            domain: If set, merge discovered routes into that domain's
                endpoints.json (dedup by method+path). Empty = inventory only.
            max_files: Cap on source files read (default 5000).

        Returns:
          {
            "source_dir": ..., "files_scanned": N, "routes_found": M,
            "by_framework": {"fastapi": 4, ...},
            "routes": [{"method","path","framework","source":"file:line"}, ...],
            "endpoints_merged": {"added": X, "total": Y}  # only if domain set
          }
        """
        root = Path(source_dir).expanduser()
        if not root.exists() or not root.is_dir():
            return {"error": f"source_dir not found or not a directory: {source_dir}"}

        raw, files_scanned = _scan_source_tree(root, max_files)
        routes = _dedupe_routes(raw)

        by_framework: dict[str, int] = {}
        for r in routes:
            fw = r.get("framework", "")
            by_framework[fw] = by_framework.get(fw, 0) + 1

        result: dict[str, Any] = {
            "source_dir": str(root),
            "files_scanned": files_scanned,
            "routes_found": len(routes),
            "by_framework": by_framework,
            "routes": routes[:500],
        }
        if len(routes) > 500:
            result["truncated"] = f"routes list capped at 500 of {len(routes)}"

        if domain and routes:
            try:
                added, total = _merge_routes_into_endpoints(domain, routes)
                result["endpoints_merged"] = {"added": added, "total": total}
                result["next_step"] = (
                    f"{added} new source-derived endpoints in {domain}. "
                    "Verify liveness (curl_request / probe_hosts), then "
                    "auto_probe / discover_attack_surface against them."
                )
            except ValueError as e:
                result["merge_error"] = str(e)
        return result

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


# Re-export _impl surface so package-path patches/access keep working.
from . import _impl as _impl  # noqa: E402
globals().update({_k: getattr(_impl, _k) for _k in dir(_impl) if not _k.startswith("__")})
