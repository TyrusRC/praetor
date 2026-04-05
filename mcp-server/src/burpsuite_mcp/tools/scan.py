"""Adaptive scan engine — discover attack surface and auto-probe with knowledge-driven detection."""

import asyncio
import json
from functools import lru_cache
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


KNOWLEDGE_DIR = Path(__file__).parent.parent / "knowledge"


@lru_cache(maxsize=16)
def _load_knowledge(category: str) -> dict | None:
    """Load and cache a knowledge base file."""
    f = KNOWLEDGE_DIR / f"{category}.json"
    if not f.exists():
        return None
    with open(f) as fh:
        return json.load(fh)


# Reference-only files (no probes, skip in auto_probe)
_REFERENCE_ONLY = {"tech_vulns"}

# Parameter name to vulnerability type mapping for attack prioritization
_PARAM_RISK_MAP = {
    "sqli_idor": ["id", "uid", "pid", "user_id", "account_id", "order_id", "item_id", "product_id", "num", "page"],
    "xss_sqli": ["search", "q", "query", "keyword", "name", "comment", "message", "text", "content"],
    "redirect_ssrf": ["url", "redirect", "next", "return", "goto", "dest", "callback", "uri", "link", "href", "forward"],
    "lfi": ["file", "path", "dir", "page", "include", "template", "load", "read", "doc", "download"],
    "cmdi": ["cmd", "command", "exec", "run", "ping", "ip", "hostname"],
    "ssti": ["template", "render", "view", "layout", "preview", "expression", "eval"],
}

# Common hidden parameter wordlists
_COMMON_PARAMS = [
    "id", "page", "search", "q", "query", "name", "email", "user", "username",
    "password", "token", "key", "api_key", "apikey", "secret", "auth", "session",
    "redirect", "url", "next", "return", "callback", "file", "path", "action",
    "type", "format", "lang", "debug", "test", "admin", "role", "sort", "order",
    "limit", "offset", "filter", "category", "status", "view", "mode", "cmd",
    "command", "input", "output", "data", "value", "template", "include", "v",
    "version", "config", "setting", "env", "verbose", "force", "confirm",
]

_EXTENDED_PARAMS = _COMMON_PARAMS + [
    "account", "profile", "uid", "pid", "sid", "tid", "cid", "oid", "bid",
    "item", "product", "article", "post", "comment", "message", "notification",
    "task", "project", "workspace", "organization", "team", "report", "export",
    "import", "log", "audit", "level", "app", "client", "client_id",
    "client_secret", "grant_type", "response_type", "scope", "state", "nonce",
    "redirect_uri", "return_url", "continue", "goto", "forward", "dest",
    "destination", "redir", "checkout", "payment", "amount", "price", "quantity",
    "coupon", "discount", "promo", "address", "phone", "zip", "country", "ip",
    "host", "port", "domain", "subdomain", "method", "endpoint", "resource",
    "field", "column", "table", "database", "schema", "index", "timeout",
    "retry", "cache", "refresh", "delete", "remove", "update", "create",
    "edit", "submit", "process", "validate", "verify", "check", "preview",
    "draft", "publish", "upload", "download", "fetch", "load", "read", "write",
]


def _matches_param(param_lower: str, target: str) -> bool:
    """Check if parameter name matches target, with word-boundary awareness for short names."""
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
    """Classify a parameter's vulnerability risk based on its name."""
    name = param_name.lower()
    risks = []
    for vuln_type, names in _PARAM_RISK_MAP.items():
        if name in names or any(_matches_param(name, n) for n in names):
            risks.append(vuln_type.replace("_", "/").upper())
    return risks


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


def _compact_targets(targets: list[dict]) -> str:
    """Format targets as a compact JSON-like string for Claude to copy-paste."""
    items = []
    for t in targets[:15]:  # Cap at 15 for readability
        items.append(f'{{"method":"{t.get("method","GET")}","path":"{t.get("path","")}","parameter":"{t.get("parameter","")}","baseline_value":"{t.get("baseline_value","1")}","location":"{t.get("location","query")}"}}')
    result = "[" + ",".join(items) + "]"
    if len(targets) > 15:
        result += f"  # ... and {len(targets) - 15} more"
    return result


def register(mcp: FastMCP):

    @mcp.tool()
    async def discover_attack_surface(
        session: str,
        max_pages: int = 20,
    ) -> str:
        """Crawl target and map the entire attack surface in ONE call.
        Returns: endpoints, parameters (risk-scored), forms, tech stack.

        Use this first, then pass high-risk parameters to auto_probe.

        Args:
            session: Session name with base_url configured
            max_pages: Max pages to crawl (default 20)
        """
        data = await client.post("/api/session/discover", json={
            "session": session, "max_pages": max_pages,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Attack Surface: {data.get('pages_crawled', 0)} pages crawled\n"]

        tech = data.get("detected_tech", [])
        if tech:
            lines.append(f"Tech Stack: {', '.join(tech)}")

        lines.append(f"Parameters: {data.get('total_parameters', 0)} total, {data.get('high_risk_parameters', 0)} high-risk\n")

        # Sort endpoints by risk score (highest first)
        endpoints_sorted = sorted(data.get("endpoints", []), key=lambda e: e.get("risk_score", 0), reverse=True)
        for ep in endpoints_sorted:
            params = ep.get("parameters", [])
            param_str = ""
            if params:
                names = [f"{p['name']}({'!' if p.get('risk') == 'high' else ''})" for p in params]
                param_str = f" [{', '.join(names)}]"
            risk = ep.get("risk_score", 0)
            priority = ep.get("priority", "low")
            marker = "***" if priority == "critical" else "**" if priority == "high" else "*" if priority == "medium" else ""
            lines.append(f"  [{risk:>2}] {ep.get('method', '?'):6s} {ep.get('path', '?'):<40s} {ep.get('status', '?')} {marker}{param_str}")

        forms = data.get("forms", [])
        if forms:
            lines.append(f"\nForms ({len(forms)}):")
            for form in forms:
                inputs = ", ".join(form.get("inputs", []))
                lines.append(f"  [{form.get('method', '?')}] {form.get('action', '?')} -> {inputs}")

        # Pre-formatted targets ready for auto_probe
        targets = data.get("targets", [])
        if targets:
            lines.append(f"\nReady-to-probe targets ({len(targets)}):")
            for t in targets:
                lines.append(f"  {t.get('method', '?'):6s} {t.get('path', '?')} -> {t.get('parameter', '?')} ({t.get('location', '?')})")
            lines.append(f"\nTo probe all: auto_probe(session=\"{session}\", targets={_compact_targets(targets)})")

        # Attack priority summary based on parameter name heuristics
        priorities = []
        for ep in endpoints_sorted:
            ep_risks = set()
            for p in ep.get("parameters", []):
                risks = _classify_param_risk(p.get("name", ""))
                ep_risks.update(risks)
            if ep_risks:
                priorities.append((ep, sorted(ep_risks)))

        if priorities:
            lines.append(f"\nATTACK PRIORITIES:")
            for i, (ep, risks) in enumerate(priorities[:10], 1):
                risk_str = ", ".join(risks)
                path = ep.get("path", "?")
                method = ep.get("method", "?")
                lines.append(f"  {i}. {method} {path} -> {risk_str}")

        return "\n".join(lines)

    @mcp.tool()
    async def auto_probe(
        session: str,
        targets: list[dict],
        categories: list[str] | None = None,
        max_probes_per_param: int = 5,
    ) -> str:
        """Knowledge-driven vulnerability probing. Tests parameters using adaptive
        payloads with server-side matchers. Auto-detects tech, selects matching probes.

        Pass targets from discover_attack_surface output. Each target:
        {"method": "GET", "path": "/page.asp", "parameter": "id", "baseline_value": "1", "location": "query"}

        Args:
            session: Session name
            targets: Parameters to test (from discover_attack_surface)
            categories: Filter categories - ["sqli", "xss", "path_traversal"]. Empty = all.
            max_probes_per_param: Max probes per parameter (default 5)
        """
        knowledge = _load_all_knowledge(categories)
        if not knowledge:
            available = [f.stem for f in KNOWLEDGE_DIR.glob("*.json") if f.stem not in _REFERENCE_ONLY]
            return f"No knowledge base found. Available: {', '.join(sorted(available))}"

        data = await client.post("/api/session/auto-probe", json={
            "session": session,
            "targets": targets,
            "knowledge": knowledge,
            "max_probes_per_param": max_probes_per_param,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Auto-Probe: {data.get('parameters_tested', 0)} params, {data.get('total_probes_sent', 0)} probes\n"]

        findings = data.get("findings", [])
        # Sort by score descending
        findings_sorted = sorted(findings, key=lambda f: f.get("score", 0), reverse=True)
        if findings_sorted:
            lines.append(f"Findings ({len(findings_sorted)}):\n")
            for finding in findings_sorted:
                sev = finding.get("severity", "?")
                score = finding.get("score", 0)
                anomaly = finding.get("anomaly_score", 0)
                lines.append(f"  [{sev:>8s}] {finding.get('endpoint', '?')} -> {finding.get('parameter', '?')} (score: {score})")
                lines.append(f"           {finding.get('category', '?')}/{finding.get('context', '?')}: {finding.get('description', '?')}")
                lines.append(f"           Payload: {finding.get('probe', '?')}")
                matched = finding.get("matched_matchers", [])
                if matched:
                    lines.append(f"           Matchers: {', '.join(str(m) for m in matched)}")
                anomalies = finding.get("anomalies", [])
                if anomalies:
                    lines.append(f"           Anomalies: {', '.join(anomalies)} (anomaly_score: {anomaly})")
                lines.append("")
        else:
            lines.append("No vulnerabilities detected.")

        saved = data.get("auto_saved_findings", 0)
        if saved:
            lines.append(f"\n{saved} findings detected. Use save_finding() to document or export_report() for report.")

        return "\n".join(lines)

    @mcp.tool()
    async def scan_target(
        session: str,
        mode: str = "discover",
        targets: list[dict] | None = None,
        categories: list[str] | None = None,
        max_pages: int = 20,
        max_probes_per_param: int = 5,
    ) -> str:
        """Two-mode scan: discover attack surface OR probe parameters.

        Mode 'discover': crawl target, map endpoints, score parameters.
        Mode 'probe': run knowledge-driven probes on specified targets.

        Typical flow:
        1. scan_target(session="s", mode="discover") -> review results
        2. scan_target(session="s", mode="probe", targets=[...high-risk params...])

        Args:
            session: Session name
            mode: 'discover' or 'probe'
            targets: Parameters to probe (required for mode='probe')
            categories: Filter vuln categories for probing
            max_pages: Max pages for discovery (default 20)
            max_probes_per_param: Max probes per parameter (default 5)
        """
        if mode == "discover":
            return await discover_attack_surface(session=session, max_pages=max_pages)
        elif mode == "probe":
            if not targets:
                return "Error: 'targets' required for mode='probe'. Run with mode='discover' first."
            return await auto_probe(session=session, targets=targets, categories=categories, max_probes_per_param=max_probes_per_param)
        else:
            return f"Error: Unknown mode '{mode}'. Use 'discover' or 'probe'."

    # ── Probe tools (moved from session.py) ──

    @mcp.tool()
    async def quick_scan(
        session: str, method: str, path: str,
        headers: dict | None = None, body: str = "", data: str = "",
        json_body: dict | None = None,
    ) -> str:
        """Send request + auto-analyze in ONE call. Returns: status, tech stack,
        injection points, parameters, forms, secrets — without the response body.

        Args:
            session: Session name
            method: HTTP method
            path: Request path relative to session base_url
            headers: Additional headers
            body: Raw request body
            data: Form-encoded data
            json_body: JSON body dict
        """
        payload: dict = {"session": session, "method": method, "path": path, "analyze": True}
        if headers: payload["headers"] = headers
        if body: payload["body"] = body
        if data: payload["data"] = data
        if json_body is not None: payload["json_body"] = json_body

        resp = await client.post("/api/session/request", json=payload)
        if "error" in resp:
            return f"Error: {resp['error']}"

        lines = [f"Status: {resp.get('status')} | Length: {resp.get('response_length', 0)} bytes"]
        analysis = resp.get("analysis", {})
        if analysis:
            techs = analysis.get("tech_stack", {}).get("technologies", [])
            if techs: lines.append(f"\nTech Stack: {', '.join(techs)}")
            missing = [k for k, v in analysis.get("tech_stack", {}).get("security_headers", {}).items() if not v]
            if missing: lines.append(f"Missing Headers: {', '.join(missing)}")
            high_risk = analysis.get("injection_points", {}).get("high_risk", [])
            if high_risk:
                lines.append(f"\nInjection Points ({len(high_risk)}):")
                for ip in high_risk[:10]:
                    lines.append(f"  {ip.get('name', '?')} [{', '.join(ip.get('types', []))}] risk={ip.get('risk_score', 0)}")
            for loc in ["query", "body", "cookie"]:
                pl = analysis.get("parameters", {}).get(loc, [])
                if pl and isinstance(pl, list):
                    lines.append(f"Params ({loc}): {', '.join(p.get('name', '?') for p in pl)}")
        return "\n".join(lines)

    @mcp.tool()
    async def probe_endpoint(
        session: str, method: str, path: str, parameter: str,
        baseline_value: str = "1", payload_value: str = "",
        injection_point: str = "query", test_payloads: list[str] | None = None,
    ) -> str:
        """ADAPTIVE vulnerability probe. Auto-detects tech stack, selects payloads,
        tests for SQLi/XSS/path traversal/SSTI/RCE, checks multiple reflection variants.

        Args:
            session: Session name
            method: HTTP method
            path: Base endpoint path
            parameter: Parameter name to test
            baseline_value: Normal/safe value (default '1')
            payload_value: Single attack payload (empty = auto-detect)
            injection_point: Where to inject — 'query' or 'body'
            test_payloads: Multiple payloads to test in one call
        """
        req: dict = {
            "session": session, "method": method, "path": path,
            "parameter": parameter, "baseline_value": baseline_value,
            "injection_point": injection_point,
        }
        if payload_value: req["payload_value"] = payload_value
        if test_payloads: req["test_payloads"] = test_payloads

        resp = await client.post("/api/session/probe", json=req)
        if "error" in resp:
            return f"Error: {resp['error']}"

        lines = [f"Probe: {parameter} on {path}"]
        tech = resp.get("detected_tech", [])
        if tech: lines.append(f"Tech: {', '.join(tech)}")
        lines.append(f"Baseline: {resp.get('baseline_status')} | {resp.get('baseline_length')}B | {resp.get('baseline_time_ms')}ms")
        lines.append(f"Payloads tested: {resp.get('payloads_tested', 0)}\n")

        for r in resp.get("results", []):
            score = r.get("score", 0)
            vuln = " ***" if score >= 30 else ""
            lines.append(f"  [{score:>3}] {r.get('payload', '?')}")
            lines.append(f"        {r.get('status', '?')} | {r.get('length', 0)}B | {r.get('time_ms', 0)}ms{vuln}")
            for f in r.get("findings", []): lines.append(f"        -> {f}")
            refl = r.get("reflection", {})
            if refl:
                ctx = refl.get("context", "")
                lines.append(f"        Reflected ({refl.get('type', '?')}{', ' + ctx if ctx else ''})")

        max_score = resp.get("max_vulnerability_score", 0)
        if resp.get("likely_vulnerable"):
            lines.append(f"\n*** LIKELY VULNERABLE (score: {max_score}/100) ***")
        else:
            lines.append(f"\nNo obvious vulnerability (score: {max_score}/100)")
        return "\n".join(lines)

    @mcp.tool()
    async def batch_probe(session: str, endpoints: list[dict]) -> str:
        """Test multiple endpoints in ONE call. Returns status, length, timing for each.

        Args:
            session: Session name
            endpoints: List of endpoints - [{"method": "GET", "path": "/api/users"}]
        """
        data = await client.post("/api/session/batch", json={"session": session, "endpoints": endpoints})
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Batch Probe: {data.get('total_endpoints')} endpoints in {data.get('total_time_ms')}ms\n"]
        dist = data.get("status_distribution", {})
        if dist: lines.append(f"Status: {', '.join(f'{s}x{c}' for s, c in dist.items())}\n")
        for r in data.get("results", []):
            title = f" [{r['title']}]" if r.get("title") else ""
            lines.append(f"  {r.get('method', '?'):6s} {r.get('path', '?'):<40s} {r['status']} | {r['length']:>6}B | {r['time_ms']:>4}ms{title}")
        return "\n".join(lines)

    # ── New discovery & workflow tools ────────────────────────────────

    @mcp.tool()
    async def discover_hidden_parameters(
        session: str,
        method: str = "GET",
        path: str = "/",
        wordlist: str = "common",
        param_type: str = "query",
        baseline_value: str = "1",
    ) -> str:
        """Discover hidden/undocumented parameters by brute-forcing parameter names (Arjun-style).
        Sends requests adding each candidate parameter and detects anomalies
        (status change, length change, new content, reflection).

        Args:
            session: Session name
            method: HTTP method (GET or POST)
            path: Endpoint path to test
            wordlist: 'common' (~60 params) or 'extended' (~150 params)
            param_type: Where to add params - 'query', 'body', or 'json'
            baseline_value: Value to use for test parameters (default '1')
        """
        candidates = _EXTENDED_PARAMS if wordlist == "extended" else _COMMON_PARAMS

        # Send baseline request
        baseline_req: dict = {"session": session, "method": method, "path": path}
        if param_type == "body":
            baseline_req["body"] = ""
            baseline_req["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
        elif param_type == "json":
            baseline_req["json_body"] = {}
            baseline_req["headers"] = {"Content-Type": "application/json"}

        baseline_resp = await client.post("/api/session/request", json=baseline_req)
        if "error" in baseline_resp:
            return f"Error getting baseline: {baseline_resp['error']}"

        baseline_status = baseline_resp.get("status", 0)
        baseline_length = baseline_resp.get("response_length", 0)
        baseline_body = baseline_resp.get("response_body", "")[:500]

        discovered = []
        tested = 0

        for param in candidates:
            tested += 1
            req: dict = {"session": session, "method": method}

            if param_type == "query":
                sep = "&" if "?" in path else "?"
                req["path"] = f"{path}{sep}{param}={baseline_value}"
            elif param_type == "body":
                req["path"] = path
                req["data"] = f"{param}={baseline_value}"
                req["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
            elif param_type == "json":
                req["path"] = path
                req["json_body"] = {param: baseline_value}
                req["headers"] = {"Content-Type": "application/json"}

            resp = await client.post("/api/session/request", json=req)
            if "error" in resp:
                continue

            status = resp.get("status", 0)
            length = resp.get("response_length", 0)
            body = resp.get("response_body", "")[:500]

            reasons = []
            if status != baseline_status:
                reasons.append(f"status {baseline_status}->{status}")
            if baseline_length > 0:
                diff_pct = abs(length - baseline_length) / baseline_length * 100
                if diff_pct > 10:
                    sign = "+" if length > baseline_length else "-"
                    reasons.append(f"{sign}{diff_pct:.0f}% length")
            if param in body and param not in baseline_body:
                reasons.append("reflected")

            if reasons:
                discovered.append({"name": param, "status": status, "length": length, "reasons": reasons})

        lines = [f"HIDDEN PARAMETER DISCOVERY"]
        lines.append(f"Target: {method} {path}")
        lines.append(f"Baseline: {baseline_status} ({baseline_length} bytes)")
        lines.append(f"Tested: {tested} parameters ({wordlist})\n")

        if discovered:
            lines.append(f"DISCOVERED ({len(discovered)}):")
            for d in discovered:
                reasons_str = ", ".join(d["reasons"])
                lines.append(f"  {d['name']:<20} -> {d['status']}, {d['length']}B ({reasons_str})")
        else:
            lines.append("No hidden parameters found.")

        lines.append(f"\nNO CHANGE: {tested - len(discovered)} parameters matched baseline")
        return "\n".join(lines)

    @mcp.tool()
    async def full_recon(
        session: str,
        depth: str = "standard",
    ) -> str:
        """Full reconnaissance pipeline in ONE call. Combines tech detection, endpoint mapping,
        security header audit, JS secret scanning, robots.txt, and sensitive file discovery.

        Depth levels:
        - quick: Tech stack + unique endpoints + security headers
        - standard: + JS secrets + robots.txt + forms
        - deep: + sensitive file discovery + all endpoint injection points

        Args:
            session: Session name with base_url configured
            depth: 'quick', 'standard', or 'deep'
        """
        lines = [f"FULL RECON (depth: {depth})\n"]

        # Step 1: Quick scan the root page
        root_req: dict = {"session": session, "method": "GET", "path": "/", "analyze": True}
        root_resp = await client.post("/api/session/request", json=root_req)
        if "error" in root_resp:
            return f"Error: {root_resp['error']}"

        root_index = root_resp.get("proxy_index", -1)
        analysis = root_resp.get("analysis", {})

        # Tech stack
        techs = analysis.get("tech_stack", {}).get("technologies", [])
        if techs:
            lines.append(f"TECH STACK: {', '.join(techs)}")

        # Security headers with scoring
        present = []
        missing = []
        sec_headers = analysis.get("tech_stack", {}).get("security_headers", {})
        for h, v in sec_headers.items():
            (present if v else missing).append(h)

        from burpsuite_mcp.tools.analyze import _score_security_headers
        lines.append(_score_security_headers(present, missing))

        # Endpoints
        ep_data = await client.get("/api/analysis/unique-endpoints", params={"limit": "100"})
        endpoints = ep_data.get("endpoints", []) if "error" not in ep_data else []
        lines.append(f"\nENDPOINTS: {len(endpoints)} unique")
        for ep in endpoints[:15]:
            params = ep.get("parameters", [])
            param_str = f" (params: {', '.join(params)})" if params else ""
            lines.append(f"  [{ep.get('status_code', '?')}] {ep['endpoint']}{param_str}")
        if len(endpoints) > 15:
            lines.append(f"  ... and {len(endpoints) - 15} more")

        if depth in ("standard", "deep"):
            # JS secrets: fetch page resources then scan
            if root_index >= 0:
                page_res = await client.post("/api/resources/fetch-page", json={"index": root_index})
                if "error" not in page_res:
                    fetched = page_res.get("newly_fetched", [])
                    js_secrets = []
                    for res in fetched[:5]:
                        idx = res.get("proxy_index", -1)
                        if idx >= 0 and res.get("url", "").endswith(".js"):
                            sec_data = await client.post("/api/analysis/js-secrets", json={"index": idx})
                            if "error" not in sec_data:
                                for s in sec_data.get("secrets", []):
                                    js_secrets.append(s)

                    if js_secrets:
                        lines.append(f"\nJS SECRETS: {len(js_secrets)} found")
                        for s in js_secrets[:10]:
                            lines.append(f"  [{s.get('severity', '?')}] {s.get('type', '?')}: {s.get('match', '?')[:60]}")

            # Robots.txt
            robots = await client.post("/api/session/request", json={
                "session": session, "method": "GET", "path": "/robots.txt",
            })
            if "error" not in robots and robots.get("status") == 200:
                body = robots.get("response_body", "")
                disallowed = [l.split(":")[1].strip() for l in body.split("\n")
                              if l.lower().startswith("disallow:") and l.split(":")[1].strip()]
                if disallowed:
                    lines.append(f"\nROBOTS.TXT: {len(disallowed)} disallowed")
                    for d in disallowed[:10]:
                        lines.append(f"  {d}")

        if depth == "deep":
            # Sensitive file discovery (top 15 paths)
            sensitive_paths = [
                "/.git/HEAD", "/.env", "/robots.txt", "/.htaccess",
                "/web.config", "/phpinfo.php", "/actuator", "/actuator/env",
                "/swagger.json", "/api-docs", "/openapi.json",
                "/.svn/entries", "/.DS_Store", "/server-status", "/debug/",
            ]
            found_files = []
            for sp in sensitive_paths:
                resp = await client.post("/api/session/request", json={
                    "session": session, "method": "GET", "path": sp,
                })
                if "error" not in resp:
                    status = resp.get("status", 0)
                    length = resp.get("response_length", 0)
                    if status == 200 and length > 0:
                        found_files.append(f"{sp} ({length}B)")
                    elif status == 403:
                        found_files.append(f"{sp} (403 - exists but blocked)")

            if found_files:
                lines.append(f"\nSENSITIVE FILES: {len(found_files)} found")
                for f in found_files:
                    lines.append(f"  {f}")

        # Attack priorities
        priorities = []
        for ep in endpoints:
            ep_risks = set()
            for p in ep.get("parameters", []):
                risks = _classify_param_risk(p)
                ep_risks.update(risks)
            if ep_risks:
                priorities.append((ep, sorted(ep_risks)))

        if priorities:
            lines.append(f"\nATTACK PRIORITIES:")
            for i, (ep, risks) in enumerate(priorities[:10], 1):
                lines.append(f"  {i}. {ep['endpoint']} -> {', '.join(risks)}")

        return "\n".join(lines)

    @mcp.tool()
    async def bulk_test(
        session: str,
        vulnerability: str,
        targets: list[dict] | None = None,
        max_endpoints: int = 10,
    ) -> str:
        """Test multiple endpoints for a specific vulnerability type in ONE call.
        Auto-selects relevant payloads from knowledge base.

        Args:
            session: Session name
            vulnerability: Vulnerability type - 'sqli', 'xss', 'lfi', 'open_redirect', 'ssrf', 'ssti', 'command_injection'
            targets: [{"path": "/api/users", "parameter": "id", "method": "GET"}] - auto-discover if None
            max_endpoints: Max endpoints to test (default 10)
        """
        # Quick payload sets per vulnerability type
        payload_sets = {
            "sqli": {
                "payloads": ["'", "1 OR 1=1--", "1' AND SLEEP(3)--", "1 UNION SELECT NULL--"],
                "indicators": ["sql", "syntax", "mysql", "ora-", "postgresql", "sqlite", "unclosed quotation"],
            },
            "xss": {
                "payloads": ["<script>alert(1)</script>", "\" onmouseover=alert(1)", "<img src=x onerror=alert(1)>", "'-alert(1)-'"],
                "indicators": [],  # Check reflection
            },
            "lfi": {
                "payloads": ["../../../etc/passwd", "....//....//....//etc/passwd", "..%252f..%252f..%252fetc/passwd", "/etc/passwd"],
                "indicators": ["root:x:", "root:*:", "/bin/bash", "/bin/sh"],
            },
            "open_redirect": {
                "payloads": [],  # Populated dynamically with Collaborator URL
                "indicators": [],  # Checked via Location header + Collaborator
                "uses_collaborator": True,
            },
            "ssrf": {
                "payloads": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22", "http://[::1]/"],
                "indicators": ["ami-id", "instance-id", "ssh", "openssl"],
            },
            "ssti": {
                "payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"],
                "indicators": ["49"],  # 7*7=49
            },
            "command_injection": {
                "payloads": ["; id", "| id", "$(id)", "`id`"],
                "indicators": ["uid=", "gid=", "groups="],
            },
        }

        if vulnerability not in payload_sets:
            return f"Error: Unknown vulnerability '{vulnerability}'. Options: {', '.join(payload_sets.keys())}"

        vconfig = payload_sets[vulnerability]

        # For open_redirect, generate Collaborator-based payloads
        collab_host = ""
        if vconfig.get("uses_collaborator"):
            collab = await client.post("/api/collaborator/payload")
            if "error" in collab:
                return f"Error: open_redirect requires Burp Collaborator: {collab['error']}"
            collab_url = collab.get("payload", "")
            collab_host = collab_url.replace("http://", "").replace("https://", "").split("/")[0]
            if not collab_host:
                return "Error: Could not get Collaborator host."
            vconfig["payloads"] = [
                f"https://{collab_host}",
                f"//{collab_host}",
                f"\\/\\/{collab_host}",
                f"//{collab_host}%2F%2F",
            ]

        # Auto-discover targets if not provided
        if not targets:
            ep_data = await client.get("/api/analysis/unique-endpoints", params={"limit": str(max_endpoints * 3)})
            if "error" in ep_data:
                return f"Error: {ep_data['error']}"
            auto_targets = []
            for ep in ep_data.get("endpoints", []):
                params = ep.get("parameters", [])
                if params:
                    endpoint = ep.get("endpoint", "")
                    # Extract method and path
                    parts = endpoint.split(" ", 1)
                    ep_method = parts[0] if len(parts) > 1 else "GET"
                    ep_path = parts[1] if len(parts) > 1 else parts[0]
                    for p in params:
                        auto_targets.append({"method": ep_method, "path": ep_path, "parameter": p})
            targets = auto_targets[:max_endpoints]

        if not targets:
            return "No targets found. Browse the target first or provide targets manually."

        lines = [f"BULK TEST: {vulnerability} across {len(targets)} targets\n"]
        findings = []
        total_requests = 0

        for t in targets[:max_endpoints]:
            t_method = t.get("method", "GET")
            t_path = t.get("path", "/")
            t_param = t.get("parameter", "")
            if not t_param:
                continue

            # Baseline
            baseline_resp = await client.post("/api/session/request", json={
                "session": session, "method": t_method, "path": t_path,
            })
            if "error" in baseline_resp:
                continue
            baseline_status = baseline_resp.get("status", 0)
            baseline_length = baseline_resp.get("response_length", 0)
            baseline_body = baseline_resp.get("response_body", "")

            for payload in vconfig["payloads"]:
                total_requests += 1
                sep = "&" if "?" in t_path else "?"
                inject_path = f"{t_path}{sep}{t_param}={payload}"

                resp = await client.post("/api/session/request", json={
                    "session": session, "method": t_method, "path": inject_path,
                })
                if "error" in resp:
                    continue

                status = resp.get("status", 0)
                length = resp.get("response_length", 0)
                body = resp.get("response_body", "")
                time_ms = resp.get("time_ms", 0)

                finding_reasons = []

                # Check indicators (only flag if NEW — not present in baseline)
                for ind in vconfig["indicators"]:
                    if ind.lower() in body.lower() and ind.lower() not in baseline_body.lower():
                        finding_reasons.append(f"indicator: {ind}")

                # Check reflection for XSS
                if vulnerability == "xss" and payload in body:
                    finding_reasons.append("reflected in response")

                # Check Location header for redirects (using Collaborator URL)
                if vulnerability == "open_redirect" and collab_host:
                    for h in resp.get("response_headers", []):
                        if h["name"].lower() == "location" and collab_host in h["value"]:
                            finding_reasons.append(f"redirect to Collaborator: {h['value'][:50]}")

                # Check timing anomaly
                if time_ms > 3000 and "SLEEP" in payload.upper():
                    finding_reasons.append(f"timing: {time_ms}ms")

                # Status anomaly
                if status == 500 and baseline_status != 500:
                    finding_reasons.append("500 error (possible injection)")

                if finding_reasons:
                    severity = "HIGH" if any("indicator" in r or "timing" in r for r in finding_reasons) else "MEDIUM"
                    findings.append({
                        "severity": severity,
                        "endpoint": f"{t_method} {t_path}",
                        "parameter": t_param,
                        "payload": payload,
                        "reasons": finding_reasons,
                    })

        if findings:
            lines.append(f"FINDINGS ({len(findings)}):")
            for f in findings:
                reasons_str = ", ".join(f["reasons"])
                lines.append(f"  [{f['severity']}] {f['endpoint']}?{f['parameter']}=")
                lines.append(f"    Payload: {f['payload']}")
                lines.append(f"    Evidence: {reasons_str}")
                lines.append("")
        else:
            lines.append("No findings.")

        # For open_redirect: poll Collaborator to confirm real interactions
        if vulnerability == "open_redirect" and collab_host:
            await asyncio.sleep(5)
            interactions_data = await client.get("/api/collaborator/interactions")
            interactions = interactions_data.get("interactions", []) if "error" not in interactions_data else []
            if interactions:
                lines.append(f"\nCOLLABORATOR CONFIRMED: {len(interactions)} interaction(s) detected")
                for hit in interactions[:5]:
                    lines.append(f"  [{hit.get('type', '?')}] from {hit.get('client_ip', '?')}")
                lines.append("  Open redirect CONFIRMED — server followed redirect to Collaborator.")
            elif findings:
                lines.append(f"\nNo Collaborator interactions (Location header showed redirect but server may not follow).")

        clean = len(targets) - len(set(f"{f['endpoint']}?{f['parameter']}" for f in findings))
        lines.append(f"CLEAN: {clean} endpoints showed no anomalies")
        lines.append(f"TESTED: {len(targets)} targets, {total_requests} requests total")

        return "\n".join(lines)
