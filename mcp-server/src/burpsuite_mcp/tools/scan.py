"""Adaptive scan engine — discover attack surface and auto-probe with knowledge-driven detection."""

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


def _load_all_knowledge(categories: list[str] | None = None) -> list[dict]:
    """Load all knowledge base files, optionally filtered by category."""
    if not KNOWLEDGE_DIR.exists():
        return []
    available = [f.stem for f in KNOWLEDGE_DIR.glob("*.json")]
    if categories:
        available = [c for c in available if c in categories]
    result = []
    for cat in available:
        kb = _load_knowledge(cat)
        if kb:
            result.append(kb)
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
            available = [f.stem for f in KNOWLEDGE_DIR.glob("*.json")]
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
            return await _do_discover(session, max_pages)
        elif mode == "probe":
            if not targets:
                return "Error: 'targets' required for mode='probe'. Run with mode='discover' first."
            return await _do_auto_probe(session, targets, categories, max_probes_per_param)
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
