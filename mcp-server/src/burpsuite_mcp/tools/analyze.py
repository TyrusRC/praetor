"""Tools for analyzing attack surface - extract parameters, forms, endpoints, injection points."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


# Security header scoring with severity and description
_SECURITY_HEADERS = {
    "Content-Security-Policy": {"severity": "HIGH", "desc": "Prevents XSS and data injection attacks"},
    "Strict-Transport-Security": {"severity": "HIGH", "desc": "Enforces HTTPS connections"},
    "X-Content-Type-Options": {"severity": "MEDIUM", "desc": "Prevents MIME-type sniffing"},
    "X-Frame-Options": {"severity": "MEDIUM", "desc": "Prevents clickjacking attacks"},
    "Permissions-Policy": {"severity": "LOW", "desc": "Controls browser feature access"},
    "Referrer-Policy": {"severity": "LOW", "desc": "Controls referrer information leakage"},
    "X-XSS-Protection": {"severity": "INFO", "desc": "Legacy XSS filter (deprecated but shows awareness)"},
    "Cross-Origin-Opener-Policy": {"severity": "LOW", "desc": "Isolates browsing context"},
    "Cross-Origin-Resource-Policy": {"severity": "LOW", "desc": "Controls cross-origin resource loading"},
}


def _score_security_headers(present: list[str], missing: list[str]) -> str:
    """Generate security header score card."""
    lines = ["\nSECURITY HEADER SCORE:"]
    score = 0
    total = len(_SECURITY_HEADERS)

    for header, info in _SECURITY_HEADERS.items():
        found = any(header.lower() in p.lower() for p in present)
        if found:
            score += 1
            lines.append(f"  + {header}")
        else:
            lines.append(f"  - {header}: MISSING ({info['severity']}) -- {info['desc']}")

    pct = (score / total * 100) if total > 0 else 0
    if pct >= 80:
        grade = "A"
    elif pct >= 60:
        grade = "B"
    elif pct >= 40:
        grade = "C"
    elif pct >= 20:
        grade = "D"
    else:
        grade = "F"

    lines.append(f"\n  Grade: {grade} ({score}/{total} headers present)")

    high_missing = [h for h, info in _SECURITY_HEADERS.items()
                    if info["severity"] == "HIGH" and not any(h.lower() in p.lower() for p in present)]
    if high_missing:
        lines.append(f"  Reportable: Missing {', '.join(high_missing)}")

    return "\n".join(lines)


def register(mcp: FastMCP):

    @mcp.tool()
    async def extract_api_endpoints(index: int) -> str:
        """Extract API endpoints, JS fetch calls, and links from a response.

        Args:
            index: Proxy history index
        """
        data = await client.post("/api/analysis/endpoints", json={"index": index})
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Endpoint extraction (total: {data.get('total_found', 0)}):\n"]

        for section, key in [
            ("API Endpoints", "api_endpoints"),
            ("JS Fetch/Ajax Calls", "js_endpoints"),
            ("Links", "links"),
            ("External URLs", "external_urls"),
        ]:
            items = data.get(key, [])
            if items:
                lines.append(f"--- {section} ({len(items)}) ---")
                for item in items[:50]:  # cap at 50 per section
                    lines.append(f"  {item}")
                if len(items) > 50:
                    lines.append(f"  ... and {len(items) - 50} more")
                lines.append("")

        return "\n".join(lines)

    @mcp.tool()
    async def detect_tech_stack(index: int) -> str:
        """Detect technology stack and audit security headers from a response.

        Args:
            index: Proxy history index
        """
        data = await client.post("/api/analysis/tech-stack", json={"index": index})
        if "error" in data:
            return f"Error: {data['error']}"

        lines = ["Technology Stack Detection:\n"]

        techs = data.get("technologies", [])
        if techs:
            lines.append("--- Technologies ---")
            for t in techs:
                lines.append(f"  - {t}")
            lines.append("")

        present = data.get("security_headers_present", [])
        if present:
            lines.append("--- Security Headers (Present) ---")
            for h in present:
                lines.append(f"  [OK] {h}")
            lines.append("")

        missing = data.get("security_headers_missing", [])
        if missing:
            lines.append("--- Security Headers (MISSING) ---")
            for h in missing:
                lines.append(f"  [!!] {h}")

        # Security header scoring
        result = "\n".join(lines)
        result += _score_security_headers(present, missing)

        return result

    @mcp.tool()
    async def extract_js_secrets(index: int) -> str:
        """Extract secrets, API keys, tokens, and sensitive data from a response.

        Args:
            index: Proxy history index
        """
        data = await client.post("/api/analysis/js-secrets", json={"index": index})
        if "error" in data:
            return f"Error: {data['error']}"

        secrets = data.get("secrets", [])
        total = data.get("total_secrets", 0)

        if not secrets:
            return "No secrets or sensitive data found in this response."

        lines = [f"Secrets Found: {total}\n"]

        for s in secrets:
            severity = s.get("severity", "?")
            stype = s.get("type", "Unknown")
            match = s.get("match", "")
            context = s.get("context", "")

            lines.append(f"[{severity}] {stype}")
            lines.append(f"  Match: {match}")
            if context:
                lines.append(f"  Context: ...{context}...")
            lines.append("")

        return "\n".join(lines)

    @mcp.tool()
    async def get_unique_endpoints(url_prefix: str = "", limit: int = 30) -> str:
        """Get deduplicated endpoints from proxy history with parameter names.

        Args:
            url_prefix: Filter by URL prefix
            limit: Max endpoints to return
        """
        params = {"limit": limit}
        if url_prefix:
            params["prefix"] = url_prefix

        data = await client.get("/api/analysis/unique-endpoints", params=params)
        if "error" in data:
            return f"Error: {data['error']}"

        endpoints = data.get("endpoints", [])
        if not endpoints:
            return "No endpoints found. Browse the target first."

        lines = [f"Unique Endpoints ({data.get('total', 0)}):\n"]
        for ep in endpoints:
            status = ep.get("status_code", "")
            lines.append(f"[{status}] {ep['endpoint']}")
            params_list = ep.get("parameters", [])
            if params_list:
                lines.append(f"     Params: {', '.join(params_list)}")

        return "\n".join(lines)

    @mcp.tool()
    async def smart_analyze(index: int, summary_only: bool = False) -> str | dict:  # cost: cheap (single index, batched analysis)
        """Full attack surface analysis in ONE call: tech stack, injection points, params, forms, endpoints, secrets.

        Args:
            index: Proxy history index
            summary_only: Return compact dict (tech_stack, top-5 injection points,
                param counts, form count) — ≤1000 tokens. Use for triage; pass
                False to get the full multi-section narrative.
        """
        data = await client.post("/api/analysis/smart", json={"index": index})
        if "error" in data:
            return {"error": data["error"]} if summary_only else f"Error: {data['error']}"

        if summary_only:
            tech = data.get("tech_stack", {})
            params = data.get("parameters", {})
            injection_block = data.get("injection_points", {})
            injection_list = (
                injection_block.get("injection_points", [])
                if isinstance(injection_block, dict) else []
            )
            forms = data.get("forms", {})
            endpoints = data.get("endpoints", {})
            secrets = data.get("secrets", {})
            return {
                "method": data.get("method"),
                "url": data.get("url"),
                "tech_stack": tech.get("technologies", []),
                "missing_security_headers": tech.get("security_headers_missing", []),
                "param_counts": {
                    "query":  len(params.get("query_parameters", []) or []),
                    "body":   len(params.get("body_parameters", []) or []),
                    "cookie": len(params.get("cookie_parameters", []) or []),
                },
                "top_injection_points": [
                    {
                        "name": ip.get("name"),
                        "location": ip.get("location") or ip.get("type"),
                        "vulns": ip.get("potential_vulnerabilities") or ip.get("types") or [],
                        "risk_score": ip.get("risk_score", 0),
                    }
                    for ip in sorted(injection_list, key=lambda x: -x.get("risk_score", 0))[:5]
                ],
                "form_count": len(forms.get("forms", []) or []),
                "api_endpoint_count": len(endpoints.get("api_endpoints", []) or []),
                "secret_count": len(secrets.get("secrets", []) or []),
                "top_secrets": [
                    {"type": s.get("type"), "severity": s.get("severity"), "match": (s.get("match") or "")[:80]}
                    for s in (secrets.get("secrets") or [])[:3]
                ],
            }

        lines = [f"Smart Analysis: [{data.get('method')}] {data.get('url')}\n"]

        # Tech stack
        tech = data.get("tech_stack", {})
        techs = tech.get("technologies", [])
        if techs:
            lines.append(f"Tech Stack: {', '.join(techs)}")
        # TechStackDetector emits `security_headers_missing` as a list. Prior
        # code read `security_headers` as a bool-dict and always produced [].
        missing = tech.get("security_headers_missing", [])
        if missing:
            lines.append(f"Missing Security Headers: {', '.join(missing)}")
        present = tech.get("security_headers_present", [])
        if present:
            lines.append(f"Security Headers Present: {len(present)}")

        # Parameters. ParameterExtractor emits `query_parameters`,
        # `body_parameters`, `cookie_parameters` (NOT `query`/`body`/`cookie`).
        params = data.get("parameters", {})
        for location, server_key in (("query", "query_parameters"),
                                     ("body", "body_parameters"),
                                     ("cookie", "cookie_parameters")):
            param_list = params.get(server_key, [])
            if param_list:
                names = [p.get("name", "?") for p in param_list] if isinstance(param_list, list) else []
                if names:
                    lines.append(f"Params ({location}): {', '.join(names)}")

        # Injection points. InjectionPointDetector emits a flat list under
        # `injection_points` (already sorted by risk_score desc). There's no
        # `.high_risk` sub-key — prior code always produced empty output.
        injection_block = data.get("injection_points", {})
        injection_list = injection_block.get("injection_points", []) if isinstance(injection_block, dict) else []
        # Keep only the risky ones so low-signal cookies don't dominate output
        high_risk = [ip for ip in injection_list if ip.get("risk_score", 0) >= 1]
        if high_risk:
            lines.append(f"\nInjection Points ({len(high_risk)}):")
            for ip in high_risk[:10]:
                name = ip.get("name", "?")
                location = ip.get("location", ip.get("type", ""))
                types = ", ".join(ip.get("potential_vulnerabilities", ip.get("types", [])))
                score = ip.get("risk_score", 0)
                loc_str = f" ({location})" if location else ""
                lines.append(f"  {name}{loc_str} [{types}] (risk: {score})")

        # Forms
        forms = data.get("forms", {})
        form_list = forms.get("forms", [])
        if form_list:
            lines.append(f"\nForms ({len(form_list)}):")
            for f in form_list[:5]:
                action = f.get("action", "?")
                method = f.get("method", "GET")
                inputs = [i.get("name", "?") for i in f.get("inputs", [])]
                lines.append(f"  [{method}] {action} — inputs: {', '.join(inputs)}")

        # Endpoints
        endpoints = data.get("endpoints", {})
        api_paths = endpoints.get("api_endpoints", [])
        if api_paths:
            lines.append(f"\nAPI Endpoints ({len(api_paths)}):")
            for ep in api_paths[:10]:
                lines.append(f"  {ep}")

        # Secrets
        secrets = data.get("secrets", {})
        secret_list = secrets.get("secrets", [])
        if secret_list:
            lines.append(f"\nSecrets Found ({len(secret_list)}):")
            for s in secret_list[:5]:
                lines.append(f"  [{s.get('severity', '?')}] {s.get('type', '?')}: {s.get('match', '?')[:80]}")

        if len(lines) == 1:
            lines.append("No significant findings.")

        return "\n".join(lines)
