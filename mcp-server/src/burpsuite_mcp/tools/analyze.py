"""Tools for analyzing attack surface - extract parameters, forms, endpoints, injection points."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def extract_parameters(index: int) -> str:
        """Extract all parameters from a proxy history request (by index).
        Shows query params, body params, cookies - grouped by location.
        Use this to understand what inputs an endpoint accepts."""
        data = await client.post("/api/analysis/parameters", json={"index": index})
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Parameters for [{data.get('method')}] {data.get('url')}"]
        lines.append(f"Content-Type: {data.get('content_type', 'unknown')}")
        lines.append(f"Total: {data.get('total_parameters', 0)} parameters\n")

        for section, key in [("Query", "query_parameters"), ("Body", "body_parameters"), ("Cookie", "cookie_parameters")]:
            params = data.get(key, [])
            if params:
                lines.append(f"--- {section} Parameters ({len(params)}) ---")
                for p in params:
                    val = p.get("value", "")
                    display_val = val[:100] + "..." if len(val) > 100 else val
                    lines.append(f"  {p['name']} = {display_val}")
                lines.append("")

        json_body = data.get("json_body")
        if json_body:
            lines.append("--- JSON Body ---")
            lines.append(json_body)

        return "\n".join(lines)

    @mcp.tool()
    async def extract_forms(index: int) -> str:
        """Extract HTML forms from a proxy history response (by index).
        Shows form action, method, and all input fields - useful for finding submission endpoints."""
        data = await client.post("/api/analysis/forms", json={"index": index})
        if "error" in data:
            return f"Error: {data['error']}"

        forms = data.get("forms", [])
        if not forms:
            return "No HTML forms found in this response."

        lines = [f"Found {data.get('total_forms', 0)} form(s):\n"]
        for i, form in enumerate(forms):
            lines.append(f"--- Form #{i + 1} ---")
            lines.append(f"  Action: {form.get('action', '(none)')}")
            lines.append(f"  Method: {form.get('method', 'GET')}")
            if form.get("enctype"):
                lines.append(f"  Enctype: {form['enctype']}")
            lines.append("  Inputs:")
            for inp in form.get("inputs", []):
                input_type = inp.get("type", "text")
                name = inp.get("name", "(unnamed)")
                value = inp.get("value", "")
                lines.append(f"    [{input_type}] {name}" + (f" = {value}" if value else ""))
            lines.append("")

        return "\n".join(lines)

    @mcp.tool()
    async def extract_api_endpoints(index: int) -> str:
        """Extract API endpoints, JS fetch calls, and links from a proxy history response.
        Discovers hidden endpoints, external URLs, and JavaScript API calls."""
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
    async def find_injection_points(index: int) -> str:
        """Analyze a proxy history request/response for potential injection points.
        Identifies reflected parameters, common SQLi/XSS/SSRF/path traversal parameter names,
        IDOR patterns, and response-level indicators (error messages, SQL keywords, debug info).
        Returns risk-scored results to help prioritize testing."""
        data = await client.post("/api/analysis/injection-points", json={"index": index})
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Injection Point Analysis for [{data.get('method')}] {data.get('url')}"]
        lines.append(f"Total injection points: {data.get('total_injection_points', 0)}\n")

        for point in data.get("injection_points", []):
            risk = point.get("risk_score", 0)
            lines.append(f"[Risk: {risk}] {point['name']} ({point['location']})")
            lines.append(f"  Value: {point.get('value', '')}")
            for vuln in point.get("potential_vulnerabilities", []):
                lines.append(f"  ! {vuln}")
            lines.append("")

        # Response indicators
        indicators = data.get("response_indicators", {})
        if indicators:
            lines.append("--- Response Indicators ---")
            for key, val in indicators.items():
                if val and val is not True:
                    lines.append(f"  {key}: {val}")
                elif val is True:
                    lines.append(f"  {key}: YES")

        return "\n".join(lines)

    @mcp.tool()
    async def detect_tech_stack(index: int) -> str:
        """Detect the technology stack from a proxy history response.
        Identifies server software, frameworks, CMS, JS libraries, and checks security headers."""
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

        return "\n".join(lines)

    @mcp.tool()
    async def extract_js_secrets(index: int) -> str:
        """Extract potential secrets, API keys, tokens, and sensitive data from a response.
        Scans for AWS keys, GitHub tokens, JWTs, passwords in code, internal URLs, database URLs, etc.
        Run this on JavaScript files and API responses to find hardcoded secrets.

        Args:
            index: Proxy history index of the response to analyze
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
    async def get_unique_endpoints(url_prefix: str = "", limit: int = 200) -> str:
        """Get deduplicated endpoints from proxy history with their parameters.
        Groups by method + path, shows all parameter names per endpoint.
        Great for getting an overview of the entire attack surface."""
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
