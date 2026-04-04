"""Persistent attack sessions — cookie jar, auth tokens, request crafting, multi-step flows."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def create_session(
        name: str,
        base_url: str,
        cookies: dict | None = None,
        headers: dict | None = None,
        bearer_token: str = "",
        auth_user: str = "",
        auth_pass: str = "",
    ) -> str:
        """Create a persistent attack session. Session stores cookies, headers, and auth tokens.
        Cookies auto-update from Set-Cookie responses. All subsequent session_request calls
        auto-apply this state.

        Args:
            name: Session name (e.g. 'admin', 'user_b')
            base_url: Target base URL (e.g. 'https://target.com')
            cookies: Initial cookies dict
            headers: Default headers for all requests
            bearer_token: Bearer token for Authorization header
            auth_user: Username for Basic auth
            auth_pass: Password for Basic auth
        """
        payload = {"name": name, "base_url": base_url}
        if cookies:
            payload["cookies"] = cookies
        if headers:
            payload["headers"] = headers
        if bearer_token:
            payload["bearer_token"] = bearer_token
        if auth_user:
            payload["auth_user"] = auth_user
        if auth_pass:
            payload["auth_pass"] = auth_pass

        data = await client.post("/api/session/create", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        has_auth = data.get("has_bearer", False) or data.get("has_basic_auth", False) or data.get("has_auth", False)
        return (
            f"Session '{data['session']}' created\n"
            f"  Base URL: {data['base_url']}\n"
            f"  Cookies: {data.get('cookies_count', data.get('cookies', 0))}"
            f", Headers: {data.get('headers_count', data.get('headers', 0))}"
            f", Auth: {has_auth}"
        )

    @mcp.tool()
    async def session_request(
        session: str,
        method: str,
        path: str,
        headers: dict | None = None,
        body: str = "",
        data: str = "",
        json_body: dict | None = None,
        cookies: dict | None = None,
        extract: dict | None = None,
        follow_redirects: bool = False,
    ) -> str:
        """Send HTTP request using a persistent session. Auto-applies cookies, auth, base URL.
        Cookie jar auto-updates from Set-Cookie responses.

        Use 'extract' to pull values from the response in the same call:
        extract={"csrf": {"from": "body", "regex": 'name="csrf" value="([^"]+)"'}}

        Args:
            session: Session name
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            path: Request path relative to session base_url (e.g. '/api/users/42')
            headers: Additional headers (merged with session defaults)
            body: Raw request body
            data: Form-encoded data (sets Content-Type automatically)
            json_body: JSON body dict (sets Content-Type automatically)
            cookies: Additional cookies (merged with session jar)
            extract: Inline extraction rules - {"var_name": {"from": "body|header|cookie", "regex|json_path|name": "..."}}
            follow_redirects: Follow 3xx redirects automatically (default False)
        """
        payload_dict: dict = {"session": session, "method": method, "path": path}
        if headers:
            payload_dict["headers"] = headers
        if body:
            payload_dict["body"] = body
        if data:
            payload_dict["data"] = data
        if json_body is not None:
            payload_dict["json_body"] = json_body
        if cookies:
            payload_dict["cookies"] = cookies
        if extract:
            payload_dict["extract"] = extract
        if follow_redirects:
            payload_dict["follow_redirects"] = True

        resp = await client.post("/api/session/request", json=payload_dict)
        if "error" in resp:
            return f"Error: {resp['error']}"

        lines = [f"Status: {resp.get('status')}"]
        lines.append(f"Response Length: {resp.get('response_length', 0)} bytes")

        extracted = resp.get("extracted", {})
        if extracted:
            lines.append("\nExtracted:")
            for k, v in extracted.items():
                display = v if len(str(v)) < 100 else str(v)[:100] + "..."
                lines.append(f"  {k} = {display}")

        resp_headers = resp.get("response_headers", [])
        if resp_headers:
            lines.append("\n--- Response Headers ---")
            for h in resp_headers:
                lines.append(f"  {h['name']}: {h['value']}")

        resp_body = resp.get("response_body", "")
        if resp_body:
            max_body = 2000
            lines.append(f"\n--- Response Body ({len(resp_body)} chars) ---")
            if len(resp_body) > max_body:
                lines.append(resp_body[:max_body] + f"\n...[truncated, {len(resp_body)} total chars]")
            else:
                lines.append(resp_body)

        return "\n".join(lines)

    @mcp.tool()
    async def extract_token(
        session: str,
        extract: dict,
    ) -> str:
        """Extract values from the last response in a session without making a new request.

        Args:
            session: Session name
            extract: Extraction rules - {"var_name": {"from": "body|header|cookie", "regex|json_path|name": "..."}}
        """
        payload = {"session": session, "rules": extract}
        resp = await client.post("/api/session/extract", json=payload)
        if "error" in resp:
            return f"Error: {resp['error']}"

        extracted = resp.get("extracted", {})
        if not extracted:
            return "No values matched extraction rules."

        lines = ["Extracted:"]
        for k, v in extracted.items():
            lines.append(f"  {k} = {v}")

        variables = resp.get("session_variables", {})
        if variables:
            lines.append(f"\nSession variables ({len(variables)} total):")
            for k, v in variables.items():
                display = v if len(str(v)) < 80 else str(v)[:80] + "..."
                lines.append(f"  {k} = {display}")

        return "\n".join(lines)

    @mcp.tool()
    async def run_flow(
        session: str,
        steps: list[dict],
    ) -> str:
        """Execute a multi-step attack flow in one call. Each step can extract variables
        that are available in subsequent steps via {{variable_name}} interpolation.
        Session cookies auto-update across all steps.

        Step format: {"method": "POST", "path": "/login", "data": "user=admin&csrf={{csrf}}",
                      "extract": {"csrf": {"from": "body", "regex": "csrf.*?value=\\"([^\\"]+)\\\""}}}

        Args:
            session: Session name
            steps: Ordered list of request steps with optional extraction
        """
        payload = {"session": session, "steps": steps}
        resp = await client.post("/api/session/flow", json=payload)
        if "error" in resp:
            return f"Error: {resp['error']}"

        lines = [f"Flow: {resp.get('steps_executed')}/{resp.get('total_steps')} steps executed\n"]

        for step in resp.get("results", []):
            method = step.get('method', '')
            path = step.get('path', '')
            label = f"{method} {path}" if method else f"#{step['step']}"
            status_str = f"Step {step['step']}: {label} -> {step['status']}"
            if step.get("stopped"):
                status_str += " STOPPED"
            lines.append(status_str)
            lines.append(f"  Response: {step.get('response_length', 0)} bytes")

            extracted = step.get("extracted", {})
            if extracted:
                for k, v in extracted.items():
                    display = v if len(str(v)) < 80 else str(v)[:80] + "..."
                    lines.append(f"  -> {k} = {display}")

            # Show body snippet (from Java side, max 500 chars)
            snippet = step.get("body_snippet") or step.get("response_body", "")
            if snippet:
                if len(snippet) > 500:
                    snippet = snippet[:500] + "..."
                lines.append(f"  Body: {snippet}")

        variables = resp.get("session_variables", {})
        if variables:
            lines.append(f"\nSession variables:")
            for k, v in variables.items():
                display = v if len(str(v)) < 80 else str(v)[:80] + "..."
                lines.append(f"  {k} = {display}")

        return "\n".join(lines)

    @mcp.tool()
    async def list_sessions() -> str:
        """List all active attack sessions with their state summary."""
        resp = await client.get("/api/session/list")
        if "error" in resp:
            return f"Error: {resp['error']}"

        sessions_list = resp.get("sessions", [])
        if not sessions_list:
            return "No active sessions."

        lines = [f"Active sessions ({resp.get('total_count', resp.get('total', 0))}):\n"]
        for s in sessions_list:
            auth = "yes" if s.get("has_bearer") or s.get("has_basic_auth") or s.get("has_auth") else "no"
            lines.append(f"  {s['name']} -> {s['base_url']}")
            cookies = s.get('cookies_count', s.get('cookies', 0))
            headers = s.get('headers_count', s.get('headers', 0))
            variables = s.get('variables_count', s.get('variables', 0))
            lines.append(f"    Cookies: {cookies}, Headers: {headers}, Variables: {variables}, Auth: {auth}")

        return "\n".join(lines)

    @mcp.tool()
    async def delete_session(name: str) -> str:
        """Delete an attack session.

        Args:
            name: Session name to delete
        """
        resp = await client.delete(f"/api/session/{name}")
        if "error" in resp:
            return f"Error: {resp['error']}"
        return resp.get("message", f"Session '{name}' deleted.")

    @mcp.tool()
    async def quick_scan(
        session: str,
        method: str,
        path: str,
        headers: dict | None = None,
        body: str = "",
        data: str = "",
        json_body: dict | None = None,
    ) -> str:
        """Send request + auto-analyze in ONE call. Returns: status, tech stack,
        injection points, parameters, forms, secrets — without the response body.
        Most token-efficient way to probe an endpoint.

        Use this instead of: session_request() + detect_tech_stack() + find_injection_points()

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
        if headers:
            payload["headers"] = headers
        if body:
            payload["body"] = body
        if data:
            payload["data"] = data
        if json_body is not None:
            payload["json_body"] = json_body

        resp = await client.post("/api/session/request", json=payload)
        if "error" in resp:
            return f"Error: {resp['error']}"

        lines = [f"Status: {resp.get('status')} | Length: {resp.get('response_length', 0)} bytes"]

        # Show extracted variables if any
        extracted = resp.get("extracted", {})
        if extracted:
            for k, v in extracted.items():
                lines.append(f"  {k} = {v}")

        # Show analysis results
        analysis = resp.get("analysis", {})
        if analysis:
            # Tech stack
            tech = analysis.get("tech_stack", {})
            techs = tech.get("technologies", [])
            if techs:
                lines.append(f"\nTech Stack: {', '.join(techs)}")
            missing = [k for k, v in tech.get("security_headers", {}).items() if not v]
            if missing:
                lines.append(f"Missing Headers: {', '.join(missing)}")

            # Injection points
            injection = analysis.get("injection_points", {})
            high_risk = injection.get("high_risk", [])
            if high_risk:
                lines.append(f"\nInjection Points ({len(high_risk)}):")
                for ip in high_risk[:10]:
                    lines.append(f"  {ip.get('name', '?')} [{', '.join(ip.get('types', []))}] risk={ip.get('risk_score', 0)}")

            # Parameters
            params = analysis.get("parameters", {})
            for loc in ["query", "body", "cookie"]:
                pl = params.get(loc, [])
                if pl:
                    names = [p.get("name", "?") for p in pl] if isinstance(pl, list) else []
                    if names:
                        lines.append(f"Params ({loc}): {', '.join(names)}")

            # Forms
            forms = analysis.get("forms", {})
            for f in forms.get("forms", [])[:3]:
                inputs = [i.get("name", "?") for i in f.get("inputs", [])]
                lines.append(f"Form: [{f.get('method', '?')}] {f.get('action', '?')} -> {', '.join(inputs)}")

            # Secrets
            for s in analysis.get("secrets", {}).get("secrets", [])[:3]:
                lines.append(f"Secret: [{s.get('severity')}] {s.get('type')}: {s.get('match', '?')[:60]}")
        else:
            lines.append("\n(No analysis available — endpoint may not be in proxy history)")

        return "\n".join(lines)

    @mcp.tool()
    async def probe_endpoint(
        session: str,
        method: str,
        path: str,
        parameter: str,
        baseline_value: str = "1",
        payload_value: str = "1'",
        injection_point: str = "query",
    ) -> str:
        """Probe a parameter for vulnerabilities: sends baseline request + payload request,
        auto-diffs responses, detects SQL/XSS/path traversal error patterns, measures timing.
        Replaces 3+ tool calls with 1.

        Args:
            session: Session name
            method: HTTP method
            path: Base endpoint path (e.g. '/showforum.asp')
            parameter: Parameter name to test (e.g. 'id')
            baseline_value: Normal/safe value (default '1')
            payload_value: Attack payload (e.g. "1'", "1 OR 1=1--")
            injection_point: Where to inject — 'query' or 'body'
        """
        payload = {
            "session": session, "method": method, "path": path,
            "parameter": parameter, "baseline_value": baseline_value,
            "payload_value": payload_value, "injection_point": injection_point,
        }
        data = await client.post("/api/session/probe", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Probe: {parameter}={data.get('payload_value')} (baseline: {data.get('baseline_value')})\n"]
        lines.append(f"  Baseline: {data.get('baseline_status')} | {data.get('baseline_length')}B | {data.get('baseline_time_ms')}ms")
        lines.append(f"  Payload:  {data.get('payload_status')} | {data.get('payload_length')}B | {data.get('payload_time_ms')}ms")

        if data.get("status_changed"):
            lines.append(f"\n  [!] Status changed: {data.get('baseline_status')} -> {data.get('payload_status')}")
        if data.get("length_diff", 0) > 100:
            lines.append(f"  [!] Length diff: {data.get('length_diff')} bytes")
        if data.get("time_diff_ms", 0) > 2000:
            lines.append(f"  [!] Timing anomaly: {data.get('time_diff_ms')}ms difference")
        if data.get("payload_reflected"):
            lines.append(f"  [!] Payload reflected in response")

        errors = data.get("error_patterns", [])
        if errors:
            lines.append(f"\n  Error Patterns Detected:")
            for e in errors:
                lines.append(f"    [{e.get('confidence')}] {e.get('type')}: {e.get('description')} ({e.get('database', 'generic')})")

        findings = data.get("findings", [])
        if findings:
            lines.append(f"\n  Findings:")
            for f in findings:
                lines.append(f"    -> {f}")

        if data.get("likely_vulnerable"):
            lines.append(f"\n  *** LIKELY VULNERABLE ***")
        else:
            lines.append(f"\n  No obvious vulnerability detected.")

        return "\n".join(lines)

    @mcp.tool()
    async def batch_probe(
        session: str,
        endpoints: list[dict],
    ) -> str:
        """Test multiple endpoints in ONE call. Returns status, length, timing for each.
        92% fewer tokens vs individual session_request calls.

        Args:
            session: Session name
            endpoints: List of endpoints - [{"method": "GET", "path": "/api/users"}, {"method": "POST", "path": "/login", "data": "user=test"}]
        """
        payload = {"session": session, "endpoints": endpoints}
        data = await client.post("/api/session/batch", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Batch Probe: {data.get('total_endpoints')} endpoints in {data.get('total_time_ms')}ms\n"]

        dist = data.get("status_distribution", {})
        if dist:
            dist_str = ", ".join(f"{s}x{c}" for s, c in dist.items())
            lines.append(f"Status: {dist_str}\n")

        for r in data.get("results", []):
            title = r.get("title", "")
            title_str = f" [{title}]" if title else ""
            lines.append(f"  {r.get('method', '?'):6s} {r.get('path', '?'):<40s} {r['status']} | {r['length']:>6}B | {r['time_ms']:>4}ms{title_str}")

        return "\n".join(lines)
