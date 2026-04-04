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
            lines.append(f"\n--- Response Body ({len(resp_body)} chars) ---")
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

            if step.get("response_body"):
                resp_body = step["response_body"]
                if len(resp_body) > 500:
                    resp_body = resp_body[:500] + "..."
                lines.append(f"  Body: {resp_body}")

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
