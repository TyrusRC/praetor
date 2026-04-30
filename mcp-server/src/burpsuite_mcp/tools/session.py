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
        """Create a persistent attack session with auto-updating cookies and auth state.

        Args:
            name: Session name
            base_url: Target base URL
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
        full_body: bool = False,
    ) -> str:
        """Send HTTP request using a persistent session with auto-applied auth and cookies.

        Args:
            session: Session name
            method: HTTP method
            path: Request path relative to session base_url
            headers: Additional headers merged with session defaults
            body: Raw request body
            data: Form-encoded data
            json_body: JSON body dict
            cookies: Additional cookies merged with session jar
            extract: Inline extraction rules for response values
            follow_redirects: Follow 3xx redirects
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
            max_body = 0 if full_body else 2000
            lines.append(f"\n--- Response Body ({len(resp_body)} chars) ---")
            if max_body > 0 and len(resp_body) > max_body:
                lines.append(resp_body[:max_body] + f"\n...[truncated — use full_body=True for complete response]")
            else:
                lines.append(resp_body)

        return "\n".join(lines)

    @mcp.tool()
    async def extract_token(
        session: str,
        extract: dict,
    ) -> str:
        """Extract values from the last session response without a new request.

        Args:
            session: Session name
            extract: Extraction rules keyed by variable name
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
        """Execute a multi-step attack flow in one call with variable interpolation between steps.

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

    # Probe tools (quick_scan, probe_endpoint, batch_probe) moved to scan.py
