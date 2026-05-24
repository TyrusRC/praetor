"""recorded_login — convert captured login indices into a replayable macro.

Operator browses the login flow once (browser_navigate + browser_fill +
browser_submit_form). Each step lands in proxy history. Pass the index
list here; tool fetches each request, packages as macro steps with token
extraction from the final response, and creates the macro. Replay via
run_macro(name) -> emits {auth_token, session_cookie, ...} for subsequent
session_request calls.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


_TOKEN_EXTRACT_DEFAULTS = [
    {"name": "auth_token", "from": "header", "field": "Authorization", "regex": r"Bearer\s+([\w\-\._=]+)"},
    {"name": "session_cookie", "from": "header", "field": "Set-Cookie", "regex": r"(?:session|sid|connect\.sid|_session)=([^;]+)"},
    {"name": "csrf_token", "from": "header", "field": "Set-Cookie", "regex": r"(?:csrf|xsrf)[-_]?token=([^;]+)"},
    {"name": "jwt", "from": "body", "field": "", "regex": r"\"(?:token|access_token|id_token|jwt)\"\s*:\s*\"([\w\-\._]+)\""},
]


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def recorded_login(
        name: str,
        indices: list[int],
        description: str = "Recorded login flow",
        token_extractors: list[dict] | None = None,
    ) -> str:
        """Bundle captured proxy indices into a replayable login macro.

        Args:
            name: macro name (unique).
            indices: ordered proxy history indices forming the login flow.
            description: human-readable description.
            token_extractors: list of {name, from='header'|'body', field, regex}
                applied to the LAST step's response. Default extracts
                Authorization bearer, session cookies, CSRF, and common
                JSON token keys.
        """
        if not indices:
            return "Error: indices list empty."

        steps: list[dict] = []
        for i, idx in enumerate(indices):
            entry = await client.get(f"/api/proxy/{idx}")
            if "error" in entry:
                return f"Error fetching index {idx}: {entry['error']}"
            step = {
                "method": entry.get("method", "GET"),
                "url": entry.get("url", ""),
                "headers": entry.get("request_headers", []),
                "body": entry.get("request_body", ""),
            }
            if i == len(indices) - 1:
                step["extract"] = token_extractors or _TOKEN_EXTRACT_DEFAULTS
            steps.append(step)

        payload = {"name": name, "description": description, "steps": steps}
        data = await client.post("/api/macro/create", json=payload)
        if "error" in data:
            return f"Error creating macro: {data['error']}"

        return (
            f"Recorded login macro '{name}' created with {len(steps)} steps.\n"
            f"Replay: run_macro('{name}')  -> emits extracted variables\n"
            f"CI use:  run_macro('{name}') before each authenticated scan."
        )
