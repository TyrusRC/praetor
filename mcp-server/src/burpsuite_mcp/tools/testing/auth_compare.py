"""compare_auth_states — replay one captured request under two auth states and diff."""

import asyncio

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def compare_auth_states(
        index: int,
        original_cookies: dict | None = None,
        alt_cookies: dict | None = None,
        original_token: str = "",
        alt_token: str = "",
        remove_auth: bool = False,
    ) -> str:
        """Compare responses between auth states to detect IDOR/auth bypass.

        Args:
            index: Proxy history index of the request to test
            original_cookies: Cookies for first request
            alt_cookies: Cookies for second request (different user)
            original_token: Bearer token for first request
            alt_token: Bearer token for second request
            remove_auth: Strip all auth from second request
        """
        # First request: original or with specified auth
        modify1: dict = {"index": index}
        if original_cookies:
            cookie_str = "; ".join(
                f"{k}={v.replace(';', '%3B')}" for k, v in original_cookies.items()
            )
            modify1["modify_headers"] = {"Cookie": cookie_str}
        if original_token:
            headers = modify1.get("modify_headers", {})
            headers["Authorization"] = f"Bearer {original_token}"
            modify1["modify_headers"] = headers

        # Second request: alternate auth or no auth
        modify2: dict = {"index": index}
        if alt_cookies:
            cookie_str = "; ".join(
                f"{k}={v.replace(';', '%3B')}" for k, v in alt_cookies.items()
            )
            modify2["modify_headers"] = {"Cookie": cookie_str}
        if alt_token:
            headers = modify2.get("modify_headers", {})
            headers["Authorization"] = f"Bearer {alt_token}"
            modify2["modify_headers"] = headers
        if remove_auth:
            modify2["modify_headers"] = {"Cookie": "", "Authorization": ""}

        # Send both requests concurrently for accurate comparison
        data1, data2 = await asyncio.gather(
            client.post("/api/http/resend", json=modify1),
            client.post("/api/http/resend", json=modify2),
        )

        if "error" in data1:
            return f"Error (request 1): {data1['error']}"
        if "error" in data2:
            return f"Error (request 2): {data2['error']}"

        status1 = data1.get("status_code", 0)
        status2 = data2.get("status_code", 0)
        length1 = data1.get("response_length", 0)
        length2 = data2.get("response_length", 0)
        body1 = data1.get("response_body", "")
        body2 = data2.get("response_body", "")

        lines = ["Auth State Comparison:\n"]
        lines.append(f"  Request 1 (original auth): Status {status1}, Length {length1}")
        lines.append(f"  Request 2 (alt auth):      Status {status2}, Length {length2}")
        lines.append("")

        if status1 == status2 and abs(length1 - length2) < 50:
            lines.append("[!!] POTENTIAL VULNERABILITY: Both requests returned similar responses!")
            lines.append("     This could indicate IDOR or broken access control.")
            if body1 == body2:
                lines.append("     Responses are IDENTICAL - strong indicator of missing auth checks.")
            else:
                lines.append(f"     Responses differ slightly ({abs(length1 - length2)} bytes difference).")
        elif status1 == status2:
            lines.append(f"[!] Same status code ({status1}) but different content lengths.")
            lines.append("    May need manual review.")
        else:
            lines.append(f"[OK] Different responses: {status1} vs {status2}")
            if status2 in (401, 403):
                lines.append("     Access control appears to be working (got 401/403).")
            elif status2 in (200, 302):
                lines.append(f"     [!] Alt auth got {status2} - review if data should be accessible.")

        lines.append(f"\n--- Response 1 (first 500 chars) ---")
        lines.append(body1[:500] if body1 else "(empty)")
        lines.append(f"\n--- Response 2 (first 500 chars) ---")
        lines.append(body2[:500] if body2 else "(empty)")
        return "\n".join(lines)
