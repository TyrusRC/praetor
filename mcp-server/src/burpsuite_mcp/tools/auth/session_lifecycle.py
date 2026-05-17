"""test_session_lifecycle — verify token/session is actually revoked on logout.

The "logout doesn't invalidate JWT" finding is the single most common HIGH
on JWT-stateless apps. The flow is mechanical: capture baseline → trigger
logout → replay → assess. Documented in session_security.json
(logout_does_not_invalidate_session context) but nobody runs it because
it's three coordinated requests.

This tool runs that flow in one call. All three requests route through
Burp; logger_index of the final replay is the evidence the operator cites.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools._request_headers import apply_realistic_headers


def _build_headers(
    base_headers: dict | None, cookies: dict | None, bearer: str, url: str,
) -> dict:
    """Merge realistic profile + caller-supplied auth into one header dict."""
    merged = apply_realistic_headers(url, base_headers or {})
    if cookies:
        # Use Cookie header — keeps the session control explicit (caller
        # sees exactly what auth went on the wire). %3B escape so an
        # operator can pass any value safely.
        cookie_str = "; ".join(f"{k}={str(v).replace(';', '%3B')}"
                               for k, v in cookies.items())
        merged["Cookie"] = cookie_str
    if bearer:
        merged["Authorization"] = f"Bearer {bearer}"
    return merged


async def _send(method: str, url: str, headers: dict, body: str = "") -> dict:
    payload: dict = {"method": method, "url": url, "headers": headers,
                     "follow_redirects": False}
    if body:
        payload["body"] = body
    return await client.post("/api/http/curl", json=payload)


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_session_lifecycle(  # cost: low (3 requests)
        protected_url: str,
        logout_url: str,
        bearer_token: str = "",
        cookies: dict | None = None,
        logout_method: str = "POST",
        protected_method: str = "GET",
        protected_body: str = "",
    ) -> str:
        """Verify a token is revoked after logout.

        Three-step flow:
          1) GET protected_url with auth -> expect 200 (baseline)
          2) POST logout_url with same auth
          3) GET protected_url with same auth -> if still 200, session was NOT revoked

        The third request's logger_index is the evidence to cite in
        save_finding. Maps to WSTG-SESS-06 / session_security.json
        logout_does_not_invalidate_session context.

        Args:
            protected_url: A protected endpoint that returns 200 when authenticated
            logout_url: The logout endpoint
            bearer_token: Bearer auth (or use cookies)
            cookies: Session cookies (or use bearer)
            logout_method: HTTP method for logout (default POST)
            protected_method: HTTP method for the protected endpoint (default GET)
            protected_body: Body for the protected request if non-GET
        """
        if not bearer_token and not cookies:
            return "Error: provide bearer_token or cookies — need auth to test revocation"

        # Step 1: baseline
        headers = _build_headers(None, cookies, bearer_token, protected_url)
        baseline = await _send(protected_method, protected_url, headers,
                               protected_body)
        if "error" in baseline:
            return f"Error (baseline): {baseline['error']}"

        baseline_status = baseline.get("status_code", 0)
        baseline_len = baseline.get("response_length", 0)
        baseline_idx = baseline.get("history_index", -1)

        # Step 2: logout
        logout_headers = _build_headers(None, cookies, bearer_token, logout_url)
        logout = await _send(logout_method, logout_url, logout_headers)
        if "error" in logout:
            return f"Error (logout): {logout['error']}"

        logout_status = logout.get("status_code", 0)
        logout_idx = logout.get("history_index", -1)

        # Step 3: replay protected with the SAME auth (no cookie refresh)
        replay = await _send(protected_method, protected_url, headers,
                             protected_body)
        if "error" in replay:
            return f"Error (replay): {replay['error']}"

        replay_status = replay.get("status_code", 0)
        replay_len = replay.get("response_length", 0)
        replay_idx = replay.get("history_index", -1)

        lines = ["Session Lifecycle Test:\n"]
        lines.append(f"  1) Baseline    {protected_method} {protected_url}")
        lines.append(f"     -> {baseline_status} ({baseline_len}b, logger #{baseline_idx})")
        lines.append(f"  2) Logout      {logout_method} {logout_url}")
        lines.append(f"     -> {logout_status} (logger #{logout_idx})")
        lines.append(f"  3) Replay      {protected_method} {protected_url}")
        lines.append(f"     -> {replay_status} ({replay_len}b, logger #{replay_idx})")
        lines.append("")

        # Verdict.
        if baseline_status not in (200, 302) and replay_status not in (200, 302):
            lines.append("INDETERMINATE: baseline didn't authenticate (not 200/302).")
            lines.append("Check that bearer_token / cookies are valid before re-running.")
            return "\n".join(lines)

        # Strong revocation signal: replay flips to 401/403.
        if replay_status in (401, 403, 419, 440):
            lines.append(f"REVOKED: replay returned {replay_status}.")
            lines.append("Server invalidates session on logout. No finding.")
            return "\n".join(lines)

        # Weak revocation: status same but body changed materially.
        same_status = (replay_status == baseline_status)
        len_delta = abs(replay_len - baseline_len)

        if same_status and len_delta < 50:
            lines.append("[!!] NOT REVOKED — token still authenticates after logout.")
            lines.append(f"     Replay status={replay_status} matches baseline; "
                         f"length delta={len_delta}b.")
            lines.append("")
            lines.append("This is the classic stateless-JWT-no-revocation pattern.")
            lines.append("Cite logger_index in save_finding:")
            lines.append(f"  save_finding(vuln_type='session_not_invalidated',")
            lines.append(f"               severity='high',")
            lines.append(f"               endpoint='{protected_url}',")
            lines.append(f"               evidence={{'logger_index': {replay_idx}, "
                         f"'reproductions': []}})")
        elif same_status:
            lines.append("[?] PARTIAL — status unchanged but response body differs "
                         f"by {len_delta}b.")
            lines.append("    Inspect both responses; logout may have reduced "
                         "scope without revoking.")
            lines.append("    Use compare_responses or get_request_detail on the "
                         "two logger indices.")
        else:
            lines.append(f"[?] AMBIGUOUS — replay returned {replay_status} "
                         f"(baseline was {baseline_status}).")
            lines.append("    Not a clear revoke and not a clear pass. "
                         "Re-run after a clean re-login.")

        return "\n".join(lines)
