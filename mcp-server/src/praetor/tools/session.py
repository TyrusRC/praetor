"""Persistent attack sessions — cookie jar, auth tokens, request crafting, multi-step flows."""

import re
from urllib.parse import quote, urlparse

from mcp.server.fastmcp import FastMCP

from praetor import client

# Vendor-agnostic anti-CSRF field names (body params) and header names. Covers
# Django, Rails, Laravel, ASP.NET, Angular/double-submit, Spring, and the
# Meta-style fb_dtsg/lsd/jazoest tokens Zurp's "Sprinkle" targets.
_CSRF_FIELDS = [
    "csrfmiddlewaretoken", "authenticity_token", "__RequestVerificationToken",
    "_csrf", "csrf_token", "csrftoken", "csrf", "_token", "xsrf", "xsrf_token",
    "fb_dtsg", "lsd", "jazoest", "anti-csrf", "anticsrf", "request_token",
]
_CSRF_HEADERS = [
    "x-csrf-token", "x-csrftoken", "x-xsrf-token", "x-csrf", "csrf-token",
    "requestverificationtoken", "x-request-verification-token",
]


def _shape(v: str) -> str:
    """Show a token's shape, never its full value (sk-...4f2a style)."""
    v = str(v or "")
    if len(v) <= 10:
        return f"<{len(v)}B>"
    return f"{v[:6]}...{v[-4:]} ({len(v)}B)"


def _detect_csrf_field(body: str, headers: dict):
    """Find the anti-CSRF token in a request. Returns (field, old_value, location)
    where location is 'header' or 'body', or (None, None, None)."""
    lower_hdr = {k.lower(): (k, v) for k, v in (headers or {}).items()}
    for hn in _CSRF_HEADERS:
        if hn in lower_hdr:
            orig, val = lower_hdr[hn]
            return orig, val, "header"
    b = body or ""
    for f in _CSRF_FIELDS:
        m = re.search(r'"' + re.escape(f) + r'"\s*:\s*"([^"]*)"', b)
        if m:
            return f, m.group(1), "body"
        m = re.search(r'(?:^|&)' + re.escape(f) + r'=([^&]*)', b)
        if m:
            return f, m.group(1), "body"
    return None, None, None


def _extract_fresh_token(field: str, resp_body: str, resp_headers: list) -> str:
    """Pull a fresh token value from a source-page response (hidden input, Rails
    meta tag, JSON, generic assignment, or an XSRF-TOKEN Set-Cookie)."""
    b = resp_body or ""
    fe = re.escape(field)
    patterns = [
        r'name=["\']?' + fe + r'["\']?[^>]*\bvalue=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\'][^>]*\bname=["\']?' + fe + r'["\']?',
        r'["\']' + fe + r'["\']\s*:\s*["\']([^"\']+)["\']',
        r'\b' + fe + r'["\']?\s*[:=]\s*["\']([^"\'&\s]+)',
    ]
    if "csrf" in field.lower() or "xsrf" in field.lower():
        patterns.insert(0, r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)')
    for p in patterns:
        m = re.search(p, b, re.IGNORECASE)
        if m:
            return m.group(1)
    # Double-submit cookie (Angular/Laravel): XSRF-TOKEN in Set-Cookie.
    for h in resp_headers or []:
        if str(h.get("name", "")).lower() == "set-cookie":
            m = re.search(r'(?:XSRF-TOKEN|csrftoken|_csrf)=([^;]+)', h.get("value", ""), re.IGNORECASE)
            if m:
                return m.group(1)
    return ""


def _substitute_token(body: str, field: str, new: str) -> str:
    """Replace the token value for `field` in a form or JSON body."""
    if re.search(r'"' + re.escape(field) + r'"\s*:', body or ""):
        return re.sub(r'("' + re.escape(field) + r'"\s*:\s*")[^"]*(")',
                      lambda m: m.group(1) + new + m.group(2), body)
    return re.sub(r'((?:^|&)' + re.escape(field) + r'=)[^&]*',
                  lambda m: m.group(1) + quote(new, safe=""), body or "")


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
        """Send an HTTP request using a persistent session with auto-applied auth and cookies.

        Args:
            session: Session name.
            method: HTTP method.
            path: Request path relative to session base_url.
            headers: Additional headers merged with session defaults.
            body: Raw request body.
            data: Form-encoded data.
            json_body: JSON body dict.
            cookies: Additional cookies merged with session jar.
            extract: Inline extraction rules {var: rule}. Rule forms: body regex {"regex"|"pattern"}; body json {"json_path"|"path"}; header {"from":"header","name"}; cookie {"from":"cookie","name"}. Extracted values feed {{var}} in run_flow; misses surface in extract_warnings.
            follow_redirects: Follow 3xx redirects.
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
        # Surface server-measured latency — the oracle for time-based blind SQLi
        # and other timing classes. The Java layer computes it; dropping it here
        # forced a proxied-curl workaround to read the delay.
        if "response_time_ms" in resp:
            lines.append(f"Response Time: {resp['response_time_ms']} ms")

        extracted = resp.get("extracted", {})
        if extracted:
            lines.append("\nExtracted:")
            for k, v in extracted.items():
                display = v if len(str(v)) < 100 else str(v)[:100] + "..."
                lines.append(f"  {k} = {display}")

        warnings = resp.get("extract_warnings", [])
        if warnings:
            lines.append("\nExtract warnings:")
            for w in warnings:
                lines.append(f"  ! {w}")

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
                lines.append(resp_body[:max_body] + "\n...[truncated — use full_body=True for complete response]")
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
            extract: Extraction rules keyed by variable name. Rule schema is
                identical to session_request.extract — see that tool for the
                full grammar (regex/pattern, json_path/path, from header/cookie,
                or {"type": ...} shorthand).
        """
        payload = {"session": session, "rules": extract}
        resp = await client.post("/api/session/extract", json=payload)
        if "error" in resp:
            return f"Error: {resp['error']}"

        extracted = resp.get("extracted", {})
        warnings = resp.get("extract_warnings", [])
        if not extracted:
            if warnings:
                return "No values matched extraction rules.\nWarnings:\n  ! " + "\n  ! ".join(warnings)
            return "No values matched extraction rules."

        lines = ["Extracted:"]
        for k, v in extracted.items():
            lines.append(f"  {k} = {v}")

        if warnings:
            lines.append("\nExtract warnings:")
            for w in warnings:
                lines.append(f"  ! {w}")

        variables = resp.get("session_variables", {})
        if variables:
            lines.append(f"\nSession variables ({len(variables)} total):")
            for k, v in variables.items():
                display = v if len(str(v)) < 80 else str(v)[:80] + "..."
                lines.append(f"  {k} = {display}")

        return "\n".join(lines)

    @mcp.tool()
    async def resend_with_csrf_refresh(
        index: int,
        session: str,
        source_path: str = "",
        token_field: str = "",
        method: str = "",
        full_body: bool = False,
    ) -> str:
        """Replay a captured request through a session, auto-refreshing its anti-CSRF token.

        The generic "Sprinkle": take proxy-history request <index>, GET a source
        page under `session` to pull a FRESH anti-CSRF token, substitute it into
        the captured body/header, and resend the whole request through that
        session (so it carries the session's cookies/auth). The point is
        account-swap IDOR/BOLA testing — replay user A's state-changing request as
        user B without the stale token causing a false 403 that masks the bug.

        Vendor-agnostic: detects csrfmiddlewaretoken / authenticity_token /
        __RequestVerificationToken / _csrf / _token / fb_dtsg / lsd and the
        X-CSRF-Token / X-XSRF-TOKEN headers (double-submit cookie supported).
        It never sends a stale token silently — if the token can't be refreshed
        it reports why and stops (Rule 32a), so a 403 is never mistaken for "safe".

        Args:
            index: proxy-history index of the request to replay.
            session: session whose cookies/auth (i.e. which account) to replay as.
            source_path: page to GET for a fresh token (default: the request's
                Referer, else its own path). Path relative to the session base_url.
            token_field: force the token field/header name (default: auto-detect).
            method: override the HTTP method (default: the captured method).
            full_body: return the full response body (default: truncated).
        """
        from praetor.tools.notes._proxy_entry import _normalize_entry

        detail = await client.get(
            f"/api/proxy/history/{int(index)}", params={"include_body": "true"})
        if "error" in detail:
            return f"Error fetching proxy entry {index}: {detail['error']}"
        req = _normalize_entry(detail)
        headers = dict(req.get("headers") or {})
        body = req.get("body") or ""
        cap_method = (method or req.get("method") or "GET").upper()
        parsed = urlparse(req.get("url") or "")
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")

        # 1. Locate the anti-CSRF token in the captured request.
        if token_field:
            loc = "header" if token_field.lower() in {h.lower() for h in headers} else "body"
            field, old = token_field, (headers.get(token_field, "") if loc == "header" else "")
        else:
            field, old, loc = _detect_csrf_field(body, headers)
        if not field:
            return ("No anti-CSRF token found in the captured request (searched common "
                    "field + header names). Pass token_field= if it is custom, or just "
                    "replay with session_request if the endpoint needs no token.")

        # 2. GET a source page under the session to pull a fresh token.
        src = source_path
        if not src:
            ref = next((v for k, v in headers.items() if k.lower() == "referer"), "")
            src = (urlparse(ref).path or path) if ref else path
        src_resp = await client.post("/api/session/request", json={
            "session": session, "method": "GET", "path": src, "follow_redirects": True})
        if "error" in src_resp:
            return f"Error GETting source page {src} under session '{session}': {src_resp['error']}"
        fresh = _extract_fresh_token(
            field, src_resp.get("response_body", ""), src_resp.get("response_headers", []))
        if not fresh:
            return (f"Could not extract a fresh '{field}' token from {src} (status "
                    f"{src_resp.get('status')}). The source page may not render it — "
                    "pass source_path= pointing at the page/endpoint that issues the token. "
                    "Not resending with a stale token (would risk a false 403).")

        # 3. Substitute the fresh token (body or header) and resend as the session.
        send: dict = {"session": session, "method": cap_method, "path": path}
        if loc == "header":
            headers[field] = fresh
        else:
            body = _substitute_token(body, field, fresh)
        if headers:
            send["headers"] = headers
        if body:
            send["body"] = body
        out = await client.post("/api/session/request", json=send)
        if "error" in out:
            return f"Error on resend: {out['error']}"

        lines = [
            f"Resent #{index} as session '{session}' with a refreshed {loc} token.",
            f"  token field: {field}  ({_shape(old)} -> {_shape(fresh)})",
            f"  source page: {src}",
            f"  {cap_method} {path} -> {out.get('status')} ({out.get('response_length', 0)} bytes)",
        ]
        rb = out.get("response_body", "")
        if rb:
            cap = 0 if full_body else 2000
            lines.append(f"\n--- Response Body ({len(rb)} chars) ---")
            lines.append(rb if cap == 0 or len(rb) <= cap
                         else rb[:cap] + "\n...[truncated — full_body=True for all]")
        return "\n".join(lines)

    @mcp.tool()
    async def run_flow(
        session: str,
        steps: list[dict],
    ) -> str:
        """Execute a multi-step attack flow in one call with variable interpolation between steps.

        Args:
            session: Session name
            steps: Ordered list of request steps. Each step:
                {method, path, headers?, body?, data?, json_body?, cookies?,
                 follow_redirects?, continue_on_error?, extract?: {var: rule, ...}}
                Extracted values become session variables; later steps can
                interpolate them as {{var}} in path/data/body/headers values.
                Rule schema is identical to session_request.extract — supports
                regex/pattern, json_path/path, from header/cookie, and
                {"type": ...} shorthand. Failed rules surface in
                step.extract_warnings.
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

            step_warnings = step.get("extract_warnings", [])
            if step_warnings:
                for w in step_warnings:
                    lines.append(f"  ! extract_warning: {w}")

            # Show body snippet (from Java side, max 500 chars)
            snippet = step.get("body_snippet") or step.get("response_body", "")
            if snippet:
                if len(snippet) > 500:
                    snippet = snippet[:500] + "..."
                lines.append(f"  Body: {snippet}")

        variables = resp.get("session_variables", {})
        if variables:
            lines.append("\nSession variables:")
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
