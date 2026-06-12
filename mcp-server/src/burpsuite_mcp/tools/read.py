"""Tools for reading data from Burp Suite - proxy history, sitemap, scanner findings, scope."""

import re
from urllib.parse import urlsplit, parse_qsl

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.processing.formatters import format_proxy_table, format_findings


_REDIRECT_STATUSES = {301, 302, 303, 307, 308}

_DETAIL_FIELDS = frozenset({
    "method", "url", "host", "path", "query_params",
    "status_code", "mime_type", "content_type", "response_length",
    "request_headers", "response_headers",
    "request_body", "response_body",
    "has_form", "has_redirect", "location_header", "set_cookie",
    "error_markers",
})

_DETAIL_MARKER_RE = (
    ("sqli", re.compile(r"(you have an error in your sql syntax|pg_query|SQLSTATE\[|ORA-\d{5}|unclosed quotation|psycopg2|MySQLSyntaxError)", re.I)),
    ("ssti", re.compile(r"(jinja2\.exceptions|TemplateSyntaxError|freemarker\.core|velocity\.exception|twig\.error)", re.I)),
    ("rce",  re.compile(r"(uid=\d+\(.+?\)\s+gid=\d+|(?:root|nobody|www-data|apache).+?(?:bash|sh|nologin))")),
    ("stack_trace", re.compile(r"(Traceback \(most recent call last\)|at\s+[\w.$]+\.[\w$]+\([\w.]+\.java:\d+\)|Whitelabel Error Page|ServletException|NoMethodError|NameError|ReferenceError)")),
)


def _header_lookup(headers: list, name: str) -> str | None:
    """First-match header lookup, case-insensitive. Supports list-of-dict and list-of-[k,v]."""
    if not headers:
        return None
    target = name.lower()
    for h in headers:
        if isinstance(h, dict):
            k = h.get("name", "")
            if k.lower() == target:
                return h.get("value")
        elif isinstance(h, (list, tuple)) and len(h) >= 2:
            if str(h[0]).lower() == target:
                return str(h[1])
    return None


def _set_cookie_values(headers: list) -> list:
    """All Set-Cookie header values."""
    if not headers:
        return []
    out = []
    for h in headers:
        if isinstance(h, dict) and h.get("name", "").lower() == "set-cookie":
            out.append(h.get("value", ""))
        elif isinstance(h, (list, tuple)) and len(h) >= 2 and str(h[0]).lower() == "set-cookie":
            out.append(str(h[1]))
    return out


def _trim_body(body: str, body_first: int, body_last: int) -> str:
    """Slice body to head+tail; signal truncation when both are non-zero and body exceeds head+tail."""
    if not body:
        return ""
    total = len(body)
    if body_first <= 0 and body_last <= 0:
        return ""
    head = body[: body_first] if body_first > 0 else ""
    tail = body[-body_last:] if body_last > 0 else ""
    cut = body_first + body_last
    if cut >= total:
        return body
    return f"{head}\n…[TRUNCATED {total - cut} of {total} chars]…\n{tail}" if tail else head + f"\n…[TRUNCATED {total - body_first} of {total} chars]"


def _detect_error_markers(body: str) -> list[str]:
    """Return marker labels found in body. Cheap regex sweep, capped at 2k tail to bound cost."""
    if not body:
        return []
    sample = body[:8192]
    hits = []
    for label, rx in _DETAIL_MARKER_RE:
        if rx.search(sample):
            hits.append(label)
    return hits


def _slice_request_detail(
    data: dict, fields: list[str], body_first: int, body_last: int
) -> dict:
    """Return a dict containing only the requested fields. Unknown fields are skipped silently."""
    requested = [f for f in fields if f in _DETAIL_FIELDS]
    if not requested:
        return {"error": "no recognised fields", "allowed": sorted(_DETAIL_FIELDS)}

    url = data.get("url", "") or ""
    parsed = urlsplit(url) if url else None
    resp_headers = data.get("response_headers", []) or []
    req_headers = data.get("request_headers", []) or []
    resp_body = data.get("response_body", "") or ""
    status = data.get("status_code")

    out: dict = {}
    for f in requested:
        if f == "method":            out[f] = data.get("method")
        elif f == "url":             out[f] = url
        elif f == "status_code":     out[f] = status
        elif f == "mime_type":       out[f] = data.get("mime_type")
        elif f == "response_length": out[f] = data.get("response_length")
        elif f == "host":            out[f] = parsed.netloc if parsed else None
        elif f == "path":            out[f] = parsed.path if parsed else None
        elif f == "query_params":    out[f] = dict(parse_qsl(parsed.query)) if parsed and parsed.query else {}
        elif f == "request_headers":  out[f] = req_headers
        elif f == "response_headers": out[f] = resp_headers
        elif f == "request_body":  out[f] = _trim_body(data.get("request_body", "") or "", body_first, body_last)
        elif f == "response_body": out[f] = _trim_body(resp_body, body_first, body_last)
        elif f == "content_type":  out[f] = _header_lookup(resp_headers, "Content-Type")
        elif f == "location_header": out[f] = _header_lookup(resp_headers, "Location")
        elif f == "set_cookie":    out[f] = _set_cookie_values(resp_headers)
        elif f == "has_form":      out[f] = bool(resp_body and "<form" in resp_body.lower())
        elif f == "has_redirect":  out[f] = status in _REDIRECT_STATUSES
        elif f == "error_markers": out[f] = _detect_error_markers(resp_body)

    return out


def _format_raw_findings(data: dict) -> str:
    """Format all findings without filtering — for explicit INFORMATION requests."""
    items = data.get("items", [])
    total = data.get("total_findings", 0)
    if not items:
        return "No scanner findings."
    lines = [f"Scanner Findings — UNFILTERED ({len(items)}/{total}):\n"]
    for f in items:
        lines.append(f"  [{f.get('severity', '?')}/{f.get('confidence', '?')}] {f.get('name', '?')}")
        lines.append(f"    {f.get('base_url', '')}")
    return "\n".join(lines)


def register(mcp: FastMCP):

    @mcp.tool()
    async def get_proxy_history(
        limit: int = 50,
        offset: int = 0,
        filter_url: str = "",
        filter_method: str = "",
        filter_status: str = "",
        host: str = "",
        since_index: int = -1,
    ) -> str:
        """Get HTTP proxy history from Burp Suite with optional filters.

        Performance notes:
          - `host` (exact domain match) is faster than `filter_url`
            (substring) — Burp parses the host once.
          - `since_index` short-circuits iteration: pass the last index you
            saw to tail new entries only (e.g. since_index=12000 on a
            50K-entry history skips 12000 iterations).
          - Both fields are optional; combining them (since_index + host)
            is the cheapest poll for "new entries on this domain only".

        Args:
            limit: Max items to return
            offset: Pagination offset (use since_index instead for polling)
            filter_url: URL substring filter (slower; use `host` if you only
                need an exact domain match)
            filter_method: HTTP method filter (GET/POST/etc)
            filter_status: Status code filter (exact match)
            host: Exact-host filter (e.g. 'api.target.tld') — preferred over
                filter_url for domain-only narrowing
            since_index: Return only entries with index > since_index
                (default -1 = no lower bound)
        """
        params = {"limit": limit, "offset": offset}
        if filter_url:
            params["filter_url"] = filter_url
        if filter_method:
            params["filter_method"] = filter_method
        if filter_status:
            params["filter_status"] = filter_status
        if host:
            params["host"] = host
        if since_index >= 0:
            params["since_index"] = since_index

        data = await client.get("/api/proxy/history", params=params)
        if "error" in data:
            return f"Error: {data['error']}"
        return format_proxy_table(data)

    @mcp.tool()
    async def get_proxy_count() -> str:
        """Sub-millisecond proxy-history size check.

        Returns just the total count — useful for orientation before
        deciding whether to fetch the table, or to confirm new traffic is
        landing. Cheap enough to call repeatedly in a polling loop.
        """
        data = await client.get("/api/proxy/count")
        if "error" in data:
            return f"Error: {data['error']}"
        return f"Proxy history: {data.get('count', 0)} entries"

    @mcp.tool()
    async def get_request_detail(
        index: int,
        full_body: bool = False,
        fields: list[str] | None = None,
        body_first: int = 1024,
        body_last: int = 0,
    ) -> str | dict:
        """Get request/response details for a proxy history item.

        Args:
            index: Proxy history index
            full_body: Return complete response body without truncation (str mode only)
            fields: When provided, return a dict containing only these fields.
                Whitelist: method, url, host, path, query_params, status_code,
                mime_type, content_type, response_length, request_headers,
                response_headers, request_body, response_body, has_form,
                has_redirect, location_header, set_cookie, error_markers.
                Common triage slice: ['status_code', 'content_type', 'has_form',
                'has_redirect', 'location_header'] — ~99% token reduction vs str.
            body_first: Head bytes to keep when fields= slice includes bodies (default 1024)
            body_last: Tail bytes to keep when fields= slice includes bodies (default 0)
        """
        data = await client.get(f"/api/proxy/history/{index}")
        if "error" in data:
            return {"error": data["error"]} if fields else f"Error: {data['error']}"

        if fields:
            return _slice_request_detail(data, fields, body_first, body_last)

        # Legacy str format — preserve existing behavior for backwards compat
        lines = []
        lines.append(f"=== Request [{data.get('method')}] {data.get('url')} ===")
        lines.append("")

        for h in data.get("request_headers", []):
            lines.append(f"  {h['name']}: {h['value']}")
        req_body = data.get("request_body", "")
        if req_body:
            lines.append(f"\n--- Request Body ({len(req_body)} chars) ---")
            lines.append(req_body[:5000])

        lines.append(f"\n=== Response [{data.get('status_code')}] ({data.get('response_length', 0)} bytes, {data.get('mime_type', '')}) ===")
        for h in data.get("response_headers", []):
            lines.append(f"  {h['name']}: {h['value']}")
        resp_body = data.get("response_body", "")
        if resp_body:
            max_body = 0 if full_body else 5000
            lines.append(f"\n--- Response Body ({len(resp_body)} chars) ---")
            if max_body > 0 and len(resp_body) > max_body:
                lines.append(resp_body[:max_body] + f"\n...[truncated, {len(resp_body)} total chars — use full_body=True for complete response]")
            else:
                lines.append(resp_body)

        return "\n".join(lines)

    @mcp.tool()
    async def get_scanner_findings(
        severity: str = "",
        confidence: str = "",
        limit: int = 20,
        actionable_only: bool = True,
    ) -> str:
        """Get scanner/audit findings from Burp Suite Professional with noise filtering.

        Args:
            severity: Filter by severity (HIGH, MEDIUM, LOW, INFORMATION)
            confidence: Filter by confidence (CERTAIN, FIRM, TENTATIVE)
            limit: Max findings to return (default 20 — pass higher when iterating)
            actionable_only: Filter out noise/informational findings (default True). Set False to see everything.
        """
        params = {"limit": limit}
        if severity:
            params["severity"] = severity
        if confidence:
            params["confidence"] = confidence

        data = await client.get("/api/scanner/findings", params=params)
        if "error" in data:
            return f"Error: {data['error']}"

        if not actionable_only and severity == "INFORMATION":
            # Raw mode: skip filtering for explicit INFORMATION requests
            return _format_raw_findings(data)

        return format_findings(data)

    @mcp.tool()
    async def get_sitemap(url_prefix: str = "", limit: int = 30) -> str:
        """Get Burp's site map showing all discovered URLs/endpoints.

        Args:
            url_prefix: Filter by URL prefix
            limit: Max entries to return (default 30 — pass higher explicitly when you need more)
        """
        params = {"limit": limit}
        if url_prefix:
            params["prefix"] = url_prefix

        data = await client.get("/api/sitemap", params=params)
        if "error" in data:
            return f"Error: {data['error']}"

        items = data.get("items", [])
        if not items:
            return "Sitemap is empty. Browse the target in Burp first."

        lines = [f"Sitemap ({data.get('total_returned', 0)} entries):"]
        lines.append(f"{'METHOD':<8} {'STATUS':<7} {'SIZE':<8} URL")
        lines.append("-" * 80)
        for item in items:
            status = item.get("status_code", "-")
            size = item.get("response_length", 0)
            lines.append(f"{item['method']:<8} {status:<7} {size:<8} {item['url']}")

        return "\n".join(lines)

    @mcp.tool()
    async def get_scope() -> str:
        """Get the current target scope configuration from Burp Suite."""
        data = await client.get("/api/scope")
        if "error" in data:
            return f"Error: {data['error']}"

        hosts = data.get("in_scope_hosts", [])
        total = data.get("total_in_scope_urls", 0)

        if not hosts:
            return "No scope defined. Add targets to scope in Burp Suite."

        lines = [f"Target Scope ({total} URLs in scope):"]
        for h in hosts:
            lines.append(f"  - {h}")
        return "\n".join(lines)

    @mcp.tool()
    async def check_scope(url: str) -> str:
        """Check if a specific URL is within the target scope.

        Args:
            url: URL to check
        """
        data = await client.post("/api/scope/check", json={"url": url})
        if "error" in data:
            return f"Error: {data['error']}"

        in_scope = data.get("in_scope", False)
        return f"{url} is {'IN SCOPE' if in_scope else 'OUT OF SCOPE'}"

    @mcp.tool()
    async def get_cookies(domain: str = "", full_values: bool = False) -> str:
        """Get cookies from Burp's cookie jar.

        Args:
            domain: Filter by domain
            full_values: Show complete cookie values without truncation
        """
        params = {}
        if domain:
            params["domain"] = domain

        data = await client.get("/api/cookies", params=params)
        if "error" in data:
            return f"Error: {data['error']}"

        cookies = data.get("cookies", [])
        if not cookies:
            return f"No cookies found{' for domain ' + domain if domain else ''}."

        lines = [f"Cookies ({data.get('total', 0)} total):\n"]
        lines.append(f"{'NAME':<25} {'VALUE':<40} {'DOMAIN':<25} PATH")
        lines.append("-" * 100)
        for c in cookies:
            name = c.get("name", "")[:23]
            value = c.get("value", "")
            if not full_values and len(value) > 38:
                value = value[:36] + ".."
            domain_val = c.get("domain", "")[:23]
            path = c.get("path", "/")
            lines.append(f"{name:<25} {value:<40} {domain_val:<25} {path}")

            # Flag security issues
            exp = c.get("expiration")
            if exp:
                lines.append(f"  {'  Expires: ' + str(exp)}")

        return "\n".join(lines)

    @mcp.tool()
    async def get_websocket_history(
        limit: int = 50,
        offset: int = 0,
        direction: str = "",
        filter_payload: str = "",
        filter_url: str = "",
        since_index: int = -1,
    ) -> str:
        """Get WebSocket message history from Burp's proxy with filters.

        Args:
            limit: Max messages to return
            offset: Pagination offset
            direction: Filter by direction — 'client' (outgoing) or 'server' (incoming)
            filter_payload: Substring filter applied to message payload (case-insensitive)
            filter_url: Substring filter applied to the WebSocket connection URL
            since_index: Only return messages with index > since_index (poll for new traffic)
        """
        params: dict = {"limit": limit, "offset": offset}
        if direction:
            params["direction"] = direction
        if filter_payload:
            params["filter_payload"] = filter_payload
        if filter_url:
            params["filter_url"] = filter_url
        if since_index >= 0:
            params["since_index"] = since_index

        data = await client.get("/api/websocket/history", params=params)
        if "error" in data:
            return f"Error: {data['error']}"

        messages = data.get("messages", [])
        if not messages:
            hint = " Try clearing filters." if (direction or filter_payload or filter_url or since_index >= 0) else ""
            return f"No WebSocket messages captured.{hint} WebSocket traffic must flow through Burp's proxy."

        lines = [f"WebSocket Messages ({data.get('total', 0)} total, showing {len(messages)}):\n"]
        for msg in messages:
            d = msg.get("direction", "?")
            idx = msg.get("index", "?")
            length = msg.get("length", 0)
            payload = msg.get("payload", "")
            url = msg.get("url", "")

            arrow = ">>" if "CLIENT" in str(d).upper() else "<<"
            url_part = f" {url}" if url else ""
            lines.append(f"[{idx}] {arrow} ({d}, {length} bytes){url_part}")

            if len(payload) > 200:
                lines.append(f"  {payload[:200]}...")
            else:
                lines.append(f"  {payload}")
            lines.append("")

        return "\n".join(lines)
