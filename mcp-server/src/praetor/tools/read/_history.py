"""Read: proxy history, request detail, scanner findings."""

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.processing.formatters import format_proxy_table, format_findings
from ._helpers import _format_raw_findings, _slice_request_detail


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
