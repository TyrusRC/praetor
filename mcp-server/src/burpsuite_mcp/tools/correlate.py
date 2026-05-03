"""Tools for correlating findings - search history, match scanner findings to endpoints."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def search_history(
        query: str,
        in_url: bool = True,
        in_request_body: bool = False,
        in_response_body: bool = False,
        method: str = "",
        status_code: int = 0,
        limit: int = 50,
    ) -> str:
        """Search proxy history for requests matching a query string.

        Args:
            query: Search string (case-insensitive)
            in_url: Search in URLs
            in_request_body: Search in request bodies
            in_response_body: Search in response bodies
            method: Filter by HTTP method
            status_code: Filter by status code
            limit: Max results
        """
        payload = {
            "query": query,
            "in_url": in_url,
            "in_request_body": in_request_body,
            "in_response_body": in_response_body,
            "limit": limit,
        }
        if method:
            payload["method"] = method
        if status_code:
            payload["status_code"] = status_code

        data = await client.post("/api/search/history", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        results = data.get("results", [])
        if not results:
            return f"No results found for '{query}'"

        lines = [f"Search results for '{query}' ({data.get('total_matches', 0)} matches):\n"]
        lines.append(f"{'INDEX':<8} {'METHOD':<8} {'STATUS':<8} URL")
        lines.append("-" * 80)
        for r in results:
            lines.append(f"{r['index']:<8} {r['method']:<8} {r.get('status_code', '-'):<8} {r['url']}")

        return "\n".join(lines)

    @mcp.tool()
    async def get_findings_for_endpoint(url: str) -> str:
        """Get all scanner and manual findings for a specific endpoint URL.

        Args:
            url: Endpoint URL to look up
        """
        # Get scanner findings (parallel)
        import asyncio
        scanner_data, notes_data = await asyncio.gather(
            client.get("/api/scanner/findings"),
            client.get("/api/notes/findings", params={"endpoint": url}),
        )

        lines = [f"Findings for: {url}\n"]
        errors: list[str] = []

        def _url_matches(candidate: str, target: str) -> bool:
            """Match exact URL or proper path/host containment, not bare substring.
            Avoids /users/1 spuriously matching /users/10."""
            if not candidate or not target:
                return False
            if candidate == target:
                return True
            return candidate.startswith(target + "/") or candidate.startswith(target + "?")

        # Scanner findings matching this URL
        if "error" in scanner_data:
            errors.append(f"scanner: {scanner_data['error']}")
        elif "items" in scanner_data:
            matching = [f for f in scanner_data["items"] if _url_matches(str(f.get("base_url", "")), url)]
            if matching:
                lines.append(f"--- Scanner Findings ({len(matching)}) ---")
                for f in matching:
                    lines.append(f"  [{f.get('severity')}] {f.get('name')} (confidence: {f.get('confidence')})")
                    if f.get("detail"):
                        lines.append(f"    {f['detail'][:200]}")
                lines.append("")

        # Manual findings
        if "error" in notes_data:
            errors.append(f"notes: {notes_data['error']}")
        else:
            findings = notes_data.get("findings", [])
            if findings:
                lines.append(f"--- Manual Findings ({len(findings)}) ---")
                for f in findings:
                    lines.append(f"  [{f.get('severity')}] {f.get('title')}")
                    if f.get("description"):
                        lines.append(f"    {f['description'][:200]}")

        if errors and len(lines) == 1:
            return f"Error fetching findings: {'; '.join(errors)}"
        if len(lines) == 1:
            lines.append("No findings found for this endpoint.")
        if errors:
            lines.append(f"\n[partial: {'; '.join(errors)}]")

        return "\n".join(lines)

    @mcp.tool()
    async def search_ws_history(
        query: str,
        direction: str = "",
        filter_url: str = "",
        since_index: int = -1,
        limit: int = 50,
    ) -> str:
        """Search Burp's WebSocket message history for a substring across payloads.

        Use to grep WS traffic for tokens, IDs, error keywords, leaked secrets, or
        any payload pattern. Mirrors `search_history` for HTTP. Direction filter
        accepts 'client' (outgoing) or 'server' (incoming).

        Args:
            query: Substring to find inside the WS message payload (case-insensitive)
            direction: Limit to one direction ('client' or 'server')
            filter_url: Substring filter on the upgrade-request URL
            since_index: Only return messages with index > this value (poll for new)
            limit: Max results
        """
        params: dict = {"limit": limit, "filter_payload": query}
        if direction:
            params["direction"] = direction
        if filter_url:
            params["filter_url"] = filter_url
        if since_index >= 0:
            params["since_index"] = since_index

        data = await client.get("/api/websocket/history", params=params)
        if "error" in data:
            return f"Error: {data['error']}"

        messages = data.get("messages", [])
        if not messages:
            return f"No WS messages match '{query}'."

        lines = [f"WS search '{query}' ({data.get('matched', 0)} matched, showing {len(messages)}):\n"]
        for msg in messages:
            d = msg.get("direction", "?")
            arrow = ">>" if "CLIENT" in str(d).upper() else "<<"
            payload = msg.get("payload", "")
            snippet = payload[:200] + ("..." if len(payload) > 200 else "")
            url = msg.get("url", "")
            url_part = f" {url}" if url else ""
            lines.append(f"[{msg.get('index', '?')}] {arrow} ({d}, {msg.get('length', 0)}B){url_part}")
            lines.append(f"  {snippet}")

        return "\n".join(lines)

    @mcp.tool()
    async def get_response_diff(index1: int, index2: int) -> str:
        """Diff two proxy history responses to spot differences.

        Args:
            index1: First proxy history index
            index2: Second proxy history index
        """
        data = await client.post("/api/search/response-diff", json={
            "index1": index1,
            "index2": index2,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Response Diff: #{data.get('index1')} vs #{data.get('index2')}"]
        lines.append(f"Status: {data.get('status1')} vs {data.get('status2')}")
        lines.append(f"Length: {data.get('length1')} vs {data.get('length2')}")
        lines.append(f"Differences: {data.get('total_differences', 0)}\n")

        diff_lines = data.get("diff_lines", [])
        if diff_lines:
            for line in diff_lines:
                lines.append(line)
        else:
            lines.append("Responses are identical.")

        return "\n".join(lines)
