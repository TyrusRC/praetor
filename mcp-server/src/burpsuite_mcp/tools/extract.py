"""Tools for extracting specific data from responses — regex, JSON path, CSS selectors, headers, links, hashes."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def extract_regex(
        index: int,
        pattern: str,
        group: int = 0,
        find_all: bool = False,
        max_matches: int = 200,
        max_match_chars: int = 500,
    ) -> str:
        """Extract data from a response using regex pattern matching.

        Args:
            index: Proxy history index
            pattern: Regex pattern (use capture groups for specific extraction)
            group: Capture group number (0=whole match, 1=first group)
            find_all: Return all matches instead of just the first
            max_matches: Cap on returned matches when find_all=True (default 200). Prevents 10k+ matches blowing the context window.
            max_match_chars: Per-match length cap (default 500). Long matches are truncated with a marker.
        """
        data = await client.post("/api/extract-text/regex", json={
            "index": index, "pattern": pattern, "group": group, "all": find_all,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        matches = data.get("matches", [])
        if not matches:
            return f"No matches for /{pattern}/ in response #{index}"

        total = data.get("count", len(matches))
        # Per-match cap so a 50KB regex hit doesn't dominate the response.
        cap_per = max(64, int(max_match_chars))
        # Total-match cap to keep payload bounded for find_all=True.
        cap_total = max(1, int(max_matches))
        truncated_count = max(0, len(matches) - cap_total)
        if truncated_count:
            matches = matches[:cap_total]

        lines = [f"Matches ({total}){' [showing first ' + str(cap_total) + ']' if truncated_count else ''}"]
        for i, m in enumerate(matches):
            s = str(m)
            if len(s) > cap_per:
                s = s[:cap_per] + f"... [+{len(str(m)) - cap_per} chars]"
            lines.append(f"  [{i}] {s}")
        if truncated_count:
            lines.append(f"  ... +{truncated_count} more matches not shown (raise max_matches to see).")
        return "\n".join(lines)

    @mcp.tool()
    async def extract_json_path(index: int, path: str) -> str:
        """Extract a value from a JSON response using a simple path expression.

        Args:
            index: Proxy history index
            path: JSON path expression (e.g. '$.data.users[0].email')
        """
        data = await client.post("/api/extract-data/json-path", json={
            "index": index, "path": path,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        value = data.get("value")
        return f"{path} = {value}"

    @mcp.tool()
    async def extract_css_selector(
        index: int,
        selector: str,
        attribute: str = "",
    ) -> str:
        """Extract elements from an HTML response using CSS-like selectors.

        Args:
            index: Proxy history index
            selector: CSS-like selector (e.g. 'input[name=csrf_token]')
            attribute: Extract this attribute's value (optional)
        """
        data = await client.post("/api/extract-text/css-selector", json={
            "index": index, "selector": selector, "attribute": attribute,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        elements = data.get("elements", [])
        if not elements:
            return f"No elements matching '{selector}' in response #{index}"

        lines = [f"Found {data.get('count', len(elements))} element(s):"]
        for el in elements:
            if attribute and el.get("attribute_value"):
                lines.append(f"  {attribute}={el['attribute_value']}")
            elif el.get("text"):
                lines.append(f"  {el['text'][:200]}")
            else:
                html_snippet = el.get("outer_html", "")[:200]
                lines.append(f"  {html_snippet}")
        return "\n".join(lines)

    @mcp.tool()
    async def extract_headers(
        index: int,
        names: list[str] | None = None,
        from_request: bool = False,
    ) -> str:
        """Extract specific headers from a request or response.

        Args:
            index: Proxy history index
            names: Header names to extract (None = all)
            from_request: Extract from request headers instead of response
        """
        payload: dict = {"index": index}
        if names:
            payload["names"] = names
        if from_request:
            payload["from"] = "request"

        data = await client.post("/api/extract-data/headers", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        headers = data.get("headers", [])
        if not headers:
            return "No matching headers found"

        lines = []
        for h in headers:
            lines.append(f"{h['name']}: {h['value']}")
        return "\n".join(lines)

    @mcp.tool()
    async def extract_links(index: int, link_filter: str = "all") -> str:
        """Extract all links and URLs from an HTML response.

        Args:
            index: Proxy history index
            link_filter: 'all', 'internal', or 'external'
        """
        data = await client.post("/api/extract-text/links", json={
            "index": index, "filter": link_filter,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        links = data.get("links", [])
        if not links:
            return f"No links found in response #{index}"

        lines = [f"Links ({data.get('count', len(links))}):"]
        by_type: dict[str, list] = {}
        for link in links:
            t = link.get("type", "other")
            by_type.setdefault(t, []).append(link)

        for link_type, items in by_type.items():
            lines.append(f"\n  [{link_type.upper()}] ({len(items)})")
            for item in items[:20]:
                scope = "int" if item.get("internal") else "ext"
                lines.append(f"    [{scope}] {item['url']}")
            if len(items) > 20:
                lines.append(f"    ... +{len(items)-20} more")
        return "\n".join(lines)

    @mcp.tool()
    async def get_response_hash(index: int, algorithm: str = "sha256") -> str:
        """Get a hash of a response body for change detection.

        Args:
            index: Proxy history index
            algorithm: 'sha256' (default), 'md5', or 'sha1'
        """
        data = await client.post("/api/extract-data/hash", json={
            "index": index, "algorithm": algorithm,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        return f"{data.get('algorithm', algorithm)}: {data.get('hash', '?')} ({data.get('body_length', 0)} bytes)"
