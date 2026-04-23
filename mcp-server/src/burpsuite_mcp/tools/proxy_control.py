"""Tools for controlling Burp proxy — intercept, match-replace, annotations, stats, traffic monitoring."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    # ── Intercept Control ───────────────────────────────────────

    @mcp.tool()
    async def enable_intercept() -> str:
        """Enable Burp proxy interception. Requests will be held for review/modification.
        Use disable_intercept() when done to resume normal traffic flow."""
        data = await client.post("/api/intercept/enable")
        if "error" in data:
            return f"Error: {data['error']}"
        return "Proxy intercept ENABLED — requests will be held"

    @mcp.tool()
    async def disable_intercept() -> str:
        """Disable Burp proxy interception. Requests will pass through automatically."""
        data = await client.post("/api/intercept/disable")
        if "error" in data:
            return f"Error: {data['error']}"
        return "Proxy intercept DISABLED — requests passing through"

    @mcp.tool()
    async def get_intercept_status() -> str:
        """Check whether proxy interception is currently enabled."""
        data = await client.get("/api/intercept/status")
        if "error" in data:
            return f"Error: {data['error']}"
        enabled = data.get("intercept_enabled", False)
        return f"Intercept is {'ENABLED' if enabled else 'DISABLED'}"

    # ── Match & Replace ─────────────────────────────────────────

    # Headers whose rewriting frequently breaks traffic or leaks auth. Flag before applying.
    _DANGEROUS_HEADER_PATTERNS = (
        "host:",               # breaks TLS SNI / vhost routing
        "authorization:",      # auth-leak risk if replaced globally
        "cookie:",             # session leak across targets
        "content-length:",     # mismatches body length → smuggling/500s
        "transfer-encoding:",  # request smuggling risk
    )

    @mcp.tool()
    async def set_match_replace(rules: list[dict], force: bool = False) -> str:
        """Add match-and-replace rules to automatically modify proxy traffic.
        Each rule: {'type': 'request'|'response', 'match': 'regex', 'replace': 'replacement'}
        Optional: 'enabled' (default True), 'scope': 'all'|'in_scope' (recommended 'in_scope')

        Safety:
        - Rules affect ALL proxy traffic unless `scope: 'in_scope'` is set. For most
          bug-bounty use cases, set scope='in_scope' so out-of-scope sites aren't
          touched.
        - Rewriting Host, Authorization, Cookie, Content-Length, or Transfer-Encoding
          headers is refused unless `force=True` — these commonly break traffic or
          leak auth across hosts.
        - Rules live in Burp memory only; restarting Burp wipes them. Persist
          important rules in your hunt notes.

        Use cases:
        - Add X-Forwarded-For (in-scope only):
          {'type':'request', 'scope':'in_scope',
           'match':'(\\r\\n\\r\\n)', 'replace':'\\r\\nX-Forwarded-For: 127.0.0.1\\r\\n\\r\\n'}
        - Strip CSP (in-scope):
          {'type':'response', 'scope':'in_scope',
           'match':'Content-Security-Policy: [^\\r\\n]+', 'replace':''}
        - Swap Bearer token (in-scope):
          {'type':'request', 'scope':'in_scope',
           'match':'Bearer old_token', 'replace':'Bearer new_token'}

        Args:
            rules: List of match-replace rule dicts
            force: Allow rules that target dangerous headers (Host, Auth, Cookie,
                   Content-Length, Transfer-Encoding). Default False.
        """
        if not force:
            blocked = []
            for i, r in enumerate(rules):
                match_str = str(r.get("match", "")).lower()
                for pat in _DANGEROUS_HEADER_PATTERNS:
                    if pat in match_str:
                        blocked.append(f"rule #{i}: matches '{pat}' — set force=True to override")
                        break
            if blocked:
                return (
                    "Refused: dangerous header rewrite detected.\n  "
                    + "\n  ".join(blocked)
                    + "\nRe-run with force=True if intentional."
                )

        data = await client.post("/api/match-replace/add", json={"rules": rules})
        if "error" in data:
            return f"Error: {data['error']}"

        active = data.get("rules", [])
        if not active:
            return "No rules active"

        lines = [f"Active Rules ({len(active)}):"]
        lines.append(f"{'ID':<5} {'TYPE':<10} {'SCOPE':<10} MATCH → REPLACE")
        lines.append("-" * 70)
        for r in active:
            match_short = str(r.get("match", ""))[:25]
            replace_short = str(r.get("replace", ""))[:25]
            lines.append(
                f"{r.get('id', '?'):<5} {r.get('type', '?'):<10} {r.get('scope', 'all'):<10} "
                f"{match_short} → {replace_short}"
            )
        global_rules = [r for r in active if r.get("scope") not in ("in_scope",)]
        if global_rules:
            lines.append(f"\nWarning: {len(global_rules)} rule(s) apply to ALL traffic (not in-scope-only).")
        lines.append("Note: rules are in-memory only — Burp restart wipes them.")
        return "\n".join(lines)

    @mcp.tool()
    async def get_match_replace() -> str:
        """List all active match-and-replace rules."""
        data = await client.get("/api/match-replace")
        if "error" in data:
            return f"Error: {data['error']}"

        rules = data.get("rules", [])
        if not rules:
            return "No match-replace rules active"

        lines = [f"Match-Replace Rules ({len(rules)}):"]
        for r in rules:
            status = "ON" if r.get("enabled", True) else "OFF"
            lines.append(
                f"  [{r.get('id')}] [{status}] {r.get('type')}/{r.get('scope','all')}: "
                f"{r.get('match', '')[:40]} → {r.get('replace', '')[:40]}"
            )
        return "\n".join(lines)

    @mcp.tool()
    async def remove_match_replace(rule_id: int) -> str:
        """Remove a specific match-and-replace rule by ID.

        Args:
            rule_id: Rule ID from set_match_replace or get_match_replace
        """
        data = await client.delete(f"/api/match-replace/{rule_id}")
        if "error" in data:
            return f"Error: {data['error']}"
        return f"Rule #{rule_id} removed"

    @mcp.tool()
    async def clear_match_replace() -> str:
        """Remove all match-and-replace rules."""
        data = await client.post("/api/match-replace/clear")
        if "error" in data:
            return f"Error: {data['error']}"
        return "All match-replace rules cleared"

    # ── Annotations ─────────────────────────────────────────────

    @mcp.tool()
    async def annotate_request(
        index: int,
        color: str = "",
        comment: str = "",
    ) -> str:
        """Mark a proxy history item with a color and/or comment in Burp's UI.
        Colors: RED, ORANGE, YELLOW, GREEN, CYAN, BLUE, PINK, MAGENTA, GRAY.

        Use to flag interesting requests, mark tested endpoints, or highlight vulnerabilities.
        Annotations are visible in Burp's proxy history — useful for human review.

        Args:
            index: Proxy history index
            color: Highlight color (e.g. 'RED' for vulnerabilities, 'GREEN' for tested)
            comment: Note text (e.g. 'Possible SQLi in id parameter')
        """
        data = await client.post("/api/annotations/set", json={
            "index": index, "color": color, "comment": comment,
        })
        if "error" in data:
            return f"Error: {data['error']}"
        return f"Annotated #{index}: {color} {comment}".strip()

    @mcp.tool()
    async def annotate_bulk(items: list[dict]) -> str:
        """Annotate multiple proxy history items at once.
        Each item: {'index': N, 'color': 'RED', 'comment': 'note'}

        Efficient for marking multiple findings or categorizing traffic.

        Args:
            items: List of annotation dicts with index, color, and/or comment
        """
        data = await client.post("/api/annotations/bulk", json={"items": items})
        if "error" in data:
            return f"Error: {data['error']}"
        return f"Annotated {data.get('applied', len(items))} items"

    @mcp.tool()
    async def get_annotations(index: int) -> str:
        """Get the current annotation (color and comment) for a proxy history item.

        Args:
            index: Proxy history index
        """
        data = await client.get(f"/api/annotations/{index}")
        if "error" in data:
            return f"Error: {data['error']}"

        color = data.get("color", "NONE")
        comment = data.get("notes", "")
        if color == "NONE" and not comment:
            return f"#{index}: no annotations"
        return f"#{index}: color={color}, comment={comment}"

    # ── Statistics & Live Traffic ────────────────────────────────

    @mcp.tool()
    async def get_proxy_stats() -> str:
        """Get proxy traffic statistics — total requests, unique hosts, method and status distributions.
        Quick situational awareness without parsing full history."""
        data = await client.get("/api/traffic/stats")
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Proxy Stats ({data.get('total_requests', 0)} total requests)"]
        lines.append(f"  Unique hosts: {data.get('unique_hosts', 0)}")

        methods = data.get("method_distribution", {})
        if methods:
            lines.append(f"\n  Methods: {', '.join(f'{k}={v}' for k, v in methods.items())}")

        statuses = data.get("status_code_distribution", {})
        if statuses:
            lines.append(f"  Status codes: {', '.join(f'{k}={v}' for k, v in statuses.items())}")

        return "\n".join(lines)

    @mcp.tool()
    async def get_live_requests(since_index: int) -> str:
        """Get new proxy requests captured since a given index.
        Use for polling to watch live traffic as the user browses.

        Call get_proxy_stats() first to get current total, then poll with
        get_live_requests(total-1) to see new traffic.

        Args:
            since_index: Return items after this proxy history index
        """
        data = await client.get("/api/traffic/live", params={"since_index": since_index})
        if "error" in data:
            return f"Error: {data['error']}"

        items = data.get("items", [])
        if not items:
            return f"No new requests since #{since_index}"

        lines = [f"New Requests ({len(items)} since #{since_index}):"]
        lines.append(f"{'IDX':<7} {'METHOD':<8} {'STATUS':<7} URL")
        lines.append("-" * 80)
        for item in items:
            lines.append(
                f"{item.get('index', '?'):<7} {item.get('method', '?'):<8} "
                f"{item.get('status_code', '?'):<7} {item.get('url', '?')}"
            )
        return "\n".join(lines)

    # ── Traffic Monitoring ──────────────────────────────────────

    @mcp.tool()
    async def register_traffic_monitor(tag: str, patterns: list[dict]) -> str:
        """Register a traffic monitor that watches for patterns in proxy traffic.
        Passively detects interesting traffic while the user browses.

        Each pattern: {'location': 'url'|'request_body'|'response_body'|'request_header'|'response_header', 'regex': 'pattern'}

        Examples:
        - API keys: [{'location':'response_body', 'regex':'(api[_-]?key|apikey)[\"\\s:=]+[a-zA-Z0-9]{20,}'}]
        - Admin paths: [{'location':'url', 'regex':'/admin|/debug|/internal'}]
        - SQL errors: [{'location':'response_body', 'regex':'(SQL syntax|ORA-|mysql_)'}]

        Args:
            tag: Unique name for this monitor
            patterns: List of pattern dicts with location and regex
        """
        data = await client.post("/api/traffic/monitor/register", json={
            "tag": tag, "patterns": patterns,
        })
        if "error" in data:
            return f"Error: {data['error']}"
        return f"Monitor '{tag}' registered with {len(patterns)} pattern(s). Use check_traffic_monitor('{tag}') to check for hits."

    @mcp.tool()
    async def check_traffic_monitor(tag: str) -> str:
        """Check a registered traffic monitor for hits since last check.
        Returns any proxy items that matched the monitor's patterns.

        Args:
            tag: Monitor name from register_traffic_monitor
        """
        data = await client.get("/api/traffic/monitor/check", params={"tag": tag})
        if "error" in data:
            return f"Error: {data['error']}"

        hits = data.get("hits", [])
        if not hits:
            return f"Monitor '{tag}': no new hits"

        lines = [f"Monitor '{tag}' — {len(hits)} hit(s):"]
        for hit in hits:
            lines.append(
                f"  [#{hit.get('index')}] {str(hit.get('matched_text', ''))[:100]}"
            )
        return "\n".join(lines)

    @mcp.tool()
    async def remove_traffic_monitor(tag: str) -> str:
        """Remove a registered traffic monitor.

        Args:
            tag: Monitor name to remove
        """
        data = await client.delete(f"/api/traffic/monitor/{tag}")
        if "error" in data:
            return f"Error: {data['error']}"
        return f"Monitor '{tag}' removed"
