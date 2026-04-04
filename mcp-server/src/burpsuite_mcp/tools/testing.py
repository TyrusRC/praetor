"""Advanced testing tools - smart fuzzing engine and auth state comparison."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def fuzz_parameter(
        index: int,
        parameters: list[dict] | None = None,
        parameter: str = "",
        payloads: list[str] | None = None,
        injection_point: str = "query",
        attack_type: str = "sniper",
        grep_match: list[str] | None = None,
        grep_extract: str = "",
        delay_ms: int = 0,
    ) -> str:
        """Smart fuzz engine - send Claude-generated payloads and analyze responses for anomalies.
        You are the brain: analyze the target's tech stack, parameters, and context to craft
        targeted payloads. This tool is the execution engine.

        Attack types:
        - sniper: One parameter at a time, each payload (default)
        - battering_ram: Same payload in all parameters simultaneously
        - pitchfork: Parallel payload lists (payload[i] in param[i])
        - cluster_bomb: All combinations across all parameters

        Results include anomaly detection: status code changes, response length variance,
        timing anomalies, and grep pattern matches.

        Args:
            index: Proxy history index of the base request
            parameters: List of parameter configs: [{"name": "id", "position": "query", "payloads": ["1", "' OR 1=1--"]}]
            parameter: Simple mode - single parameter name (use with payloads + injection_point)
            payloads: Simple mode - payload list for single parameter
            injection_point: Simple mode - where to inject: query, body, header, path, cookie
            attack_type: sniper, battering_ram, pitchfork, or cluster_bomb
            grep_match: List of strings to search for in responses (e.g. ["error", "SQL", "syntax"])
            grep_extract: Regex pattern to extract from responses
            delay_ms: Delay between requests in milliseconds
        """
        # Build the request payload
        payload: dict = {"index": index, "attack_type": attack_type}

        if parameters:
            payload["parameters"] = parameters
        elif parameter and payloads:
            payload["parameters"] = [{"name": parameter, "position": injection_point, "payloads": payloads}]
        else:
            return "Error: Provide 'parameters' list or 'parameter' + 'payloads'"

        if grep_match:
            payload["grep_match"] = grep_match
        if grep_extract:
            payload["grep_extract"] = grep_extract
        if delay_ms > 0:
            payload["delay_ms"] = delay_ms

        data = await client.post("/api/fuzz", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        return _format_fuzz_results(data)

    @mcp.tool()
    async def compare_auth_states(
        index: int,
        original_cookies: dict | None = None,
        alt_cookies: dict | None = None,
        original_token: str = "",
        alt_token: str = "",
        remove_auth: bool = False,
    ) -> str:
        """Compare responses between different authentication states to find IDOR/auth bypass.
        Resends a request with different credentials and diffs the responses.

        Use cases:
        - IDOR: Same endpoint with different user's session cookie
        - Auth bypass: Request with vs without authentication
        - Privilege escalation: Admin endpoint with regular user token

        Args:
            index: Proxy history index of the request to test
            original_cookies: Cookies dict for first request (uses original if empty)
            alt_cookies: Cookies dict for second request (different user)
            original_token: Bearer token for first request (uses original if empty)
            alt_token: Bearer token for second request (different user)
            remove_auth: If True, second request strips all auth headers/cookies
        """
        # First request: original or with specified auth
        modify1: dict = {"index": index}
        if original_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in original_cookies.items())
            modify1["modify_headers"] = {"Cookie": cookie_str}
        if original_token:
            headers = modify1.get("modify_headers", {})
            headers["Authorization"] = f"Bearer {original_token}"
            modify1["modify_headers"] = headers

        # Second request: alternate auth or no auth
        modify2: dict = {"index": index}
        if alt_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in alt_cookies.items())
            modify2["modify_headers"] = {"Cookie": cookie_str}
        if alt_token:
            headers = modify2.get("modify_headers", {})
            headers["Authorization"] = f"Bearer {alt_token}"
            modify2["modify_headers"] = headers
        if remove_auth:
            modify2["modify_headers"] = {"Cookie": "", "Authorization": ""}

        # Send both requests
        data1 = await client.post("/api/http/resend", json=modify1)
        data2 = await client.post("/api/http/resend", json=modify2)

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

    @mcp.tool()
    async def send_to_comparer(index1: int, index2: int) -> str:
        """Send two proxy history items to Burp's Comparer tab for visual comparison.

        Args:
            index1: First proxy history index
            index2: Second proxy history index
        """
        data = await client.post("/api/search/send-to-comparer", json={
            "index1": index1,
            "index2": index2,
        })
        if "error" in data:
            return f"Error: {data['error']}"
        return data.get("message", "Sent to Comparer")

    @mcp.tool()
    async def compare_responses(
        index1: int,
        index2: int,
        mode: str = "full",
    ) -> str:
        """Enhanced response comparison - detailed diff between two proxy history items.
        More detailed than get_response_diff: shows header diffs, body similarity,
        unique words in each response.

        Args:
            index1: First proxy history index
            index2: Second proxy history index
            mode: Comparison mode - 'full', 'headers', or 'body'
        """
        data = await client.post("/api/search/compare", json={
            "index1": index1,
            "index2": index2,
            "mode": mode,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Enhanced Comparison: #{index1} vs #{index2} (mode: {mode})\n"]

        status = data.get("status_diff", {})
        if status:
            lines.append(f"Status: {status.get('item1', '?')} vs {status.get('item2', '?')}")

        length = data.get("length_diff", {})
        if length:
            lines.append(f"Length: {length.get('item1', '?')} vs {length.get('item2', '?')}")

        # Header diffs
        header_diffs = data.get("header_diffs", [])
        if header_diffs:
            lines.append(f"\n--- Header Differences ({len(header_diffs)}) ---")
            for h in header_diffs:
                lines.append(f"  {h.get('name')}: {h.get('item1', '(absent)')} vs {h.get('item2', '(absent)')}")

        # Body diff
        body = data.get("body_diff", {})
        if body:
            lines.append(f"\n--- Body Diff ---")
            lines.append(f"  Identical: {body.get('identical', False)}")
            if "similarity_pct" in body:
                lines.append(f"  Similarity: {body['similarity_pct']}%")
            lines.append(f"  Added: {body.get('added_lines', 0)} | Removed: {body.get('removed_lines', 0)}")
            for line in body.get("diff_lines", [])[:50]:
                lines.append(f"  {line}")

        # Unique words
        u1 = data.get("unique_to_item1", [])
        u2 = data.get("unique_to_item2", [])
        if u1:
            lines.append(f"\nUnique to #{index1}: {', '.join(u1[:20])}")
        if u2:
            lines.append(f"Unique to #{index2}: {', '.join(u2[:20])}")

        return "\n".join(lines)


def _format_fuzz_results(data: dict) -> str:
    """Format fuzz results into a compact, analysis-friendly table."""
    results = data.get("results", [])
    total = data.get("total_requests", 0)
    baseline_status = data.get("baseline_status", "?")
    baseline_length = data.get("baseline_length", "?")

    lines = [f"Fuzz Results ({total} requests, baseline: {baseline_status}/{baseline_length} bytes):\n"]

    # Table header
    header = f"{'#':<4} {'PARAM':<15} {'PAYLOAD':<35} {'STATUS':<8} {'LENGTH':<10} {'TIME':<8}"
    grep_keys = set()
    for r in results:
        grep_keys.update(r.get("grep_matches", {}).keys())
    if grep_keys:
        header += " " + " ".join(f"{k[:8]:<8}" for k in sorted(grep_keys))
    header += " FLAGS"
    lines.append(header)
    lines.append("-" * len(header))

    for r in results:
        payload_display = r.get("payload", "")[:33]
        if len(r.get("payload", "")) > 33:
            payload_display += ".."

        anomalies = r.get("anomalies", [])
        flags = " ".join(f"[!{a}]" for a in anomalies) if anomalies else ""

        line = (
            f"{r.get('payload_index', '?'):<4} "
            f"{r.get('parameter', '?'):<15} "
            f"{payload_display:<35} "
            f"{r.get('status_code', '?'):<8} "
            f"{r.get('response_length', '?'):<10} "
            f"{r.get('response_time_ms', '?'):<8}"
        )

        # Grep matches
        grep = r.get("grep_matches", {})
        if grep_keys:
            line += " " + " ".join(f"{grep.get(k, 0):<8}" for k in sorted(grep_keys))

        line += f" {flags}"
        lines.append(line)

        # Show response snippet for anomalous results
        snippet = r.get("response_snippet", "")
        if snippet and anomalies:
            lines.append(f"     > {snippet[:120]}")

    # Anomaly summary
    summary = data.get("anomaly_summary", {})
    if summary:
        lines.append(f"\n--- Anomaly Summary ---")
        if summary.get("status_anomalies"):
            lines.append(f"  [!STATUS] {summary['status_anomalies']} responses with different status code")
        if summary.get("length_anomalies"):
            lines.append(f"  [!LENGTH] {summary['length_anomalies']} responses with unusual length")
        if summary.get("timing_anomalies"):
            lines.append(f"  [!TIMING] {summary['timing_anomalies']} responses with unusual timing")
        if summary.get("grep_hits"):
            lines.append(f"  [!GREP]   {summary['grep_hits']} grep pattern matches")

    return "\n".join(lines)
