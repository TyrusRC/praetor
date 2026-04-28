"""Tools for sending HTTP requests through Burp Suite.

Requests are routed through Burp's proxy listener (ProxyTunnel) so they appear
in **Proxy → HTTP history** AND the **Logger** tab AND the MCP history store
(get_mcp_history). Anomalies are auto-highlighted on the Proxy entry. If the
proxy listener is unreachable, the extension falls back to the direct HTTP
client and only Logger sees the request.
"""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def send_http_request(
        method: str,
        url: str,
        headers: dict | None = None,
        body: str = "",
    ) -> str:
        """Send an HTTP request through Burp Suite's HTTP client.

        Visibility: appears in Proxy → HTTP history (with anomaly highlighting),
        the Logger tab, and MCP history (get_mcp_history). Use this index in
        save_finding evidence.proxy_history_index or evidence.logger_index.

        Passive scanner still sees the request/response pair.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Full URL (e.g. https://example.com/api/users)
            headers: Optional dict of headers (e.g. {"Authorization": "Bearer xxx"})
            body: Optional request body string
        """
        payload = {"method": method, "url": url}
        if headers:
            payload["headers"] = headers
        if body:
            payload["body"] = body

        data = await client.post("/api/http/send", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        return _format_response(data)

    @mcp.tool()
    async def send_raw_request(
        raw: str,
        host: str,
        port: int = 443,
        https: bool = True,
    ) -> str:
        """Send a raw HTTP request through Burp Suite.
        Use when you need exact control over the request bytes (e.g. request smuggling tests).
        The raw string should be a complete HTTP request with CRLF line endings.

        Args:
            raw: Complete raw HTTP request string
            host: Target hostname
            port: Target port (default 443)
            https: Use HTTPS (default True)
        """
        data = await client.post("/api/http/raw", json={
            "raw": raw,
            "host": host,
            "port": port,
            "https": https,
        })
        if "error" in data:
            return f"Error: {data['error']}"
        return _format_response(data)

    @mcp.tool()
    async def resend_with_modification(
        index: int,
        modify_headers: dict | None = None,
        modify_body: str = "",
        modify_path: str = "",
        modify_method: str = "",
    ) -> str:
        """Resend a proxy history request with modifications through Burp.
        Takes a request by index and applies changes before sending.
        Perfect for testing parameter tampering, auth bypass, injection payloads.

        Args:
            index: Proxy history index of the original request
            modify_headers: Dict of headers to add/replace
            modify_body: New request body (replaces original)
            modify_path: New URL path (replaces original)
            modify_method: New HTTP method (replaces original)
        """
        payload: dict = {"index": index}
        if modify_headers:
            payload["modify_headers"] = modify_headers
        if modify_body:
            payload["modify_body"] = modify_body
        if modify_path:
            payload["modify_path"] = modify_path
        if modify_method:
            payload["modify_method"] = modify_method

        data = await client.post("/api/http/resend", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"
        return _format_response(data)

    @mcp.tool()
    async def send_to_repeater(index: int, tab_name: str = "") -> str:
        """Send a proxy history request to Burp's Repeater tool for manual testing.

        Args:
            index: Proxy history index of the request
            tab_name: Optional name for the Repeater tab
        """
        payload: dict = {"index": index}
        if tab_name:
            payload["tab_name"] = tab_name

        data = await client.post("/api/http/repeater", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"
        return data.get("message", "Sent to Repeater")

    @mcp.tool()
    async def send_to_intruder(index: int) -> str:
        """Send a proxy history request to Burp's Intruder tool for automated testing.

        Args:
            index: Proxy history index of the request
        """
        data = await client.post("/api/http/intruder", json={"index": index})
        if "error" in data:
            return f"Error: {data['error']}"
        return data.get("message", "Sent to Intruder")


    @mcp.tool()
    async def curl_request(
        url: str,
        method: str = "GET",
        headers: dict | None = None,
        body: str = "",
        data: str = "",
        json_body: dict | None = None,
        auth_user: str = "",
        auth_pass: str = "",
        bearer_token: str = "",
        cookies: dict | None = None,
        follow_redirects: bool = False,
        max_redirects: int = 10,
    ) -> str:
        """Send HTTP requests through Burp like curl/httpx - with optional redirect following, auth, and cookies.

        Visibility: appears in Proxy → HTTP history (with anomaly highlighting),
        the Logger tab, and MCP history (get_mcp_history).

        This is the most flexible request tool - use it like curl:
        - Opt-in redirect following (off by default to avoid cross-scope cookie/token leaks)
        - Supports Basic auth, Bearer tokens, custom cookies
        - Shortcuts for JSON and form-encoded data

        Args:
            url: Target URL (e.g. 'https://target.com/api/users')
            method: HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
            headers: Custom headers dict (e.g. {"X-Custom": "value"})
            body: Raw request body string
            data: Form-encoded data (sets Content-Type: application/x-www-form-urlencoded)
            json_body: JSON body dict (sets Content-Type: application/json)
            auth_user: Username for Basic auth
            auth_pass: Password for Basic auth
            bearer_token: Bearer token for Authorization header
            cookies: Cookies dict (e.g. {"session": "abc123"})
            follow_redirects: Follow HTTP redirects. Default False — enabling can leak
                              auth cookies / bearer tokens cross-scope on a 302. Only
                              enable when you've verified the target domain doesn't
                              redirect off-origin.
            max_redirects: Max redirect hops (default 10)
        """
        payload: dict = {
            "method": method,
            "url": url,
            "follow_redirects": follow_redirects,
            "max_redirects": max_redirects,
        }
        if headers:
            payload["headers"] = headers
        if body:
            payload["body"] = body
        if data:
            payload["data"] = data
        if json_body:
            payload["json"] = json_body
        if auth_user and auth_pass:
            payload["auth_user"] = auth_user
            payload["auth_pass"] = auth_pass
        if bearer_token:
            payload["bearer_token"] = bearer_token
        if cookies:
            payload["cookies"] = cookies

        resp = await client.post("/api/http/curl", json=payload)
        if "error" in resp:
            return f"Error: {resp['error']}"

        return _format_curl_response(resp)

    @mcp.tool()
    async def concurrent_requests(
        requests: list[dict],
        concurrency: int = 10,
        delay_ms_between_batches: int = 0,
    ) -> str:
        """Fire many requests concurrently. For rate-limit testing, spam tests,
        custom brute-force loops, business-flow probing, or any case Intruder's
        position/payload model can't express.

        Each request dict supports the same shape as `curl_request`:
          {"url", "method", "headers", "body", "data", "json_body",
           "auth_user", "auth_pass", "bearer_token", "cookies",
           "follow_redirects", "max_redirects"}

        Args:
            requests: List of request dicts (1..N). All fire through Burp.
            concurrency: Max in-flight at once (default 10). Use 1 for serial
                         back-to-back (rate-limit detection); higher for spam
                         and rate-limit-saturation tests.
            delay_ms_between_batches: Optional sleep between concurrency-sized
                         batches. Use 0 for full saturation.

        Returns a compact table:
          # | status | length | elapsed_ms | url
        Plus aggregate stats: median/p95/p99 elapsed, status distribution,
        first 429/Retry-After detection. The Burp Logger / Proxy history
        keeps the full detail for follow-up.

        Use cases:
          - Rate-limit absence test: 50 requests, concurrency=20, look for
            consistent 200s (vulnerable) vs 429 (protected).
          - Custom brute force: branch on response shape per attempt.
          - Spam / quota abuse: hammer a paid-feature endpoint.
          - Business-flow racing without `test_race_condition`'s exact-copy
            constraint (e.g. distinct payloads per attempt).
          - Detection-evasion timing tests: vary concurrency to find the
            burst threshold.
        """
        import asyncio
        import time

        if not requests:
            return "Error: requests list is empty"
        if concurrency < 1:
            concurrency = 1

        sem = asyncio.Semaphore(concurrency)
        results: list[dict] = [{} for _ in requests]

        async def _one(idx: int, req: dict) -> None:
            async with sem:
                start = time.perf_counter()
                payload = {k: v for k, v in req.items() if v is not None}
                payload.setdefault("method", "GET")
                if "url" not in payload:
                    results[idx] = {"error": "missing url"}
                    return
                try:
                    resp = await client.post("/api/http/curl", json=payload)
                except Exception as e:
                    results[idx] = {"error": str(e)[:200]}
                    return
                elapsed = int((time.perf_counter() - start) * 1000)
                if "error" in resp:
                    results[idx] = {"error": resp["error"], "elapsed_ms": elapsed}
                    return
                # Capture key fields; full body stays in proxy history.
                headers = resp.get("response_headers", []) or []
                retry_after = ""
                for h in headers:
                    if h.get("name", "").lower() == "retry-after":
                        retry_after = h.get("value", "")
                        break
                results[idx] = {
                    "status": resp.get("status_code", 0),
                    "length": len(resp.get("response_body", "") or ""),
                    "elapsed_ms": elapsed,
                    "url": payload.get("url", ""),
                    "method": payload.get("method", "GET"),
                    "retry_after": retry_after,
                    "history_index": resp.get("history_index"),
                }

        # Batch dispatch with optional inter-batch delay.
        batch_size = concurrency
        for batch_start in range(0, len(requests), batch_size):
            batch = list(enumerate(requests))[batch_start:batch_start + batch_size]
            await asyncio.gather(*[_one(i, r) for i, r in batch])
            if delay_ms_between_batches > 0 and batch_start + batch_size < len(requests):
                await asyncio.sleep(delay_ms_between_batches / 1000.0)

        # Aggregates
        statuses: dict[int, int] = {}
        elapsed_ms_list: list[int] = []
        first_429: int = -1
        first_retry_after = ""
        errors = 0
        for i, r in enumerate(results):
            if "error" in r and not r.get("status"):
                errors += 1
                continue
            s = r.get("status", 0)
            statuses[s] = statuses.get(s, 0) + 1
            if r.get("elapsed_ms") is not None:
                elapsed_ms_list.append(r["elapsed_ms"])
            if s == 429 and first_429 == -1:
                first_429 = i
                first_retry_after = r.get("retry_after", "")

        elapsed_ms_list.sort()
        n = len(elapsed_ms_list)

        def _pct(p: float) -> int:
            return elapsed_ms_list[min(int(n * p), n - 1)] if n else 0

        lines = [
            f"Concurrent requests: {len(requests)} dispatched, "
            f"concurrency={concurrency}, errors={errors}",
            f"Status: {dict(sorted(statuses.items()))}",
        ]
        if n:
            median = elapsed_ms_list[n // 2]
            lines.append(f"Elapsed (ms): median={median}, p95={_pct(0.95)}, p99={_pct(0.99)}, max={elapsed_ms_list[-1]}")
        if first_429 >= 0:
            ra = f", Retry-After={first_retry_after}" if first_retry_after else ""
            lines.append(f"First 429 at request #{first_429}{ra} — rate limit triggered.")
        else:
            lines.append("No 429 observed — rate limiting absent or threshold not reached.")

        # Detail table (compact)
        lines.append("")
        lines.append("# | status | len | elapsed_ms | retry-after | url")
        for i, r in enumerate(results[:50]):
            if "error" in r and not r.get("status"):
                lines.append(f"{i:3d} | ERR     | -   | {r.get('elapsed_ms','?'):>10} | - | {r.get('error','')[:60]}")
            else:
                lines.append(
                    f"{i:3d} | {r.get('status','?'):<7} | {r.get('length',0):<3} | "
                    f"{r.get('elapsed_ms','?'):>10} | {r.get('retry_after','-') or '-':<13} | "
                    f"{r.get('url','')[:60]}"
                )
        if len(results) > 50:
            lines.append(f"... {len(results) - 50} more (full detail in Burp Proxy history / Logger)")

        return "\n".join(lines)

    @mcp.tool()
    async def probe_with_diff(
        index: int,
        modify_headers: dict | None = None,
        modify_body: str = "",
        modify_path: str = "",
        modify_method: str = "",
        diff_mode: str = "smart",
    ) -> str:
        """Send a modified copy of a captured request AND auto-diff against
        the original — in one call.

        Replaces the common 3-call pattern:
          1) resend_with_modification(index, ...) → new index N'
          2) get_response_diff(index, N')
          3) extract_regex / extract_headers for the delta

        Use cases:
          - SQLi probe: send 'value' AND 'value with quote', see length/error delta
          - IDOR probe: change ID, see whether response shape diverges
          - Header injection: add Host:, X-Forwarded-Host:, see whether body reflects
          - Mass-assignment probe: add `role=admin` to body, see whether response includes new fields

        Args:
            index: Proxy history index of the baseline request
            modify_headers: Headers dict to merge/override
            modify_body: Body to substitute (entire body)
            modify_path: Path to substitute
            modify_method: Method to substitute (GET/POST/...)
            diff_mode: 'smart' (status + length + body keywords),
                       'full' (full byte diff via get_response_diff),
                       'headers' (just header set delta)

        Returns the probe response summary + a delta block highlighting
        what changed vs baseline. Both indices are returned for further
        use (annotate, save_finding, etc.).
        """
        # 1) Send the probe via existing /api/http/resend
        payload: dict = {"index": index}
        if modify_headers:
            payload["modify_headers"] = modify_headers
        if modify_body:
            payload["modify_body"] = modify_body
        if modify_path:
            payload["modify_path"] = modify_path
        if modify_method:
            payload["modify_method"] = modify_method

        resp = await client.post("/api/http/resend", json=payload)
        if "error" in resp:
            return f"Error: {resp['error']}"

        probe_index = resp.get("history_index")
        if probe_index is None:
            return f"Probe sent but history_index missing — cannot diff. Response: {_format_response(resp)}"

        # 2) Compute the diff
        diff_summary = ""
        if diff_mode == "full":
            diff_resp = await client.post("/api/search/response-diff", json={
                "index1": index, "index2": probe_index,
            })
            if "error" not in diff_resp:
                diff_summary = diff_resp.get("diff", "")[:2000]
        else:
            # Smart / headers — fetch both via /api/proxy/history/{index} and
            # compare locally for token-efficient delta.
            base = await client.get(f"/api/proxy/history/{index}")
            new = await client.get(f"/api/proxy/history/{probe_index}")
            if "error" in base or "error" in new:
                diff_summary = "(baseline or probe entry not found in proxy history)"
            else:
                base_status = base.get("status_code") or base.get("status")
                new_status = new.get("status_code") or new.get("status")
                base_len = len(base.get("response_body", "") or "")
                new_len = len(new.get("response_body", "") or "")
                lines = []
                if base_status != new_status:
                    lines.append(f"  status: {base_status} → {new_status} (CHANGED)")
                else:
                    lines.append(f"  status: {base_status} (same)")
                len_delta = new_len - base_len
                lines.append(f"  length: {base_len} → {new_len} (delta {len_delta:+d})")

                # Smart keyword scan on the new body for SQL/error/exec markers
                if diff_mode == "smart":
                    body_lower = (new.get("response_body", "") or "").lower()
                    base_lower = (base.get("response_body", "") or "").lower()
                    flags = []
                    for marker in ("sql syntax", "ora-", "mysql_fetch", "pg_query",
                                   "you have an error", "unclosed", "stack trace",
                                   "uid=", "gid=", "root:x:", "[fonts]",
                                   "<script", "alert(", "eval(",
                                   "AccessKeyId", "SecretAccessKey",
                                   "permission denied", "access denied"):
                        if marker.lower() in body_lower and marker.lower() not in base_lower:
                            flags.append(marker)
                    if flags:
                        lines.append(f"  NEW markers in probe response: {', '.join(flags)}")
                if diff_mode == "headers":
                    base_h = {h.get("name", "").lower() for h in base.get("response_headers", [])}
                    new_h = {h.get("name", "").lower() for h in new.get("response_headers", [])}
                    added = sorted(new_h - base_h)
                    removed = sorted(base_h - new_h)
                    if added:
                        lines.append(f"  headers added: {', '.join(added)}")
                    if removed:
                        lines.append(f"  headers removed: {', '.join(removed)}")
                diff_summary = "\n".join(lines)

        return (
            f"Probe sent (history_index={probe_index} vs baseline={index})\n"
            f"Response: {resp.get('status_code','?')} | "
            f"{len(resp.get('response_body','') or '')} bytes\n"
            f"\nDelta vs baseline:\n{diff_summary or '(no measurable delta)'}\n"
            f"\nNext steps if anomaly is real:\n"
            f"  annotate_request({probe_index}, color='YELLOW', comment='<f-id> | <vuln> | <delta>')\n"
            f"  send_to_organizer({probe_index})\n"
            f"  → verify-finding skill (Step 0 replay → assess_finding → save_finding)"
        )


def _format_curl_response(data: dict) -> str:
    lines = [f"Status: {data.get('status_code', 'N/A')}"]

    redirects = data.get("redirects_followed", 0)
    if redirects > 0:
        lines.append(f"Redirects followed: {redirects}")
        chain = data.get("redirect_chain", [])
        for hop in chain:
            lines.append(f"  {hop.get('status')} -> {hop.get('location')}")

    lines.append(f"Response Length: {data.get('response_length', 0)} bytes")

    resp_headers = data.get("response_headers", [])
    if resp_headers:
        lines.append("\n--- Response Headers ---")
        for h in resp_headers:
            lines.append(f"  {h['name']}: {h['value']}")

    body = data.get("response_body", "")
    if body:
        lines.append(f"\n--- Response Body ({len(body)} chars) ---")
        lines.append(_truncate_body(body))

    return "\n".join(lines)


def _format_response(data: dict) -> str:
    lines = [f"Status: {data.get('status_code', 'N/A')}"]
    lines.append(f"Response Length: {data.get('response_length', 0)} bytes")

    headers = data.get("response_headers", [])
    if headers:
        lines.append("\n--- Response Headers ---")
        for h in headers:
            lines.append(f"  {h['name']}: {h['value']}")

    body = data.get("response_body", "")
    if body:
        lines.append(f"\n--- Response Body ({len(body)} chars) ---")
        lines.append(_truncate_body(body))

    return "\n".join(lines)


def _truncate_body(body: str, max_chars: int = 2000) -> str:
    """Truncate response body to save tokens. Pass max_chars=0 for full body."""
    if max_chars <= 0 or len(body) <= max_chars:
        return body
    return body[:max_chars] + f"\n...[truncated, {len(body)} total chars — use get_request_detail(index, full_body=True) for full body]"
