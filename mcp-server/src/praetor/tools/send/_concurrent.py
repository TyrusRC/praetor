"""Volume + diff send: concurrent_requests, probe_with_diff."""

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools._request_headers import apply_realistic_headers
from ._format import _format_response


def register(mcp: FastMCP):

    @mcp.tool()
    async def concurrent_requests(  # cost: medium (scales with len(requests))
        requests: list[dict],
        concurrency: int = 10,
        delay_ms_between_batches: int = 0,
        bare_headers: bool = False,
        unsafe_headers: bool = False,
    ) -> str:
        """Fire many requests concurrently through Burp. For rate-limit testing, spam, or custom brute-force.

        Realistic browser headers are auto-injected on every request unless
        bare_headers=True. Per-request `headers` win; profile fills the rest.

        Args:
            requests: List of request dicts (same shape as curl_request args)
            concurrency: Max in-flight at once (default 10)
            delay_ms_between_batches: Sleep between batches in ms (default 0)
            bare_headers: Skip realistic-header injection on all requests.
            unsafe_headers: Keep browser fingerprint BUT also pass profile's
                wire-shape headers (Host / Content-Length / Transfer-Encoding /
                Content-Type) through. For smuggling / HPP / header injection.
        """
        import asyncio
        import time

        if not requests:
            return "Error: requests list is empty"
        concurrency = max(concurrency, 1)

        # Loop guard — concurrent_requests is the classic runaway spot.
        from praetor.tools._runtime_guard import note_call
        _first = requests[0] if requests else {}
        _sig = f"{len(requests)}:{_first.get('method','GET')}:{_first.get('url','')}"
        _loop = note_call("concurrent_requests", _sig)
        if _loop:
            return _loop

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
                merged = apply_realistic_headers(
                    payload["url"], payload.get("headers"),
                    bare=bare_headers, unsafe_headers=unsafe_headers,
                )
                if merged:
                    payload["headers"] = merged
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
        """Send a modified copy of a captured request and auto-diff against the original in one call.

        Args:
            index: Proxy history index of the baseline request
            modify_headers: Headers dict to merge/override
            modify_body: Body to substitute (entire body)
            modify_path: Path to substitute
            modify_method: Method to substitute
            diff_mode: 'smart' (status+length+keywords), 'full' (byte diff), 'headers' (header delta)
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
