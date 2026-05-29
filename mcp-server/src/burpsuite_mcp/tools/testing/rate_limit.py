"""Rate-limit probe: rapid-fire phase + bypass-header phase.

Lives under tools/testing/ because it is a behavior probe against the target,
not external recon. Moved out of recon_extended.py where it was misfiled.
"""

import asyncio
import time

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from ._verdict import make_verdict


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_rate_limit(
        session: str,
        method: str,
        path: str,
        requests_count: int = 30,
        delay_ms: int = 0,
    ) -> dict:
        """Test rate limiting on an endpoint with rapid requests, then try bypass headers if limited.

        Returns VerdictResult (W7 schema).

        Args:
            session: Session name
            method: HTTP method
            path: URL path to test
            requests_count: Number of requests to send (default 30, max 100)
            delay_ms: Delay between requests in ms (default 0)
        """
        requests_count = min(requests_count, 100)

        # Phase 1: Rapid fire requests
        status_codes: list[int] = []
        response_times: list[float] = []
        rate_limited = False
        rate_limit_at = -1

        for i in range(requests_count):
            if delay_ms > 0 and i > 0:
                await asyncio.sleep(delay_ms / 1000.0)

            start = time.monotonic()
            data = await client.post("/api/session/request", json={
                "session": session,
                "method": method,
                "path": path,
            })
            elapsed = (time.monotonic() - start) * 1000  # ms

            if "error" in data:
                status_codes.append(0)
                response_times.append(elapsed)
                continue

            status = data.get("status", data.get("status_code", 0))
            status_codes.append(status)
            response_times.append(elapsed)

            if status == 429 and not rate_limited:
                rate_limited = True
                rate_limit_at = i + 1

        # Analyze Phase 1
        lines = [f"Rate limit test: {method} {path} ({requests_count} requests):", ""]

        code_counts: dict[int, int] = {}
        for code in status_codes:
            code_counts[code] = code_counts.get(code, 0) + 1

        lines.append("  Phase 1 - Rapid requests:")
        lines.append(f"    Status codes: {', '.join(f'{code}={count}' for code, count in sorted(code_counts.items()))}")

        if response_times:
            avg_time = sum(response_times) / len(response_times)
            min_time = min(response_times)
            max_time = max(response_times)
            lines.append(f"    Response time: avg={avg_time:.0f}ms, min={min_time:.0f}ms, max={max_time:.0f}ms")

        if rate_limited:
            lines.append(f"    Rate limited at request #{rate_limit_at}")
        else:
            if response_times and max(response_times) > 3 * min(response_times):
                lines.append("    Possible soft rate limiting (response times increasing)")
            else:
                lines.append("    No rate limiting detected")

        # Phase 2: Bypass attempts (only if rate limited)
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Original-URL": path},
            {"X-Originating-IP": "127.0.0.1"},
        ]

        if rate_limited:
            lines.append("")
            lines.append("  Phase 2 - Bypass attempts:")

            for header_dict in bypass_headers:
                header_name = list(header_dict.keys())[0]
                header_value = list(header_dict.values())[0]

                data = await client.post("/api/session/request", json={
                    "session": session,
                    "method": method,
                    "path": path,
                    "headers": {header_name: header_value},
                })

                if "error" in data:
                    lines.append(f"    {header_name}: ERROR - {data['error'][:60]}")
                    continue

                status = data.get("status", data.get("status_code", 0))
                bypassed = status != 429
                marker = "BYPASSED" if bypassed else "blocked"
                lines.append(f"    {header_name}: [{status}] {marker}")

        # Summary
        lines.append("")
        if rate_limited:
            lines.append(f"  Result: Rate limited after {rate_limit_at} requests. Check bypass results above.")
        else:
            lines.append(f"  Result: No rate limiting after {requests_count} requests.")

        human = "\n".join(lines)
        # "rate_limit" finding is itself a low/medium standalone (NEVER_SUBMIT
        # on non-sensitive endpoints per Rule 17). CONFIRMED when no rate
        # limiting on a state-changing endpoint; SUSPECTED on bypass via
        # forged headers.
        if not rate_limited:
            verdict, confidence = "CONFIRMED", 0.7
            ev = f"no rate limiting after {requests_count} requests — submit only if endpoint is sensitive (login/reset/MFA)"
        else:
            verdict, confidence = "FAILED", 0.1
            ev = f"rate limited after {rate_limit_at} requests"

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="rate_limit",
            details={
                "path": path, "method": method,
                "requests_count": requests_count,
                "rate_limited": rate_limited,
                "rate_limit_at": rate_limit_at,
            },
            summary=human,
        )
