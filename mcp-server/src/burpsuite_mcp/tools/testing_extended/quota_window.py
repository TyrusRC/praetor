"""probe_quota_window_edge — off-by-one rate-limit / quota reset double-consume.

Many quota implementations use fixed-window counters with second-precision
reset (X-RateLimit-Reset). At the boundary between two windows, "pre-warm"
the counter just before reset and immediately "post-fire" after reset — the
operation can succeed twice in roughly the same window if the implementation
clears the counter eagerly while still in flight.

Strix-derived. Pure black-box; needs an endpoint that returns X-RateLimit-*
or equivalent reset hints. Falls back to operator-supplied reset_at_ts.
"""

import asyncio
import re
import time

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def _extract_reset_seconds(headers: list[dict]) -> int | None:
    """Look for X-RateLimit-Reset / Retry-After / RateLimit-Reset (RFC draft).

    Returns:
      - absolute unix-second value if absolute timestamp header present
      - seconds-from-now if delta-style header present (added to time.time())
      - None if no useful header
    """
    now = int(time.time())
    for h in headers:
        name = h.get("name", "").lower() if isinstance(h, dict) else ""
        val = h.get("value", "") if isinstance(h, dict) else ""
        if name in ("x-ratelimit-reset", "ratelimit-reset", "x-rate-limit-reset"):
            m = re.match(r"\d+", val)
            if not m:
                continue
            v = int(m.group(0))
            # Heuristic: if value > 10000, it's absolute unix-second; else seconds-from-now
            return v if v > 10000 else now + v
        if name in ("retry-after",):
            m = re.match(r"\d+", val)
            if m:
                return now + int(m.group(0))
    return None


def register(mcp: FastMCP):

    @mcp.tool()
    async def probe_quota_window_edge(
        session: str,
        endpoint: str,
        method: str = "POST",
        body: str = "",
        reset_at_ts: int = 0,
        max_wait_seconds: int = 60,
    ) -> str:
        """Off-by-one quota-reset double-consume probe.

        Args:
            session: Auth session.
            endpoint: Path of the rate-limited operation.
            method: HTTP method.
            body: Optional request body.
            reset_at_ts: Override — explicit unix-second timestamp at which quota resets. If 0, auto-discover from response headers.
            max_wait_seconds: Cap on how long the tool will wait for the reset boundary.
        """
        headers = {"Content-Type": "application/json"} if body else {}

        # 1) Initial probe — discover quota state + reset time
        first = await client.post("/api/session/request", json={
            "session": session, "method": method, "path": endpoint,
            "headers": headers, "body": body,
        })
        if "error" in first:
            return f"Error on initial probe: {first['error']}"
        first_status = first.get("status", 0)
        first_headers = first.get("response_headers", first.get("headers", []))
        discovered_reset = _extract_reset_seconds(first_headers) if not reset_at_ts else reset_at_ts

        lines = [
            f"probe_quota_window_edge {method} {endpoint}",
            f"[probe-1] status={first_status} (initial state)",
        ]
        if not discovered_reset:
            return "\n".join(lines) + "\n\nNo X-RateLimit-Reset / Retry-After header found and no reset_at_ts provided. Cannot detect window edge — pass reset_at_ts explicitly."

        now = int(time.time())
        wait = discovered_reset - now - 1  # Pre-warm 1s BEFORE reset
        lines.append(f"Reset at unix-ts {discovered_reset} (~{discovered_reset - now}s from now)")
        if wait > max_wait_seconds:
            return "\n".join(lines) + f"\n\nReset is {wait}s away — exceeds max_wait_seconds={max_wait_seconds}. Increase max_wait_seconds or schedule manually."

        # 2) Burn through the quota until we get 429 / 403 / 5xx
        lines.append("\n[burn-quota]")
        burn_count = 0
        rejected_status = None
        for i in range(50):
            r = await client.post("/api/session/request", json={
                "session": session, "method": method, "path": endpoint,
                "headers": headers, "body": body,
            })
            if "error" in r:
                continue
            s = r.get("status", 0)
            burn_count += 1
            if s in (403, 429) or s >= 500:
                rejected_status = s
                lines.append(f"  Burned {burn_count} requests until status={s}")
                break
        else:
            lines.append(f"  Burned 50 requests without hitting rate-limit — endpoint may not be rate-limited or limit > 50.")

        # 3) Sleep until just before reset
        now = int(time.time())
        sleep_until = max(0, discovered_reset - now - 1)
        if sleep_until > max_wait_seconds:
            return "\n".join(lines) + f"\n\nSleep-until-reset is {sleep_until}s — exceeds max_wait_seconds={max_wait_seconds}."
        if sleep_until > 0:
            lines.append(f"\nSleeping {sleep_until}s until ~1s before reset...")
            await asyncio.sleep(sleep_until)

        # 4) Pre-warm: fire request right before reset
        pre = await client.post("/api/session/request", json={
            "session": session, "method": method, "path": endpoint,
            "headers": headers, "body": body,
        })
        pre_status = pre.get("status", 0) if "error" not in pre else 0
        lines.append(f"\n[pre-reset T-1s] status={pre_status}")

        # 5) Sleep 2s (T-1 -> T+1)
        await asyncio.sleep(2)

        # 6) Post-fire: fire request right after reset
        post = await client.post("/api/session/request", json={
            "session": session, "method": method, "path": endpoint,
            "headers": headers, "body": body,
        })
        post_status = post.get("status", 0) if "error" not in post else 0
        lines.append(f"[post-reset T+1s] status={post_status}")

        # Analyze
        pre_ok = 200 <= pre_status < 300
        post_ok = 200 <= post_status < 300
        findings: list[str] = []

        lines.append("\n--- Summary ---")
        if rejected_status is not None and pre_ok and post_ok:
            findings.append(f"DOUBLE_CONSUME: pre-reset (T-1s, status {pre_status}) AND post-reset (T+1s, status {post_status}) both succeeded after the rate-limit ({rejected_status}) was hit. Quota counter is reset eagerly while T-1s request was in flight — double-spend opportunity.")
        elif pre_ok and post_ok and rejected_status is None:
            findings.append("Both T-1s and T+1s succeeded but rate-limit was never hit. Endpoint may not be rate-limited — re-run after burning more requests.")
        elif pre_ok and not post_ok:
            findings.append("T-1s succeeded but T+1s denied. Reset behavior is correct OR T+1s missed window — re-run.")
        elif not pre_ok and post_ok:
            findings.append("Quota reset worked correctly (T-1s denied, T+1s allowed). Not vulnerable to off-by-one.")
        else:
            findings.append("Both denied — quota not yet reset or reset disabled. Re-run with adjusted timing.")
        for f in findings:
            lines.append(f"  {f}")
        return "\n".join(lines)
