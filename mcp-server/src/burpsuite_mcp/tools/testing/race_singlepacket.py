"""probe_race_singlepacket — HTTP/2 single-packet attack via raw h2 frames.

Turbo-Intruder's BURP2 engine technique. Coalesce N HTTP/2 stream frames
(HEADERS + DATA) into a single TCP packet so the server processes all N
requests simultaneously — eliminating network jitter as a race-window
variable.

Implementation:
  1. Open one TCP socket -> Burp proxy at 127.0.0.1:8080.
  2. CONNECT tunnel to target host:port.
  3. TLS handshake with ALPN h2 over the tunnel.
  4. Send H2 preface + SETTINGS.
  5. Build N stream HEADERS+DATA frames into one byte buffer.
  6. TCP_NODELAY + one sendall() = single-packet flush.
  7. Read response frames per stream; record per-stream completion time.

All traffic routes through Burp (Rule 26a) — the proxy captures the
single-packet attack in its Logger / Proxy history.
"""

import asyncio
import time
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing import _h2_lowlevel


def register(mcp: FastMCP):

    @mcp.tool()
    async def probe_race_singlepacket(
        target_url: str,
        method: str = "POST",
        body: str = "",
        headers: dict | None = None,
        concurrent: int = 20,
        expect_once: bool = True,
    ) -> str:
        """HTTP/2 single-packet attack — N stream frames coalesced into one TCP packet.

        Most effective race-condition primitive available — the standard
        thread-pool approach (test_race_condition) still has TCP-level jitter
        because each request travels in its own packet. This pre-builds N stream
        frames in one HTTP/2 connection and flushes them all in a single sendall(),
        so the server kernel hands all N to user-space simultaneously.

        Requires:
          - Target speaks HTTP/2 (most modern web apps do)
          - Burp proxy allows CONNECT tunnels (default behavior)

        Args:
            target_url: Full HTTPS URL (h2 always uses TLS).
            method: HTTP method.
            body: Request body string.
            headers: Extra request headers.
            concurrent: Number of parallel streams (max 100).
            expect_once: Flag if more than one 2xx response = race.
        """
        if concurrent < 2:
            return "Error: concurrent must be ≥ 2"
        concurrent = min(concurrent, 100)

        # Scope check
        scope = await client.check_scope(target_url)
        if "error" in scope:
            return f"Error: scope check failed: {scope['error']}"
        if not scope.get("in_scope", False):
            return f"Error: {target_url} not in scope"

        parsed = urlparse(target_url)
        if parsed.scheme != "https":
            return "Error: HTTP/2 single-packet requires HTTPS. Use probe_race_lastbyte for HTTP."
        host = parsed.hostname or ""
        port = parsed.port or 443
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        # Build N identical requests (same as Turbo Intruder use case)
        request_template = {
            "method": method,
            "path": path,
            "headers": dict(headers or {}),
            "body": body,
        }
        requests = [dict(request_template) for _ in range(concurrent)]

        # Open tunnel in worker thread (blocking socket ops)
        try:
            ssock, conn = await asyncio.to_thread(_h2_lowlevel.open_h2_tunnel, host, port)
        except Exception as e:
            return f"Error opening H2 tunnel via Burp: {type(e).__name__}: {e}"

        try:
            buf, stream_ids = await asyncio.to_thread(
                _h2_lowlevel.build_streams_buffer, conn, host, requests
            )

            # Single-packet flush
            flush_ns = await asyncio.to_thread(_h2_lowlevel.send_singlepacket, ssock, buf)

            # Read responses
            results = await asyncio.to_thread(
                _h2_lowlevel.read_until_complete, ssock, conn, stream_ids, 15.0
            )
        finally:
            try:
                conn.close_connection()
                ssock.sendall(conn.data_to_send())
            except Exception:
                pass
            try:
                ssock.close()
            except Exception:
                pass

        # Analyse
        lines = [
            f"probe_race_singlepacket {method} {target_url}",
            f"H2 streams: {concurrent} | flush window: {flush_ns / 1_000_000:.3f} ms (single TCP packet)",
            f"Buffer size: {len(buf)} bytes",
            "",
        ]
        statuses: dict[int, int] = {}
        success_count = 0
        time_samples: list[int] = []
        for sid in stream_ids:
            r = results.get(sid, {})
            s = r.get("status", 0)
            statuses[s] = statuses.get(s, 0) + 1
            if 200 <= s < 300:
                success_count += 1
            if r.get("time_ns", -1) >= 0:
                time_samples.append(r["time_ns"])
            preview = r.get("body_preview", "")[:60].replace("\n", " ")
            tns = r.get("time_ns", -1)
            time_str = f"{tns/1_000_000:.2f}ms" if tns >= 0 else "TIMEOUT"
            lines.append(f"  stream={sid}: status={s} len={r.get('length', 0)} t={time_str} preview={preview!r}")

        lines.append("")
        lines.append(f"Status distribution: {dict(statuses)}")
        lines.append(f"Successful (2xx): {success_count}")
        if time_samples:
            t_min = min(time_samples) / 1_000_000
            t_max = max(time_samples) / 1_000_000
            t_avg = sum(time_samples) / len(time_samples) / 1_000_000
            lines.append(f"Response time range: {t_min:.2f} - {t_max:.2f} ms (avg {t_avg:.2f} ms, jitter {t_max - t_min:.2f} ms)")

        if expect_once and success_count > 1:
            lines.append(f"\n*** RACE CONFIRMED: {success_count} successes from {concurrent} single-packet streams ***")
            lines.append("Verify side effect in persistent state (DB rows, balance, transaction ledger).")
        elif success_count == 1:
            lines.append("\nSingle 2xx — race not observed at this concurrency.")
        elif success_count == 0:
            lines.append("\nNo 2xx responses — endpoint may not be reachable as configured; check status distribution.")
        return "\n".join(lines)
