"""probe_timeless_timing — jitter-free timing oracle via paired H2 streams.

Standard time-based SQLi / SSTI / blind-XXE detection compares absolute
response times to a fixed threshold. Network jitter, server load spikes, and
TLS handshake variance all add noise — a real SLEEP(5) finding can look like
a flaky 4.8s outlier and be dismissed.

Timeless timing (Mathy Vanhoef, 2020) pairs two requests in the SAME HTTP/2
connection and compares their RELATIVE completion times. Network jitter
affects both equally, cancelling out. A 200ms delta is significant evidence
of differential server-side processing.

Use case:
  baseline    = "SELECT 1"           expected: ~10ms
  suspect     = "SELECT SLEEP(2)"    expected: ~2010ms

  Paired in one connection -> the 2000ms delta survives jitter that would
  obscure absolute thresholds.

Routes through Burp at 127.0.0.1:8080.
"""

import asyncio
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing import _h2_lowlevel


def register(mcp: FastMCP):

    @mcp.tool()
    async def probe_timeless_timing(
        target_url: str,
        baseline_request: dict,
        suspect_request: dict,
        pairs: int = 5,
        threshold_ms: int = 100,
    ) -> str:
        """Compare two requests' relative completion time across N pairs in single H2 connections.

        baseline_request and suspect_request differ only in the payload bit being tested.
        Each "pair" is fired as two H2 streams in one connection — jitter affects both
        equally, so the time delta is server-side-only.

        A confirmed finding: delta > threshold_ms in ≥ ceil(pairs * 0.6) of pairs.

        Args:
            target_url: HTTPS URL of the endpoint.
            baseline_request: {method, path, headers?, body?} — the "fast" reference.
            suspect_request: {method, path, headers?, body?} — the "potentially-slow" probe.
            pairs: Number of paired runs (default 5).
            threshold_ms: Minimum suspect-minus-baseline delta to count as anomaly.
        """
        if pairs < 1:
            return "Error: pairs must be ≥ 1"
        pairs = min(pairs, 20)

        # Scope
        scope = await client.check_scope(target_url)
        if "error" in scope:
            return f"Error: scope check failed: {scope['error']}"
        if not scope.get("in_scope", False):
            return f"Error: {target_url} not in scope"

        parsed = urlparse(target_url)
        if parsed.scheme != "https":
            return "Error: timeless timing requires HTTPS (HTTP/2 ALPN)."
        host = parsed.hostname or ""
        port = parsed.port or 443

        def _pair_run() -> tuple[int, int]:
            """One connection, two streams. Return (baseline_ns, suspect_ns)."""
            ssock, conn = _h2_lowlevel.open_h2_tunnel(host, port)
            try:
                # Send baseline FIRST so it gets stream_id 1, suspect stream_id 3.
                # Both arrive in the same TCP packet — server processes them
                # concurrently; relative ordering of completion is the signal.
                buf, stream_ids = _h2_lowlevel.build_streams_buffer(
                    conn, host, [baseline_request, suspect_request]
                )
                _h2_lowlevel.send_singlepacket(ssock, buf)
                results = _h2_lowlevel.read_until_complete(ssock, conn, stream_ids, 15.0)
                base_t = results.get(stream_ids[0], {}).get("time_ns", -1)
                susp_t = results.get(stream_ids[1], {}).get("time_ns", -1)
                return base_t, susp_t
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

        results: list[tuple[int, int]] = []
        for i in range(pairs):
            try:
                base_t, susp_t = await asyncio.to_thread(_pair_run)
                results.append((base_t, susp_t))
            except Exception as e:
                return f"Error on pair #{i}: {type(e).__name__}: {e}"

        lines = [
            f"probe_timeless_timing {target_url}",
            f"Pairs: {pairs} | threshold: {threshold_ms} ms (suspect - baseline)",
            "",
        ]
        hits = 0
        deltas: list[int] = []
        for i, (b_ns, s_ns) in enumerate(results):
            if b_ns < 0 or s_ns < 0:
                lines.append(f"  pair {i}: TIMEOUT (base={b_ns} suspect={s_ns})")
                continue
            delta_ms = (s_ns - b_ns) / 1_000_000
            deltas.append(int(delta_ms))
            tag = " *** ANOMALY ***" if delta_ms >= threshold_ms else ""
            if delta_ms >= threshold_ms:
                hits += 1
            lines.append(f"  pair {i}: baseline={b_ns/1_000_000:.2f}ms suspect={s_ns/1_000_000:.2f}ms delta={delta_ms:+.2f}ms{tag}")

        confirm_floor = max(1, int(pairs * 0.6 + 0.5))
        lines.append("")
        if deltas:
            d_min = min(deltas)
            d_max = max(deltas)
            d_avg = sum(deltas) / len(deltas)
            lines.append(f"Delta stats: min={d_min} max={d_max} avg={d_avg:.1f} ms")
        lines.append(f"Anomalies: {hits}/{pairs} (confirm threshold = {confirm_floor}/{pairs})")
        if hits >= confirm_floor:
            lines.append("\n*** TIMELESS TIMING ANOMALY CONFIRMED *** — server-side processing time is materially higher for suspect payload.")
            lines.append("This is jitter-immune evidence. Strong candidate for time-based SQLi / SSTI / XXE / RCE.")
        else:
            lines.append("\nNo confirmed timing differential. Either no vuln OR the payload didn't trigger differential processing on this endpoint.")
        return "\n".join(lines)
