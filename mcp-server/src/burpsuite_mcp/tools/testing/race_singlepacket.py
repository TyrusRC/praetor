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
import re
import time
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools._request_headers import apply_realistic_headers
from burpsuite_mcp.tools.testing import _h2_lowlevel
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict

# Alt-Svc h3 advertisement: `h3=":443"; ma=86400` or draft `h3-29="..."`.
_ALT_SVC_H3_RE = re.compile(r'h3(?:-\d+)?\s*=\s*"([^"]+)"')


async def _singlepacket_exchange(
    host: str, port: int, requests: list[dict], read_timeout: float = 15.0
) -> tuple[dict[int, dict], bytes, list[int], int]:
    """Open a Burp h2 tunnel, coalesce N stream frames into one TCP packet, flush, read.

    Shared transport for probe_race_singlepacket and probe_race_http3_datagram.
    Returns (results, buf, stream_ids, flush_ns). Raises on tunnel/exchange failure.
    """
    ssock, conn = await asyncio.to_thread(_h2_lowlevel.open_h2_tunnel, host, port)
    try:
        buf, stream_ids = await asyncio.to_thread(
            _h2_lowlevel.build_streams_buffer, conn, host, requests
        )
        flush_ns = await asyncio.to_thread(_h2_lowlevel.send_singlepacket, ssock, buf)
        results = await asyncio.to_thread(
            _h2_lowlevel.read_until_complete, ssock, conn, stream_ids, read_timeout
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
    return results, buf, stream_ids, flush_ns


def _tally_race(
    stream_ids: list[int], results: dict[int, dict]
) -> tuple[dict[int, int], int, list[int], list[str]]:
    """Tally per-stream outcomes. Returns (statuses, success_count, time_samples, lines)."""
    statuses: dict[int, int] = {}
    success_count = 0
    time_samples: list[int] = []
    lines: list[str] = []
    for sid in stream_ids:
        r = results.get(sid, {})
        s = r.get("status", 0)
        statuses[s] = statuses.get(s, 0) + 1
        if 200 <= s < 300:
            success_count += 1
        tns = r.get("time_ns", -1)
        if tns >= 0:
            time_samples.append(tns)
        preview = r.get("body_preview", "")[:60].replace("\n", " ")
        time_str = f"{tns/1_000_000:.2f}ms" if tns >= 0 else "TIMEOUT"
        lines.append(f"  stream={sid}: status={s} len={r.get('length', 0)} t={time_str} preview={preview!r}")
    return statuses, success_count, time_samples, lines


async def _detect_h3_advertised(url: str) -> list[str]:
    """Return h3 host:port targets from the origin's Alt-Svc header (fetched via Burp)."""
    try:
        resp = await client.post("/api/http/curl", json={
            "method": "GET", "url": url,
            "headers": apply_realistic_headers(url, {}),
            "follow_redirects": False,
        })
    except Exception:
        return []
    if not isinstance(resp, dict) or "error" in resp:
        return []
    targets: list[str] = []
    for h in resp.get("response_headers", []) or []:
        name = h.get("name", "") if isinstance(h, dict) else ""
        if name.lower() != "alt-svc":
            continue
        val = h.get("value", "") if isinstance(h, dict) else ""
        for m in _ALT_SVC_H3_RE.finditer(val):
            targets.append(m.group(1).strip())
    return targets


def register(mcp: FastMCP):

    @mcp.tool()
    async def probe_race_singlepacket(
        target_url: str,
        method: str = "POST",
        body: str = "",
        headers: dict | None = None,
        concurrent: int = 20,
        expect_once: bool = True,
    ) -> dict:
        """HTTP/2 single-packet attack — N stream frames coalesced into one TCP packet.

        Returns VerdictResult (W7 schema).

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
            return error_verdict("concurrent must be >= 2", vuln_type="race_condition")
        concurrent = min(concurrent, 100)

        # Scope check
        scope = await client.check_scope(target_url)
        if "error" in scope:
            return error_verdict(f"scope check failed: {scope['error']}", vuln_type="race_condition")
        if not scope.get("in_scope", False):
            return error_verdict(f"{target_url} not in scope", vuln_type="race_condition")

        parsed = urlparse(target_url)
        if parsed.scheme != "https":
            return error_verdict(
                "HTTP/2 single-packet requires HTTPS; use probe_race_lastbyte for HTTP",
                vuln_type="race_condition",
            )
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

        # Coalesce N stream frames into one TCP packet through Burp (h2 transport).
        try:
            results, buf, stream_ids, flush_ns = await _singlepacket_exchange(
                host, port, requests, read_timeout=15.0
            )
        except Exception as e:
            return error_verdict(
                f"H2 single-packet exchange failed via Burp: {type(e).__name__}: {e}",
                vuln_type="race_condition",
            )

        # Analyse
        lines = [
            f"probe_race_singlepacket {method} {target_url}",
            f"H2 streams: {concurrent} | flush window: {flush_ns / 1_000_000:.3f} ms (single TCP packet)",
            f"Buffer size: {len(buf)} bytes",
            "",
        ]
        statuses, success_count, time_samples, stream_lines = _tally_race(stream_ids, results)
        lines.extend(stream_lines)

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

        human = "\n".join(lines)
        if expect_once and success_count > 1:
            verdict, confidence = "CONFIRMED", 0.9
            ev = f"H2 single-packet race confirmed: {success_count} successes from {concurrent} streams"
        elif success_count == 1:
            verdict, confidence = "FAILED", 0.1
            ev = "single 2xx — race not observed at this concurrency"
        else:
            verdict, confidence = "FAILED", 0.1
            ev = "no 2xx responses — endpoint may not be reachable as configured"

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="race_condition",
            details={
                "target_url": target_url,
                "concurrent": concurrent,
                "success_count": success_count,
                "expect_once": expect_once,
            },
            summary=human,
        )

    @mcp.tool()
    async def probe_race_http3_datagram(
        target_url: str,
        method: str = "POST",
        body: str = "",
        headers: dict | None = None,
        concurrent: int = 100,
        expect_once: bool = True,
        require_h3_advertised: bool = True,
    ) -> dict:
        """HTTP/3 single-datagram race (QUIC-er Races / BH USA 2026 SSRO).

        Returns VerdictResult (W7 schema).

        The QUIC-er race packs N HTTP/3 requests so a single UDP datagram lands
        them simultaneously; N~=100 saturates the origin's QUIC parser. This probe
        (a) verifies the origin runs a QUIC/h3 listener via Alt-Svc, then (b) fires
        the coalesced single-packet race through Burp.

        Distinct from probe_race_singlepacket (plain h2, no h3 precondition) and
        probe_http3_downgrade (forces h3->h2, no race).

        NOTE (ceiling): Burp's proxy tunnel is TCP-only and Burp intercepts HTTP/3
        by downgrading it to HTTP/2, so a true single-UDP-datagram QUIC delivery
        (coalescing N QUIC STREAM frames to saturate the origin's QUIC parser)
        cannot be carried through Burp. The coalesced-packet race here runs over
        the Burp-observable H2 downgrade path against an origin confirmed to speak
        h3. Upgrade path: a QUIC stack (aioquic) emitting direct UDP datagrams --
        that bypasses Burp, violating Rule 26a, so it is intentionally out of scope.

        Args:
            target_url: Full HTTPS URL (QUIC is TLS-only).
            method: HTTP method.
            body: Request body string.
            headers: Extra request headers.
            concurrent: Requests coalesced into the packet (max 100).
            expect_once: Flag if more than one 2xx response = race.
            require_h3_advertised: Require an Alt-Svc h3 advertisement before
                running. Set False to force the race on a known-h3 origin that
                does not advertise.
        """
        if concurrent < 2:
            return error_verdict("concurrent must be >= 2", vuln_type="race_condition")
        concurrent = min(concurrent, 100)

        scope = await client.check_scope(target_url)
        if "error" in scope:
            return error_verdict(f"scope check failed: {scope['error']}", vuln_type="race_condition")
        if not scope.get("in_scope", False):
            return error_verdict(f"{target_url} not in scope", vuln_type="race_condition")

        parsed = urlparse(target_url)
        if parsed.scheme != "https":
            return error_verdict(
                "HTTP/3 datagram race requires HTTPS (QUIC is TLS-only)",
                vuln_type="race_condition",
            )
        host = parsed.hostname or ""
        port = parsed.port or 443
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        # (a) QUIC-listener precondition: Alt-Svc must advertise h3.
        h3_targets = await _detect_h3_advertised(target_url)
        if require_h3_advertised and not h3_targets:
            return make_verdict(
                "FAILED", 0.1,
                "no Alt-Svc h3 advertisement; origin exposes no QUIC/h3 listener",
                vuln_type="race_condition",
                details={"target_url": target_url, "h3_advertised": False},
                summary=(
                    f"probe_race_http3_datagram {method} {target_url}\n"
                    "No Alt-Svc h3=... advertisement -- origin exposes no QUIC listener.\n"
                    "H3 single-datagram race not applicable. Re-run with "
                    "require_h3_advertised=False to force."
                ),
            )

        # (b) Coalesced single-packet race over the Burp-observable H2 path.
        requests = [
            {"method": method, "path": path, "headers": dict(headers or {}), "body": body}
            for _ in range(concurrent)
        ]
        try:
            results, buf, stream_ids, flush_ns = await _singlepacket_exchange(
                host, port, requests, read_timeout=15.0
            )
        except Exception as e:
            return error_verdict(
                f"H3-datagram race exchange failed via Burp: {type(e).__name__}: {e}",
                vuln_type="race_condition",
            )

        statuses, success_count, time_samples, stream_lines = _tally_race(stream_ids, results)
        lines = [
            f"probe_race_http3_datagram {method} {target_url}",
            f"h3 advertised: {h3_targets or 'forced (require_h3_advertised=False)'}",
            f"coalesced requests: {concurrent} | flush window: {flush_ns / 1_000_000:.3f} ms (single packet)",
            "transport: Burp H2 downgrade path (QUIC datagram assembly = ceiling, see tool NOTE)",
            f"Buffer size: {len(buf)} bytes",
            "",
        ]
        lines.extend(stream_lines)
        lines.append("")
        lines.append(f"Status distribution: {dict(statuses)}")
        lines.append(f"Successful (2xx): {success_count}")
        if time_samples:
            t_min = min(time_samples) / 1_000_000
            t_max = max(time_samples) / 1_000_000
            t_avg = sum(time_samples) / len(time_samples) / 1_000_000
            lines.append(f"Response time range: {t_min:.2f} - {t_max:.2f} ms (avg {t_avg:.2f} ms, jitter {t_max - t_min:.2f} ms)")

        if expect_once and success_count > 1:
            lines.append(f"\n*** RACE CONFIRMED: {success_count} successes from {concurrent} coalesced requests ***")
            lines.append("Verify side effect in persistent state (DB rows, balance, ledger).")
            verdict, confidence = "CONFIRMED", 0.9
            ev = f"H3-gated single-packet race: {success_count} successes from {concurrent} coalesced requests"
        elif success_count == 1:
            lines.append("\nSingle 2xx -- race not observed at this concurrency.")
            verdict, confidence = "FAILED", 0.1
            ev = "single 2xx -- race not observed at this concurrency"
        else:
            lines.append("\nNo 2xx responses -- endpoint may not be reachable as configured; check status distribution.")
            verdict, confidence = "FAILED", 0.1
            ev = "no 2xx responses -- endpoint may not be reachable as configured"

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="race_condition",
            details={
                "target_url": target_url,
                "concurrent": concurrent,
                "success_count": success_count,
                "expect_once": expect_once,
                "h3_advertised": h3_targets,
                "transport_note": "ran over Burp H2 downgrade path; true QUIC single-datagram assembly is the ceiling",
            },
            summary="\n".join(lines),
        )
