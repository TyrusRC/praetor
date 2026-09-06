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

from mcp.server.fastmcp import FastMCP

# Alt-Svc h3 advertisement: `h3=":443"; ma=86400` or draft `h3-29="..."`.

from ._race_helpers import (  # noqa: F401 (re-export for tests/callers)
    _singlepacket_exchange,
    _tally_race,
    _detect_h3_advertised,
    _ALT_SVC_H3_RE,
)
from ._race_singlepacket_impl import (
    _run_probe_race_singlepacket,
    _run_probe_race_http3_datagram,
)


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
        return await _run_probe_race_singlepacket(
            target_url,
            method=method,
            body=body,
            headers=headers,
            concurrent=concurrent,
            expect_once=expect_once,
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
        return await _run_probe_race_http3_datagram(
            target_url,
            method=method,
            body=body,
            headers=headers,
            concurrent=concurrent,
            expect_once=expect_once,
            require_h3_advertised=require_h3_advertised,
        )
