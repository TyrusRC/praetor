"""probe_race_lastbyte — HTTP/1.1 last-byte synchronisation via raw sockets through Burp.

Turbo-Intruder-style race window minimisation. For each of N concurrent
requests:

  1. Open a TCP connection through Burp's proxy (CONNECT tunnel for HTTPS).
  2. Send headers + body[:-1] — the last byte is withheld.
  3. After all N sockets are primed at the "one byte from done" state, flush
     the final byte across every socket in a tight loop (under 1 ms total).

This minimises the network-jitter component of the race window. Pure socket
implementation — no extra deps. Routes through Burp at 127.0.0.1:8080 so every
request is captured (Rule 26a).
"""

import asyncio
import socket
import ssl
import time
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.config import BURP_PROXY_HOST, BURP_PROXY_PORT


def _build_request_bytes(method: str, path: str, host: str, headers: dict, body: bytes) -> bytes:
    """Build the raw HTTP/1.1 request bytes."""
    hdrs = {
        "Host": host,
        "User-Agent": "Mozilla/5.0 swk-lastbyte/1.0",
        "Accept": "*/*",
        "Connection": "close",
    }
    if body:
        hdrs.setdefault("Content-Length", str(len(body)))
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    for k, v in headers.items():
        hdrs[k] = v
    # Caller may have provided Content-Length explicitly — trust that.
    request_line = f"{method} {path} HTTP/1.1\r\n"
    header_block = "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
    head = (request_line + header_block + "\r\n").encode()
    return head + body


def _open_burp_tunnel(host: str, port: int, is_https: bool) -> socket.socket:
    """Open a socket to Burp; for HTTPS, CONNECT through to target with TLS."""
    sock = socket.create_connection((BURP_PROXY_HOST, BURP_PROXY_PORT), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if is_https:
        # CONNECT tunnel
        connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode()
        sock.sendall(connect_req)
        resp = b""
        sock.settimeout(5)
        while b"\r\n\r\n" not in resp:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
        if not resp.startswith(b"HTTP/1.1 200") and not resp.startswith(b"HTTP/1.0 200"):
            sock.close()
            raise RuntimeError(f"Burp proxy CONNECT refused: {resp[:120]!r}")
        # Upgrade to TLS over the tunnel
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        ssock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return ssock
    else:
        # Plain HTTP: route via proxy's absolute-URL form (Burp accepts)
        # but here we still treat it as direct since CONNECT is for HTTPS
        return sock


async def _prime_one(sock: socket.socket, req_bytes: bytes) -> tuple[socket.socket, bytes]:
    """Send everything except the final byte; return socket + the held byte."""
    head = req_bytes[:-1]
    tail = req_bytes[-1:]
    loop = asyncio.get_running_loop()
    await loop.sock_sendall(sock, head)
    return sock, tail


def _read_response(sock: socket.socket, timeout: float = 5.0) -> tuple[int, int, bytes]:
    """Read response, return (status, length, preview)."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break
    except (socket.timeout, ssl.SSLError, OSError):
        pass
    # Parse status
    status = 0
    if buf.startswith(b"HTTP/"):
        try:
            status_line = buf.split(b"\r\n", 1)[0]
            status = int(status_line.split()[1])
        except (IndexError, ValueError):
            status = 0
    # Find body start
    body_start = buf.find(b"\r\n\r\n")
    body = buf[body_start + 4:] if body_start >= 0 else b""
    return status, len(buf), body[:200]


def register(mcp: FastMCP):

    @mcp.tool()
    async def probe_race_lastbyte(
        target_url: str,
        method: str = "POST",
        body: str = "",
        headers: dict | None = None,
        concurrent: int = 20,
        warmup_ms: int = 50,
    ) -> str:
        """HTTP/1.1 last-byte synchronisation race attack via raw sockets through Burp.

        N TCP connections opened in parallel, each receives request bytes minus the
        final byte. Final bytes flushed across all sockets in a tight loop to minimise
        the race window. Pure socket implementation — every request goes through
        127.0.0.1:8080 (Burp proxy) for Rule 26a compliance.

        Args:
            target_url: Full URL (http or https).
            method: HTTP method.
            body: Request body (raw string; will be encoded UTF-8).
            headers: Extra headers.
            concurrent: Number of parallel sockets (max 50).
            warmup_ms: How long to wait between priming all sockets and the final-byte burst.
        """
        if concurrent < 2:
            return "Error: concurrent must be ≥ 2"
        concurrent = min(concurrent, 50)

        # Scope check
        scope = await client.check_scope(target_url)
        if "error" in scope:
            return f"Error: scope check failed: {scope['error']}"
        if not scope.get("in_scope", False):
            return f"Error: {target_url} not in scope"

        parsed = urlparse(target_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        is_https = parsed.scheme == "https"
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        body_bytes = body.encode("utf-8") if body else b""
        req_bytes = _build_request_bytes(method, path, host, headers or {}, body_bytes)
        if len(req_bytes) < 2:
            return "Error: request must be at least 2 bytes to withhold a final byte"

        # ── Prime sockets ──
        loop = asyncio.get_running_loop()
        primed: list[tuple[socket.socket, bytes]] = []
        try:
            for i in range(concurrent):
                try:
                    sock = await asyncio.to_thread(_open_burp_tunnel, host, port, is_https)
                    sock.setblocking(False)
                    primed.append(await _prime_one(sock, req_bytes))
                except Exception as e:
                    return f"Error: failed to prime socket #{i}: {type(e).__name__}: {e}"

            # ── Brief warmup ──
            if warmup_ms > 0:
                await asyncio.sleep(warmup_ms / 1000.0)

            # ── Burst the final byte across all sockets ──
            start = time.perf_counter_ns()
            tasks = [loop.sock_sendall(s, tail) for s, tail in primed]
            await asyncio.gather(*tasks, return_exceptions=True)
            burst_ns = time.perf_counter_ns() - start

            # ── Read responses ──
            results = await asyncio.gather(
                *[asyncio.to_thread(_read_response, s, 5.0) for s, _ in primed],
                return_exceptions=True,
            )
        finally:
            for s, _ in primed:
                try:
                    s.close()
                except Exception:
                    pass

        # Analyse
        lines = [
            f"probe_race_lastbyte {method} {target_url}",
            f"sockets={concurrent} via Burp proxy {BURP_PROXY_HOST}:{BURP_PROXY_PORT}",
            f"Final-byte burst window: {burst_ns / 1_000_000:.3f} ms",
            "",
        ]
        statuses: dict[int, int] = {}
        success_count = 0
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                lines.append(f"  #{i}: exception — {type(r).__name__}: {r}")
                continue
            status, total_len, preview = r
            statuses[status] = statuses.get(status, 0) + 1
            if 200 <= status < 300:
                success_count += 1
            preview_str = preview.decode("utf-8", errors="replace")[:80]
            lines.append(f"  #{i}: status={status} bytes={total_len} preview={preview_str!r}")
        lines.append("")
        lines.append(f"Status distribution: {dict(statuses)}")
        lines.append(f"Successful (2xx): {success_count}")
        if success_count > 1:
            lines.append("\n*** RACE: more than one 2xx — potential limit-overrun / TOCTOU. Verify side effect in persistent state. ***")
        elif success_count == 1:
            lines.append("\nSingle 2xx — race not observed at this concurrency. Try increasing concurrent or run probe_race_singlepacket (HTTP/2).")
        return "\n".join(lines)
