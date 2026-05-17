"""Low-level HTTP/2 client over a Burp proxy CONNECT tunnel.

Used by probe_race_singlepacket and probe_timeless_timing. Provides:

  - open_h2_tunnel(host, port) -> (ssl_sock, h2.connection.H2Connection)
        TCP -> Burp proxy -> CONNECT host:port -> TLS with ALPN h2 ->
        H2 preface + SETTINGS exchanged.
  - send_streams_singlepacket(conn, sock, requests) -> list[stream_id]
        Build N stream HEADERS+DATA frames, flush to wire in ONE send().
        TCP_NODELAY is enabled so the kernel doesn't fragment.
  - read_until_streams_complete(conn, sock, stream_ids, timeout)
        Loop reading frames until all stream ids end_stream or timeout.

Routes through Burp at 127.0.0.1:8080 (Rule 26a). TLS verification is
disabled because Burp's MITM CA is trusted at the operator level, not the
Python level — we use the proxy to capture traffic, not to validate it.
"""

import socket
import ssl
import time

import h2.connection
import h2.config
import h2.events

from burpsuite_mcp.config import BURP_PROXY_HOST, BURP_PROXY_PORT


def open_h2_tunnel(host: str, port: int) -> tuple[ssl.SSLSocket, h2.connection.H2Connection]:
    """Open one socket -> Burp -> CONNECT to host:port -> TLS h2."""
    sock = socket.create_connection((BURP_PROXY_HOST, BURP_PROXY_PORT), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    # CONNECT tunnel
    sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    sock.settimeout(5)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("Burp CONNECT tunnel closed prematurely")
        buf += chunk
    if not (buf.startswith(b"HTTP/1.1 200") or buf.startswith(b"HTTP/1.0 200")):
        raise RuntimeError(f"Burp proxy refused CONNECT: {buf[:120]!r}")
    # TLS with ALPN h2
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    ssock = ctx.wrap_socket(sock, server_hostname=host)
    ssock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    selected = ssock.selected_alpn_protocol()
    if selected != "h2":
        ssock.close()
        raise RuntimeError(f"Server did not negotiate h2 (got {selected!r}). Target may be HTTP/1.1 only.")

    # H2 preface + initial SETTINGS
    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    )
    conn.initiate_connection()
    ssock.sendall(conn.data_to_send())
    # Read server SETTINGS to be polite (don't strictly need to ack before sending streams)
    ssock.settimeout(3)
    try:
        srv = ssock.recv(8192)
        if srv:
            conn.receive_data(srv)
            ssock.sendall(conn.data_to_send())
    except socket.timeout:
        pass
    return ssock, conn


def build_streams_buffer(
    conn: h2.connection.H2Connection,
    host: str,
    requests: list[dict],
) -> tuple[bytes, list[int]]:
    """Build the on-wire byte buffer for N stream HEADERS+DATA frames.

    Each request is a dict {method, path, headers?, body?}. Returns the
    full byte buffer that should be flushed in ONE send().
    """
    stream_ids = []
    for req in requests:
        method = req.get("method", "GET")
        path = req.get("path", "/")
        body = req.get("body", "")
        if isinstance(body, str):
            body = body.encode("utf-8")
        extra_headers = req.get("headers", {})

        headers_list = [
            (":method", method),
            (":scheme", "https"),
            (":authority", host),
            (":path", path),
        ]
        # Pseudo-headers must come first; regular after
        if body:
            extra_headers.setdefault("content-type", "application/x-www-form-urlencoded")
            extra_headers.setdefault("content-length", str(len(body)))
        for k, v in extra_headers.items():
            headers_list.append((k.lower(), str(v)))

        stream_id = conn.get_next_available_stream_id()
        stream_ids.append(stream_id)
        if body:
            conn.send_headers(stream_id, headers_list, end_stream=False)
            conn.send_data(stream_id, body, end_stream=True)
        else:
            conn.send_headers(stream_id, headers_list, end_stream=True)

    return conn.data_to_send(), stream_ids


def send_singlepacket(ssock: ssl.SSLSocket, buf: bytes) -> int:
    """Flush the whole buffer in one sendall — returns ns elapsed."""
    start = time.perf_counter_ns()
    ssock.sendall(buf)
    return time.perf_counter_ns() - start


def read_until_complete(
    ssock: ssl.SSLSocket,
    conn: h2.connection.H2Connection,
    stream_ids: list[int],
    overall_timeout_s: float = 10.0,
) -> dict[int, dict]:
    """Loop reading frames; return per-stream {status, length, body_preview, time_ns}.

    time_ns is wall-clock from now until first END_STREAM event for that stream.
    """
    pending = set(stream_ids)
    results: dict[int, dict] = {sid: {
        "status": 0, "length": 0, "body_preview": "",
        "time_ns": 0, "headers": [],
    } for sid in stream_ids}
    bodies: dict[int, bytearray] = {sid: bytearray() for sid in stream_ids}
    start_ns = time.perf_counter_ns()
    deadline = time.time() + overall_timeout_s
    ssock.settimeout(2.0)
    while pending and time.time() < deadline:
        try:
            data = ssock.recv(65536)
        except socket.timeout:
            continue
        except (ssl.SSLError, OSError):
            break
        if not data:
            break
        try:
            events = conn.receive_data(data)
        except Exception:
            break
        for ev in events:
            if isinstance(ev, h2.events.ResponseReceived):
                sid = ev.stream_id
                if sid in results:
                    results[sid]["headers"] = list(ev.headers)
                    for k, v in ev.headers:
                        kn = k.decode() if isinstance(k, bytes) else k
                        vn = v.decode() if isinstance(v, bytes) else v
                        if kn == ":status":
                            try:
                                results[sid]["status"] = int(vn)
                            except ValueError:
                                pass
            elif isinstance(ev, h2.events.DataReceived):
                sid = ev.stream_id
                if sid in bodies:
                    bodies[sid].extend(ev.data)
                    if ev.flow_controlled_length:
                        conn.acknowledge_received_data(ev.flow_controlled_length, sid)
            elif isinstance(ev, h2.events.StreamEnded):
                sid = ev.stream_id
                if sid in pending:
                    pending.discard(sid)
                    results[sid]["time_ns"] = time.perf_counter_ns() - start_ns
                    results[sid]["length"] = len(bodies[sid])
                    results[sid]["body_preview"] = bodies[sid][:200].decode("utf-8", errors="replace")
            elif isinstance(ev, h2.events.StreamReset):
                sid = ev.stream_id
                if sid in pending:
                    pending.discard(sid)
                    results[sid]["time_ns"] = time.perf_counter_ns() - start_ns
                    results[sid]["status"] = results[sid]["status"] or -1
        # Send any outgoing flow-control updates
        out = conn.data_to_send()
        if out:
            ssock.sendall(out)
    # For streams still pending at timeout, record timeout marker
    for sid in pending:
        results[sid]["time_ns"] = -1
    return results
