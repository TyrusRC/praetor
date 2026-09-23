"""Response formatters for the send tools."""

def _send_ref_line(data: dict) -> str | None:
    """Evidence-handle line for a direct send that skipped proxy history.

    A direct send (request smuggling, absolute-target SSRF, pinned HTTP version)
    never enters Burp's proxy history, so it has no proxy_history_index. The
    extension stores it under a `send_ref` ('send-N') that IS citable in
    save_finding via evidence={'send_ref': '...'} — surface it so the agent
    knows the direct send is not evidence-orphaned.
    """
    ref = data.get("send_ref")
    if not ref:
        return None
    return (f"Evidence handle: send_ref={ref} (direct send — not in proxy history; "
            f"cite as evidence={{'send_ref': '{ref}'}})")


def _format_curl_response(data: dict) -> str:
    lines = [f"Status: {data.get('status_code', 'N/A')}"]

    redirects = data.get("redirects_followed", 0)
    if redirects > 0:
        lines.append(f"Redirects followed: {redirects}")
        chain = data.get("redirect_chain", [])
        for hop in chain:
            lines.append(f"  {hop.get('status')} -> {hop.get('location')}")

    lines.append(f"Response Length: {data.get('response_length', 0)} bytes")

    ref_line = _send_ref_line(data)
    if ref_line:
        lines.append(ref_line)

    resp_headers = data.get("response_headers", [])
    if resp_headers:
        lines.append("\n--- Response Headers ---")
        for h in resp_headers:
            lines.append(f"  {h['name']}: {h['value']}")

    body = data.get("response_body", "")
    if body:
        lines.append(f"\n--- Response Body ({len(body)} chars) ---")
        lines.append(_truncate_body(body))

    return "\n".join(lines)


def _format_response(data: dict) -> str:
    lines = [f"Status: {data.get('status_code', 'N/A')}"]
    lines.append(f"Response Length: {data.get('response_length', 0)} bytes")

    ref_line = _send_ref_line(data)
    if ref_line:
        lines.append(ref_line)

    headers = data.get("response_headers", [])
    if headers:
        lines.append("\n--- Response Headers ---")
        for h in headers:
            lines.append(f"  {h['name']}: {h['value']}")

    body = data.get("response_body", "")
    if body:
        lines.append(f"\n--- Response Body ({len(body)} chars) ---")
        lines.append(_truncate_body(body))

    return "\n".join(lines)


def _truncate_body(body: str, max_chars: int = 2000) -> str:
    """Truncate response body to save tokens. Pass max_chars=0 for full body."""
    if max_chars <= 0 or len(body) <= max_chars:
        return body
    return body[:max_chars] + f"\n...[truncated, {len(body)} total chars — use get_request_detail(index, full_body=True) for full body]"
