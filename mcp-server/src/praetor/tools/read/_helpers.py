"""Shared helpers + constants for the read tools."""

import re
from urllib.parse import urlsplit, parse_qsl


from praetor import client
from praetor.processing.formatters import format_proxy_table, format_findings


_REDIRECT_STATUSES = {301, 302, 303, 307, 308}

_DETAIL_FIELDS = frozenset({
    "method", "url", "host", "path", "query_params",
    "status_code", "mime_type", "content_type", "response_length",
    "request_headers", "response_headers",
    "request_body", "response_body",
    "has_form", "has_redirect", "location_header", "set_cookie",
    "error_markers",
})

_DETAIL_MARKER_RE = (
    ("sqli", re.compile(r"(you have an error in your sql syntax|pg_query|SQLSTATE\[|ORA-\d{5}|unclosed quotation|psycopg2|MySQLSyntaxError)", re.I)),
    ("ssti", re.compile(r"(jinja2\.exceptions|TemplateSyntaxError|freemarker\.core|velocity\.exception|twig\.error)", re.I)),
    ("rce",  re.compile(r"(uid=\d+\(.+?\)\s+gid=\d+|(?:root|nobody|www-data|apache).+?(?:bash|sh|nologin))")),
    ("stack_trace", re.compile(r"(Traceback \(most recent call last\)|at\s+[\w.$]+\.[\w$]+\([\w.]+\.java:\d+\)|Whitelabel Error Page|ServletException|NoMethodError|NameError|ReferenceError)")),
)


def _header_lookup(headers: list, name: str) -> str | None:
    """First-match header lookup, case-insensitive. Supports list-of-dict and list-of-[k,v]."""
    if not headers:
        return None
    target = name.lower()
    for h in headers:
        if isinstance(h, dict):
            k = h.get("name", "")
            if k.lower() == target:
                return h.get("value")
        elif isinstance(h, (list, tuple)) and len(h) >= 2:
            if str(h[0]).lower() == target:
                return str(h[1])
    return None


def _set_cookie_values(headers: list) -> list:
    """All Set-Cookie header values."""
    if not headers:
        return []
    out = []
    for h in headers:
        if isinstance(h, dict) and h.get("name", "").lower() == "set-cookie":
            out.append(h.get("value", ""))
        elif isinstance(h, (list, tuple)) and len(h) >= 2 and str(h[0]).lower() == "set-cookie":
            out.append(str(h[1]))
    return out


def _trim_body(body: str, body_first: int, body_last: int) -> str:
    """Slice body to head+tail; signal truncation when both are non-zero and body exceeds head+tail."""
    if not body:
        return ""
    total = len(body)
    if body_first <= 0 and body_last <= 0:
        return ""
    head = body[: body_first] if body_first > 0 else ""
    tail = body[-body_last:] if body_last > 0 else ""
    cut = body_first + body_last
    if cut >= total:
        return body
    return f"{head}\n…[TRUNCATED {total - cut} of {total} chars]…\n{tail}" if tail else head + f"\n…[TRUNCATED {total - body_first} of {total} chars]"


def _detect_error_markers(body: str) -> list[str]:
    """Return marker labels found in body. Cheap regex sweep, capped at 2k tail to bound cost."""
    if not body:
        return []
    sample = body[:8192]
    hits = []
    for label, rx in _DETAIL_MARKER_RE:
        if rx.search(sample):
            hits.append(label)
    return hits


def _slice_request_detail(
    data: dict, fields: list[str], body_first: int, body_last: int
) -> dict:
    """Return a dict containing only the requested fields. Unknown fields are skipped silently."""
    requested = [f for f in fields if f in _DETAIL_FIELDS]
    if not requested:
        return {"error": "no recognised fields", "allowed": sorted(_DETAIL_FIELDS)}

    url = data.get("url", "") or ""
    parsed = urlsplit(url) if url else None
    resp_headers = data.get("response_headers", []) or []
    req_headers = data.get("request_headers", []) or []
    resp_body = data.get("response_body", "") or ""
    status = data.get("status_code")

    out: dict = {}
    for f in requested:
        if f == "method":            out[f] = data.get("method")
        elif f == "url":             out[f] = url
        elif f == "status_code":     out[f] = status
        elif f == "mime_type":       out[f] = data.get("mime_type")
        elif f == "response_length": out[f] = data.get("response_length")
        elif f == "host":            out[f] = parsed.netloc if parsed else None
        elif f == "path":            out[f] = parsed.path if parsed else None
        elif f == "query_params":    out[f] = dict(parse_qsl(parsed.query)) if parsed and parsed.query else {}
        elif f == "request_headers":  out[f] = req_headers
        elif f == "response_headers": out[f] = resp_headers
        elif f == "request_body":  out[f] = _trim_body(data.get("request_body", "") or "", body_first, body_last)
        elif f == "response_body": out[f] = _trim_body(resp_body, body_first, body_last)
        elif f == "content_type":  out[f] = _header_lookup(resp_headers, "Content-Type")
        elif f == "location_header": out[f] = _header_lookup(resp_headers, "Location")
        elif f == "set_cookie":    out[f] = _set_cookie_values(resp_headers)
        elif f == "has_form":      out[f] = bool(resp_body and "<form" in resp_body.lower())
        elif f == "has_redirect":  out[f] = status in _REDIRECT_STATUSES
        elif f == "error_markers": out[f] = _detect_error_markers(resp_body)

    return out


def _format_raw_findings(data: dict) -> str:
    """Format all findings without filtering — for explicit INFORMATION requests."""
    items = data.get("items", [])
    total = data.get("total_findings", 0)
    if not items:
        return "No scanner findings."
    lines = [f"Scanner Findings — UNFILTERED ({len(items)}/{total}):\n"]
    for f in items:
        lines.append(f"  [{f.get('severity', '?')}/{f.get('confidence', '?')}] {f.get('name', '?')}")
        lines.append(f"    {f.get('base_url', '')}")
    return "\n".join(lines)
