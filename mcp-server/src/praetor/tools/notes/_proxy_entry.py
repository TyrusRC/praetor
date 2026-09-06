"""Normalize a proxy-history detail entry for the capsule/repro renderers.

`GET /api/proxy/history/{n}` (ProxyHandler.handleDetail) returns flat keys with
headers as a list of {name, value}. The PoC-bundle and repro-script renderers
were written against a richer {headers: dict, body, response: {...}} shape that
no endpoint actually serves. This maps the real shape into the one they expect.
"""

from typing import Any


def _headers_to_dict(headers: Any) -> dict[str, str]:
    """[{name, value}, ...] (handleDetail form) -> {name: value}."""
    out: dict[str, str] = {}
    for h in headers or []:
        if isinstance(h, dict) and "name" in h:
            out[h["name"]] = h.get("value", "")
    return out


def _normalize_entry(detail: dict[str, Any]) -> dict[str, Any]:
    """handleDetail dict -> {method, url, headers, body, response{...}}."""
    return {
        "method": detail.get("method", "GET"),
        "url": detail.get("url", ""),
        "headers": _headers_to_dict(detail.get("request_headers")),
        "body": detail.get("request_body", ""),
        "response": {
            "status": detail.get("status_code"),
            "headers": _headers_to_dict(detail.get("response_headers")),
            "body": detail.get("response_body", ""),
        },
    }
