"""Shared helpers for testing_extended submodules.

Helpers used by 2+ submodules. Tool-specific constants live in their own files.
"""

import time
import urllib.parse

from burpsuite_mcp import client


async def confirm_timing_anomaly(
    raw_request: str,
    host: str,
    port: int,
    is_https: bool,
    threshold_ms: int,
    attempts: int = 2,
) -> int:
    """Re-send a raw request `attempts` times; return how many exceeded threshold_ms.

    Rule 11: timing findings need 3+ iterations. The caller has already observed
    one anomaly, so a return of ``attempts`` means 1+attempts confirmed hits.
    """
    confirmed = 0
    for _ in range(attempts):
        start = time.time()
        resp = await client.post("/api/http/raw", json={
            "raw": raw_request, "host": host, "port": port, "https": is_https,
        })
        elapsed = int((time.time() - start) * 1000)
        timed_out = "error" in resp and "timeout" in resp["error"].lower()
        if timed_out or elapsed > threshold_ms:
            confirmed += 1
    return confirmed


async def resolve_host_from(target_url: str, session: str = "") -> tuple[str, int, bool, str]:
    """Resolve (host, port, https, error) for raw-request probes.

    Order:
      1. parse target_url — if hostname present, use it.
      2. else fall back to session's last request via the extension.
      3. else return error.
    """
    if target_url:
        parsed = urllib.parse.urlparse(target_url)
        if parsed.hostname:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            return (parsed.hostname, port, parsed.scheme == "https", "")

    if session:
        info = await client.get_session_last_host(session)
        if "error" not in info:
            return (info["host"], int(info.get("port", 443)),
                    bool(info.get("https", True)), "")

    return ("", 0, False, "target_url required (no parseable hostname; no active session with prior requests)")


async def scope_or_error(host: str, https: bool, port: int) -> str:
    """Returns empty string if in scope, else an Error: ... message."""
    scheme = "https" if https else "http"
    if (https and port == 443) or (not https and port == 80):
        url = f"{scheme}://{host}/"
    else:
        url = f"{scheme}://{host}:{port}/"
    res = await client.check_scope(url)
    if "error" in res:
        return f"Error: scope check failed for {host}: {res['error']}"
    if not res.get("in_scope", False):
        return f"Error: {host} not in scope"
    return ""


def fmt_val(value) -> str:
    """Format a test value for display."""
    s = repr(value)
    if len(s) > 30:
        return s[:27] + "..."
    return s
