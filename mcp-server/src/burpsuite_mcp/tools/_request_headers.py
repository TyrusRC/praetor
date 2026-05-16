"""Realistic-header injection for fresh HTTP requests.

Why: httpx / curl / Burp's Montoya HTTP client ship NO User-Agent by default.
Requests look obviously synthetic — WAFs (Cloudflare, Akamai, AWS WAF, F5,
Imperva) fingerprint the missing UA / missing sec-ch-ua / missing Accept and
serve a 403 challenge page or a 200 stub. The hunt dies before it starts.

Strategy (Rule 25 — realistic mode by default):
  1. Caller-supplied headers always win (operator knows what they're doing).
  2. Profile headers (.burp-intel/<domain>/profile.json -> realistic_headers)
     fill the rest — same UA + cookies + Accept-Language the real browser used.
  3. Default Chrome fingerprint fills any remaining gaps so a target without a
     saved profile still gets a realistic-looking request.

Opt-out: pass bare=True when intentionally testing the server's reaction to a
bare / malformed / fingerprintable client (WAF detection, header injection,
smuggling, CRLF) — Rule 25 explicitly carves this out as the bare mode.
"""

import json
from urllib.parse import urlparse

from .intel._internals import _intel_path


_DEFAULT_BROWSER_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Ch-Ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Linux"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}


# Profile headers we never copy to a fresh request — they're shape-specific
# and would break the new request or leak the wrong context.
_PROFILE_BLOCKLIST = frozenset({
    "host",
    "content-length",
    "content-type",
    "content-encoding",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "expect",
    "te",
    "trailer",
    "upgrade",
    "proxy-connection",
    "proxy-authorization",
})


def _domain_from_url(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except (ValueError, TypeError):
        return ""


def _load_realistic_headers(domain: str) -> dict:
    if not domain:
        return {}
    try:
        path = _intel_path(domain) / "profile.json"
    except ValueError:
        return {}
    if not path.exists():
        return {}
    try:
        profile = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    return profile.get("realistic_headers") or {}


def apply_realistic_headers(
    url: str,
    headers: dict | None,
    bare: bool = False,
    unsafe_headers: bool = False,
) -> dict:
    """Return merged headers with browser fingerprint injected.

    Precedence (highest first):
      1. Caller-supplied headers (always win).
      2. Saved profile headers from .burp-intel/<domain>/profile.json.
      3. Default Chrome 131 fingerprint.

    Stripped from profile by default: Host, Content-Length, Content-Type,
    Transfer-Encoding, Connection, and other shape-specific headers (see
    _PROFILE_BLOCKLIST). Pass unsafe_headers=True to disable that strip and
    let profile's wire-shape headers flow through — required for HTTP request
    smuggling (TE.CL / CL.TE / TE.0 / CL.0), host-header injection, HTTP
    parameter pollution, and CRLF tests. Caller-supplied headers always win
    regardless.
    """
    caller = dict(headers or {})
    if bare:
        return caller

    caller_lc = {k.lower() for k in caller}
    merged: dict = {}

    for k, v in _DEFAULT_BROWSER_HEADERS.items():
        if k.lower() not in caller_lc:
            merged[k] = v

    domain = _domain_from_url(url)
    profile = _load_realistic_headers(domain)
    for k, v in profile.items():
        k_lc = k.lower()
        if not unsafe_headers and k_lc in _PROFILE_BLOCKLIST:
            continue
        if k_lc in caller_lc:
            continue
        merged[k] = v

    merged.update(caller)
    return merged
