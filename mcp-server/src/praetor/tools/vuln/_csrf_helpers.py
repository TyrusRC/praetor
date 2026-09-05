"""CSRF token-discovery + SameSite parsing helpers for test_csrf."""

from __future__ import annotations

import re


_TOKEN_HEADER_NAMES = (
    "x-csrf-token", "x-xsrf-token", "csrf-token", "csrftoken",
    "x-csrftoken", "x-requested-with", "anti-csrf-token", "x-anti-forgery",
)


_TOKEN_BODY_PARAMS = (
    "csrf_token", "csrf", "_token", "_csrf", "authenticity_token",
    "anti_forgery_token", "xsrf_token", "csrfmiddlewaretoken",
    "__requestverificationtoken",
)


def _find_token_in_request(headers: dict[str, str], body: str) -> tuple[str, str]:
    """Return (location, value) for any CSRF-token-like field in the request.
    location is one of: header / body / cookie / none."""
    # Headers
    for h, v in (headers or {}).items():
        if h.lower() in _TOKEN_HEADER_NAMES:
            return ("header:" + h, str(v))
    # Body — search common form/json shapes.
    if body:
        for p in _TOKEN_BODY_PARAMS:
            m = re.search(rf'[\?&]{p}=([^&]+)', body, re.IGNORECASE)
            if m:
                return ("body:" + p, m.group(1))
            m2 = re.search(rf'"{p}"\s*:\s*"([^"]+)"', body, re.IGNORECASE)
            if m2:
                return ("body:" + p, m2.group(1))
    # Cookie (double-submit pattern)
    cookie = (headers or {}).get("Cookie", "") or (headers or {}).get("cookie", "")
    for p in ("csrf_token", "xsrf-token", "csrftoken", "_csrf"):
        m = re.search(rf'(^|;\s*){p}=([^;]+)', cookie, re.IGNORECASE)
        if m:
            return ("cookie:" + p, m.group(2))
    return ("none", "")


def _samesite_status(set_cookie_lines: list[str]) -> tuple[str, str]:
    """Parse Set-Cookie for SameSite attribute on the auth/session cookie.
    Returns (verdict, detail)."""
    if not set_cookie_lines:
        return ("absent", "no Set-Cookie issued in response (test the cookie-issuing endpoint instead)")
    for line in set_cookie_lines:
        low = line.lower()
        if not any(k in low for k in ("session", "auth", "token", "sid", "jsessionid")):
            continue
        if "samesite=strict" in low:
            return ("strict", line.split(";", 1)[0])
        if "samesite=lax" in low:
            return ("lax", line.split(";", 1)[0])
        if "samesite=none" in low:
            if "secure" in low:
                return ("none-secure", line.split(";", 1)[0])
            return ("none-insecure",
                    "SameSite=None set without Secure flag — browser rejects")
        return ("missing-attribute", line.split(";", 1)[0])
    return ("no-session-cookie", "no auth/session cookie in response")

