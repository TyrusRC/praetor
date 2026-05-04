"""Header-profile scoring helpers for build_target_header_profile.

A "header profile" is a clean dict of headers captured from real client
traffic to the target, suitable for replay via curl_request /
session_request / send_raw_request. The goal: when a fresh request is
genuinely needed (no captured equivalent), the curl call mimics the real
browser/client so WAFs don't trip on default httpx/curl signatures.
"""

# Headers that must NEVER be reused from a captured request — they're either
# session-specific (Cookie), auto-derived by the HTTP client (Host,
# Content-Length, Connection, Transfer-Encoding), or sensitive (Authorization
# without explicit opt-in).
_HEADER_PROFILE_DROP = {
    "host", "content-length", "connection", "transfer-encoding",
    "te", "upgrade", "proxy-connection", "proxy-authenticate",
    "expect", "trailer", "x-forwarded-for", "x-forwarded-host",
    "x-forwarded-proto", "x-real-ip", "cf-connecting-ip",
}

# Browser-fingerprint indicator headers — presence of these means the source
# request looks like a real browser, not a bot/scanner. Score higher.
_BROWSER_FINGERPRINT_HEADERS = {
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "upgrade-insecure-requests", "accept-language", "accept-encoding",
}

# User-Agent substrings that indicate a real browser worth mimicking.
_REAL_BROWSER_UA_HINTS = ("mozilla", "chrome", "safari", "firefox", "edg/", "webkit")
# User-Agent substrings that indicate scanners/bots/curl — avoid as profile sources.
_BOT_UA_HINTS = ("nuclei", "ffuf", "sqlmap", "gobuster", "dirb", "wfuzz",
                 "scrapy", "python-httpx", "python-requests", "curl/",
                 "java-http-client", "okhttp/4.0", "go-http-client",
                 "burp", "katana", "wappalyzer", "nmap", "masscan")


def score_header_set(headers: list[dict]) -> int:
    """Return a "browser-likeness" score for a header list. Higher = more
    realistic. Used to pick the best source request for a header profile.
    """
    score = 0
    by_name = {h.get("name", "").lower(): h.get("value", "") for h in headers}
    ua = by_name.get("user-agent", "").lower()
    if any(hint in ua for hint in _REAL_BROWSER_UA_HINTS):
        score += 50
    if any(bot in ua for bot in _BOT_UA_HINTS):
        score -= 100
    score += sum(5 for h in _BROWSER_FINGERPRINT_HEADERS if h in by_name)
    if "accept" in by_name and "html" in by_name["accept"].lower():
        score += 10
    if "referer" in by_name and by_name["referer"]:
        score += 5
    if "cookie" in by_name and by_name["cookie"]:
        score += 3  # logged-in real session — rare but valuable signal
    score += min(20, len(by_name))  # general richness, capped
    return score


def normalize_headers(headers_list: list[dict]) -> dict[str, str]:
    """Convert a [{name, value}, ...] list into a clean dict suitable for
    curl_request / session_request, with session-specific and auto-derived
    headers removed.
    """
    out: dict[str, str] = {}
    seen = set()
    for h in headers_list:
        name = (h.get("name") or "").strip()
        value = h.get("value") or ""
        if not name:
            continue
        low = name.lower()
        if low in _HEADER_PROFILE_DROP:
            continue
        if low == "cookie":
            # Strip session cookies — session_request manages the cookie jar.
            continue
        if low == "authorization":
            # Don't blindly carry an auth header into fresh requests —
            # caller must opt in via session.
            continue
        if low in seen:
            continue
        seen.add(low)
        out[name] = value
    return out
