"""CSP parsing + risky-CDN/token detection helpers for analyze_csp."""

from __future__ import annotations


_RISKY_CDNS = {
    "*.jsdelivr.net": "JSONP via /npm/*; arbitrary npm package fetch",
    "cdn.jsdelivr.net": "JSONP via /npm/*; arbitrary npm package fetch",
    "unpkg.com": "Arbitrary npm package CDN fetch",
    "ajax.googleapis.com": "AngularJS JSONP gadget (1.x)",
    "www.googletagmanager.com": "GTM custom-tag JS injection if attacker has GTM access",
    "googletagmanager.com": "GTM custom-tag JS injection if attacker has GTM access",
    "*.facebook.net": "FB SDK has had JSONP-like endpoints",
    "cdn.ampproject.org": "AMP scripts have eval-like behaviour",
    "ajax.aspnetcdn.com": "JSONP via older jQuery versions",
    "*.cdn.shopify.com": "User-uploadable assets",
    "code.jquery.com": "Older jQuery loads have JSONP gadgets",
    "stackpath.bootstrapcdn.com": "Older bootstrap gadgets",
    "maxcdn.bootstrapcdn.com": "Older bootstrap gadgets",
    "*.cloudfront.net": "Anyone can host on CloudFront",
    "*.amazonaws.com": "S3 bucket misconfig → JS upload",
    "*.azureedge.net": "Azure CDN — any tenant",
    "storage.googleapis.com": "GCS bucket misconfig → JS upload",
}


# Required directives — absence of these means relevant policy gaps
_REQUIRED_DIRECTIVES = ("default-src", "script-src", "object-src", "base-uri")


def _parse_csp(csp: str) -> dict[str, list[str]]:
    """Parse a CSP string into {directive: [source1, source2, ...]}."""
    out: dict[str, list[str]] = {}
    if not csp:
        return out
    for clause in csp.split(";"):
        clause = clause.strip()
        if not clause:
            continue
        parts = clause.split()
        directive = parts[0].lower()
        sources = parts[1:] if len(parts) > 1 else []
        out[directive] = sources
    return out


def _effective_script_src(parsed: dict[str, list[str]]) -> list[str]:
    """Return the effective script-src list (fallback to default-src)."""
    if "script-src" in parsed:
        return parsed["script-src"]
    if "default-src" in parsed:
        return parsed["default-src"]
    return []


def _detect_risky_cdns(sources: list[str]) -> list[tuple[str, str]]:
    """Return (cdn_host, reason) for each risky CDN allowlist entry."""
    hits = []
    for src in sources:
        src_lower = src.lower().strip("'\"")
        # Strip scheme prefix
        for prefix in ("https://", "http://", "//"):
            if src_lower.startswith(prefix):
                src_lower = src_lower[len(prefix):]
                break
        # Strip path
        src_lower = src_lower.split("/")[0]
        for risky, reason in _RISKY_CDNS.items():
            if risky == src_lower or (
                risky.startswith("*.") and src_lower.endswith(risky[1:])
            ):
                hits.append((src_lower, reason))
                break
    return hits


def _has_token(sources: list[str], token: str) -> bool:
    return any(s.lower().strip("'\"") == token.lstrip("'").rstrip("'")
               for s in sources)


def _has_nonce_or_hash(sources: list[str]) -> bool:
    return any(s.lower().startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
               for s in sources)


