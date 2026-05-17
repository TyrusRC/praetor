"""harvest_identifiers — pull IDs / emails / usernames out of captured traffic for IDOR pivots.

Strix's pivot-harvest pattern: before IDOR / auth-matrix testing, sweep all
captured responses for usable identifiers — integer IDs, UUIDs (v1/v4),
ULIDs, Snowflakes, emails, usernames, account numbers, internal slugs.

Distinct from `extract_js_secrets` (which is per-index, API-key-focused) and
`extract_regex` (which is operator-specified one-off pattern).
"""

import re

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


_RE_EMAIL = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", re.U)
_RE_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-7][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
_RE_ULID = re.compile(r"\b[0-9A-HJKMNP-TV-Z]{26}\b")
_RE_SNOWFLAKE = re.compile(r"\"(id|user_id|account_id|order_id)\"\s*:\s*\"?([0-9]{15,20})\"?")
_RE_NUMERIC_ID = re.compile(r"\"(id|user_id|account_id|order_id|customer_id|tenant_id|org_id|profile_id)\"\s*:\s*\"?(\d{1,12})\"?")
_RE_USERNAME = re.compile(r"\"(username|user_name|handle|login|nickname)\"\s*:\s*\"([^\"<>\\]{2,64})\"")
_RE_SLUG = re.compile(r"\"(slug|permalink|path_alias)\"\s*:\s*\"([a-z0-9][a-z0-9_-]{2,64})\"")
_RE_PHONE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
_RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_RE_HEX_TOKEN = re.compile(r"\b[a-f0-9]{32,128}\b")  # API keys / session tokens / hashes


_BORING_DOMAINS = {
    "example.com", "example.org", "example.net",
    "test.com", "test.org",
    "google.com", "googleapis.com", "google-analytics.com",
    "facebook.com", "twitter.com",
    "amazonaws.com", "cloudfront.net",
    "w3.org", "schema.org",
    "github.com", "gitlab.com",
    "localhost", "localhost.com",
}


def _looks_boring(email: str) -> bool:
    parts = email.split("@", 1)
    if len(parts) != 2:
        return True
    domain = parts[1].lower()
    return domain in _BORING_DOMAINS or domain.endswith(".local") or domain.endswith(".internal")


def _emit_chunk(text: str, out: dict[str, set]):
    for m in _RE_EMAIL.findall(text):
        if not _looks_boring(m):
            out["emails"].add(m)
    for m in _RE_UUID.findall(text):
        out["uuids"].add(m)
    for m in _RE_ULID.findall(text):
        out["ulids"].add(m)
    for m in _RE_JWT.findall(text):
        out["jwts"].add(m)
    for fkey, val in _RE_SNOWFLAKE.findall(text):
        out["snowflakes"].add(f"{fkey}={val}")
    for fkey, val in _RE_NUMERIC_ID.findall(text):
        out["numeric_ids"].add(f"{fkey}={val}")
    for fkey, val in _RE_USERNAME.findall(text):
        out["usernames"].add(f"{fkey}={val}")
    for fkey, val in _RE_SLUG.findall(text):
        out["slugs"].add(f"{fkey}={val}")
    for m in _RE_PHONE.findall(text):
        out["phones"].add(m)
    # Hex tokens are noisy — only keep ones that look strong (≥40 chars, mixed positions)
    for m in _RE_HEX_TOKEN.findall(text):
        if len(m) >= 40:
            out["hex_tokens"].add(m[:48])


def register(mcp: FastMCP):

    @mcp.tool()
    async def harvest_identifiers(
        scan_proxy: bool = True,
        scan_sitemap: bool = False,
        extra_urls: list[str] | None = None,
        max_per_category: int = 100,
        url_prefix: str = "",
    ) -> str:
        """Harvest IDs / emails / usernames / tokens from captured traffic for IDOR pivots.

        Args:
            scan_proxy: Scan proxy history (default true).
            scan_sitemap: Also scan the static sitemap export (slower, more breadth).
            extra_urls: Optional list of well-known docs to also fetch & scan (e.g. /robots.txt,
                /sitemap.xml, /humans.txt, /security.txt, /.well-known/security.txt).
            max_per_category: Cap per identifier category in the report.
            url_prefix: Restrict proxy scan to URLs matching this prefix.

        Reports unique identifiers grouped by category. The output is intended
        as pivot input for `probe_id_monotonic`, `test_auth_matrix`,
        `probe_cross_transport_idor`, etc.
        """
        bins = {
            "emails": set(), "uuids": set(), "ulids": set(),
            "snowflakes": set(), "numeric_ids": set(), "usernames": set(),
            "slugs": set(), "phones": set(), "jwts": set(), "hex_tokens": set(),
        }

        scanned = 0
        if scan_proxy:
            params = {"limit": 500}
            if url_prefix:
                params["url_prefix"] = url_prefix
            history = await client.get("/api/proxy-history", params=params)
            if "error" in history:
                return f"Error reading proxy history: {history['error']}"
            for item in history.get("history", history.get("entries", [])):
                idx = item.get("index")
                if idx is None:
                    continue
                detail = await client.get(f"/api/request-detail/{idx}")
                if "error" in detail:
                    continue
                body = detail.get("response_body", "") or detail.get("body", "")
                if body:
                    _emit_chunk(body, bins)
                    scanned += 1

        if scan_sitemap:
            sm = await client.get("/api/sitemap", params={"limit": 500})
            if "error" not in sm:
                for item in sm.get("entries", []):
                    # sitemap entries don't carry response bodies — fetch each URL
                    u = item.get("url", "")
                    if not u:
                        continue
                    r = await client.post("/api/http/curl", json={"method": "GET", "url": u})
                    if "error" in r:
                        continue
                    body = r.get("response_body", "") or r.get("body", "")
                    if body:
                        _emit_chunk(body, bins)
                        scanned += 1

        if extra_urls:
            for u in extra_urls:
                r = await client.post("/api/http/curl", json={"method": "GET", "url": u})
                if "error" in r:
                    continue
                body = r.get("response_body", "") or r.get("body", "")
                if body:
                    _emit_chunk(body, bins)
                    scanned += 1

        if scanned == 0:
            return "No traffic scanned. Run browser_crawl + a few authenticated requests first, then re-invoke."

        lines = [f"harvest_identifiers — scanned {scanned} responses", ""]
        total = 0
        for cat in ("emails", "usernames", "uuids", "ulids", "snowflakes", "numeric_ids", "slugs", "phones", "jwts", "hex_tokens"):
            vals = sorted(bins[cat])[:max_per_category]
            total += len(vals)
            if not vals:
                continue
            lines.append(f"--- {cat} ({len(bins[cat])}{'+' if len(bins[cat]) > max_per_category else ''}) ---")
            for v in vals:
                lines.append(f"  {v}")
            lines.append("")
        if total == 0:
            lines.append("No identifiers found.")
        else:
            lines.append(f"Total identifiers: {total}")
            lines.append("\nNext: feed numeric_ids / uuids / ulids / snowflakes into probe_id_monotonic or test_auth_matrix.")
        return "\n".join(lines)
