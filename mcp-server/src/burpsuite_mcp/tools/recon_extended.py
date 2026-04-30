"""Python-only external recon tools — no Go binaries required.

Provides certificate transparency lookups, Wayback Machine URL harvesting,
DNS analysis, subdomain takeover detection, and rate limit testing.
All tools use httpx for external APIs and asyncio subprocess for dig commands.
"""

import asyncio
import re
import socket
import time

import httpx
from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def _sanitize_domain(domain: str) -> str:
    """Sanitize domain input to prevent injection."""
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$', domain):
        raise ValueError(f"Invalid domain: {domain}")
    return domain


_DIG_MISSING_LOGGED = False


async def _dig(domain: str, record_type: str, timeout: int = 10) -> str:
    """Run dig for a specific record type. Returns +short output.

    Returns empty string if dig is missing (common on Windows) or the lookup
    times out. Use `_dig_available()` to distinguish "dig missing" from
    "no records exist" before reporting to the user.
    """
    global _DIG_MISSING_LOGGED
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", domain, record_type, "+short",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace").strip()
    except asyncio.TimeoutError:
        return ""
    except FileNotFoundError:
        _DIG_MISSING_LOGGED = True
        return ""


def _dig_available() -> bool:
    """Return True if dig produced any result at least once OR is on PATH.

    Cheap heuristic: we set _DIG_MISSING_LOGGED to True the first time a
    FileNotFoundError fires. If that's ever set, dig is not installed.
    """
    import shutil
    return shutil.which("dig") is not None


# Known services vulnerable to subdomain takeover
TAKEOVER_FINGERPRINTS = {
    "github.io": {"cname": "github.io", "body": "There isn't a GitHub Pages site here"},
    "herokuapp.com": {"cname": "herokuapp.com", "body": "no-such-app"},
    "s3.amazonaws.com": {"cname": "s3.amazonaws.com", "body": "NoSuchBucket"},
    "azurewebsites.net": {"cname": "azurewebsites.net", "body": "404 Web Site not found"},
    "cloudfront.net": {"cname": "cloudfront.net", "body": "Bad Request"},
    "pantheon.io": {"cname": "pantheon.io", "body": "404 error unknown site"},
    "shopify.com": {"cname": "shopify.com", "body": "Sorry, this shop is currently unavailable"},
    "surge.sh": {"cname": "surge.sh", "body": "project not found"},
    "ghost.io": {"cname": "ghost.io", "body": "The thing you were looking for is no longer here"},
    "bitbucket.io": {"cname": "bitbucket.io", "body": "Repository not found"},
    "wordpress.com": {"cname": "wordpress.com", "body": "doesn't exist"},
    "tumblr.com": {"cname": "tumblr.com", "body": "There's nothing here"},
    "zendesk.com": {"cname": "zendesk.com", "body": "Help Center Closed"},
    "readme.io": {"cname": "readme.io", "body": "Project doesnt exist"},
    "cargo.site": {"cname": "cargo.site", "body": "404 Not Found"},
}


def register(mcp: FastMCP):

    @mcp.tool()
    async def query_crtsh(domain: str, include_expired: bool = False) -> str:
        """Query crt.sh Certificate Transparency logs for subdomains.

        Args:
            domain: Target domain
            include_expired: Include expired certificates (default false)
        """
        domain = _sanitize_domain(domain)
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        if not include_expired:
            url += "&exclude=expired"

        # crt.sh is a third-party reference DB for CT logs — not the target.
        # Direct call; don't pollute Burp proxy history with intel lookups.
        try:
            async with httpx.AsyncClient(timeout=30) as http:
                resp = await http.get(url)
                resp.raise_for_status()
                entries = resp.json()
        except httpx.TimeoutException:
            return "Error: crt.sh timed out (30s). The service can be slow — try again later."
        except httpx.HTTPStatusError as e:
            return f"Error: crt.sh returned HTTP {e.response.status_code}"
        except Exception as e:
            return f"Error querying crt.sh: {e}"

        if not entries:
            return f"No CT log entries found for {domain}"

        # Extract unique subdomains from name_value field
        subdomains: set[str] = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and name.endswith(domain) and "*" not in name:
                    subdomains.add(name)

        sorted_subs = sorted(subdomains)

        lines = [f"CT subdomains for {domain} ({len(sorted_subs)} unique):", ""]
        for sub in sorted_subs[:300]:
            lines.append(f"  {sub}")
        if len(sorted_subs) > 300:
            lines.append(f"  ... +{len(sorted_subs) - 300} more")

        lines.append(f"\nTotal: {len(sorted_subs)} subdomains from {len(entries)} CT log entries")
        return "\n".join(lines)

    @mcp.tool()
    async def fetch_wayback_urls(
        domain: str,
        limit: int = 200,
        filter_status: str = "200",
    ) -> str:
        """Get historical URLs from the Wayback Machine CDX API.

        Args:
            domain: Target domain
            limit: Max URLs to return (default 200)
            filter_status: HTTP status filter (default '200', '' for all)
        """
        domain = _sanitize_domain(domain)
        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original,statuscode,timestamp",
            "collapse": "urlkey",
            "limit": str(limit),
        }
        if filter_status:
            params["filter"] = f"statuscode:{filter_status}"

        # Wayback CDX is a third-party archive service — not the target.
        # Direct call; don't pollute Burp proxy history with intel lookups.
        try:
            async with httpx.AsyncClient(timeout=30) as http:
                resp = await http.get(
                    "https://web.archive.org/cdx/search/cdx",
                    params=params,
                )
                resp.raise_for_status()
                rows = resp.json()
        except httpx.TimeoutException:
            return "Error: Wayback Machine timed out (30s). Try again later."
        except httpx.HTTPStatusError as e:
            return f"Error: Wayback Machine returned HTTP {e.response.status_code}"
        except Exception as e:
            return f"Error querying Wayback Machine: {e}"

        if not rows or len(rows) <= 1:
            return f"No Wayback URLs found for {domain}"

        # First row is header: ["original", "statuscode", "timestamp"]
        data_rows = rows[1:]

        # Extract unique URLs
        seen: set[str] = set()
        urls: list[str] = []
        for row in data_rows:
            url_val = row[0] if len(row) > 0 else ""
            if url_val and url_val not in seen:
                seen.add(url_val)
                urls.append(url_val)

        # Categorize
        api_urls = [u for u in urls if "/api/" in u or "/v1/" in u or "/v2/" in u or "/v3/" in u or "/graphql" in u]
        js_urls = [u for u in urls if u.endswith(".js") or ".js?" in u]
        interesting = [u for u in urls if any(p in u.lower() for p in [
            ".env", ".git", ".bak", ".old", ".sql", ".zip", ".tar",
            "config", "admin", "debug", "backup", ".log", "phpinfo",
            ".swp", ".DS_Store", "wp-config", ".htaccess",
        ])]
        pages = [u for u in urls if u not in set(api_urls + js_urls + interesting)]

        lines = [f"Wayback URLs for {domain} ({len(urls)} unique):", ""]

        if interesting:
            lines.append(f"  Interesting files ({len(interesting)}):")
            for u in interesting[:30]:
                lines.append(f"    {u}")
            if len(interesting) > 30:
                lines.append(f"    ... +{len(interesting) - 30} more")
            lines.append("")

        if api_urls:
            lines.append(f"  API endpoints ({len(api_urls)}):")
            for u in api_urls[:30]:
                lines.append(f"    {u}")
            if len(api_urls) > 30:
                lines.append(f"    ... +{len(api_urls) - 30} more")
            lines.append("")

        if js_urls:
            lines.append(f"  JavaScript files ({len(js_urls)}):")
            for u in js_urls[:20]:
                lines.append(f"    {u}")
            if len(js_urls) > 20:
                lines.append(f"    ... +{len(js_urls) - 20} more")
            lines.append("")

        if pages:
            lines.append(f"  Pages ({len(pages)}):")
            for u in pages[:30]:
                lines.append(f"    {u}")
            if len(pages) > 30:
                lines.append(f"    ... +{len(pages) - 30} more")

        lines.append(f"\nTotal: {len(urls)} URLs ({len(api_urls)} API, {len(js_urls)} JS, {len(interesting)} interesting, {len(pages)} pages)")
        return "\n".join(lines)

    @mcp.tool()
    async def analyze_dns(domain: str) -> str:
        """Analyze DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA) and flag security-relevant findings.

        Args:
            domain: Target domain
        """
        domain = _sanitize_domain(domain)
        lines = [f"DNS records for {domain}:", ""]
        notes: list[str] = []

        # Warn up front if dig is missing — socket-only output is misleading
        # for a tool that claims MX/TXT/NS/CNAME/SOA support.
        dig_ok = _dig_available()
        if not dig_ok:
            lines.append("  [!] `dig` not found on PATH — only A/AAAA records available")
            lines.append("      Install BIND utils (Linux: `apt install dnsutils`;")
            lines.append("      Windows: `scoop install dnsutils` or use WSL)")
            lines.append("")

        # A records via socket
        try:
            a_records: set[str] = set()
            results = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
            for _, _, _, _, addr in results:
                a_records.add(addr[0])
            if a_records:
                lines.append("  A records:")
                for ip in sorted(a_records):
                    lines.append(f"    {ip}")
        except socket.gaierror:
            lines.append("  A records: NXDOMAIN / resolution failed")
            notes.append("Domain does not resolve — possible expired or parked domain")

        # AAAA records via socket
        try:
            aaaa_records: set[str] = set()
            results = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
            for _, _, _, _, addr in results:
                aaaa_records.add(addr[0])
            if aaaa_records:
                lines.append("  AAAA records:")
                for ip in sorted(aaaa_records):
                    lines.append(f"    {ip}")
        except socket.gaierror:
            pass

        # Other record types via dig
        for rtype in ["CNAME", "MX", "NS", "TXT", "SOA"]:
            result = await _dig(domain, rtype)
            if result:
                lines.append(f"  {rtype} records:")
                for record_line in result.split("\n"):
                    record_line = record_line.strip()
                    if not record_line:
                        continue
                    lines.append(f"    {record_line}")

                    # Security analysis
                    if rtype == "TXT":
                        if "v=spf1" in record_line:
                            notes.append(f"SPF record found: {record_line[:100]}")
                        if "v=DMARC1" in record_line.upper():
                            notes.append(f"DMARC record found: {record_line[:100]}")
                    if rtype == "CNAME":
                        if not record_line.rstrip(".").endswith(domain):
                            notes.append(f"External CNAME: {domain} -> {record_line} (check for takeover)")
                    if rtype == "MX":
                        if "google" in record_line.lower():
                            notes.append("Mail hosted on Google Workspace")
                        elif "outlook" in record_line.lower() or "microsoft" in record_line.lower():
                            notes.append("Mail hosted on Microsoft 365")

        # Check DMARC subdomain
        dmarc_result = await _dig(f"_dmarc.{domain}", "TXT")
        if dmarc_result:
            lines.append(f"  DMARC (_dmarc.{domain}):")
            for record_line in dmarc_result.split("\n"):
                if record_line.strip():
                    lines.append(f"    {record_line.strip()}")
                    notes.append(f"DMARC policy: {record_line.strip()[:100]}")
        else:
            notes.append("No DMARC record found")

        # Check wildcard DNS
        wildcard_result = await _dig(f"random-nonexistent-sub-1337.{domain}", "A")
        if wildcard_result:
            notes.append(f"Wildcard DNS detected (*.{domain} -> {wildcard_result})")

        # Security notes
        if notes:
            lines.append("")
            lines.append("  Security notes:")
            for note in notes:
                lines.append(f"    - {note}")

        return "\n".join(lines)

    @mcp.tool()
    async def test_subdomain_takeover(subdomains: list[str]) -> str:
        """Check subdomains for potential takeover via dangling CNAME records.

        Args:
            subdomains: List of subdomains to check
        """
        if not subdomains:
            return "Error: provide at least one subdomain to check"

        if len(subdomains) > 100:
            return "Error: max 100 subdomains per check to avoid abuse"

        results: list[dict] = []
        vulnerable: list[dict] = []

        for subdomain in subdomains:
            subdomain = subdomain.strip().lower()
            if not subdomain:
                continue

            # Resolve CNAME
            cname = await _dig(subdomain, "CNAME")
            if not cname:
                results.append({"subdomain": subdomain, "status": "no_cname"})
                continue

            cname = cname.split("\n")[0].strip().rstrip(".")

            # Check against known vulnerable services
            matched_service = None
            for service, fingerprint in TAKEOVER_FINGERPRINTS.items():
                if fingerprint["cname"] in cname:
                    matched_service = service
                    break

            if not matched_service:
                results.append({"subdomain": subdomain, "cname": cname, "status": "not_vulnerable_service"})
                continue

            # HTTP check to verify the body fingerprint
            fingerprint = TAKEOVER_FINGERPRINTS[matched_service]
            body_match = False
            http_error = None

            try:
                data = await client.post("/api/http/curl", json={
                    "url": f"https://{subdomain}",
                    "method": "GET",
                })
                if "error" not in data:
                    body = data.get("response_body", "")
                    body_match = fingerprint["body"].lower() in body.lower()
                else:
                    http_error = data["error"][:100]
            except Exception as e:
                http_error = str(e)[:100]

            entry = {
                "subdomain": subdomain,
                "cname": cname,
                "service": matched_service,
                "body_match": body_match,
                "http_error": http_error,
            }

            if body_match:
                entry["status"] = "VULNERABLE"
                vulnerable.append(entry)
            elif http_error:
                entry["status"] = "possible (HTTP failed)"
                vulnerable.append(entry)
            else:
                entry["status"] = "cname_match_but_active"

            results.append(entry)

        # Format output
        lines = [f"Subdomain takeover check ({len(subdomains)} checked):", ""]

        if vulnerable:
            lines.append(f"  POTENTIALLY VULNERABLE ({len(vulnerable)}):")
            for v in vulnerable:
                status = v["status"]
                lines.append(f"    [{status}] {v['subdomain']}")
                lines.append(f"      CNAME: {v['cname']} ({v['service']})")
                if v.get("http_error"):
                    lines.append(f"      HTTP error: {v['http_error']}")
            lines.append("")

        safe_count = len(results) - len(vulnerable)
        no_cname = sum(1 for r in results if r.get("status") == "no_cname")
        lines.append(f"  Summary: {len(vulnerable)} potentially vulnerable, {safe_count} safe, {no_cname} no CNAME")

        return "\n".join(lines)

    @mcp.tool()
    async def test_rate_limit(
        session: str,
        method: str,
        path: str,
        requests_count: int = 30,
        delay_ms: int = 0,
    ) -> str:
        """Test rate limiting on an endpoint with rapid requests, then try bypass headers if limited.

        Args:
            session: Session name
            method: HTTP method
            path: URL path to test
            requests_count: Number of requests to send (default 30, max 100)
            delay_ms: Delay between requests in ms (default 0)
        """
        requests_count = min(requests_count, 100)

        # Phase 1: Rapid fire requests
        status_codes: list[int] = []
        response_times: list[float] = []
        rate_limited = False
        rate_limit_at = -1

        for i in range(requests_count):
            if delay_ms > 0 and i > 0:
                await asyncio.sleep(delay_ms / 1000.0)

            start = time.monotonic()
            data = await client.post("/api/session/request", json={
                "session": session,
                "method": method,
                "path": path,
            })
            elapsed = (time.monotonic() - start) * 1000  # ms

            if "error" in data:
                status_codes.append(0)
                response_times.append(elapsed)
                continue

            status = data.get("status", data.get("status_code", 0))
            status_codes.append(status)
            response_times.append(elapsed)

            if status == 429 and not rate_limited:
                rate_limited = True
                rate_limit_at = i + 1

        # Analyze Phase 1
        lines = [f"Rate limit test: {method} {path} ({requests_count} requests):", ""]

        # Status code distribution
        code_counts: dict[int, int] = {}
        for code in status_codes:
            code_counts[code] = code_counts.get(code, 0) + 1

        lines.append("  Phase 1 - Rapid requests:")
        lines.append(f"    Status codes: {', '.join(f'{code}={count}' for code, count in sorted(code_counts.items()))}")

        if response_times:
            avg_time = sum(response_times) / len(response_times)
            min_time = min(response_times)
            max_time = max(response_times)
            lines.append(f"    Response time: avg={avg_time:.0f}ms, min={min_time:.0f}ms, max={max_time:.0f}ms")

        if rate_limited:
            lines.append(f"    Rate limited at request #{rate_limit_at}")
        else:
            # Check for soft rate limiting (increasing response times)
            if response_times and max(response_times) > 3 * min(response_times):
                lines.append("    Possible soft rate limiting (response times increasing)")
            else:
                lines.append("    No rate limiting detected")

        # Phase 2: Bypass attempts (only if rate limited)
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Original-URL": path},
            {"X-Originating-IP": "127.0.0.1"},
        ]

        if rate_limited:
            lines.append("")
            lines.append("  Phase 2 - Bypass attempts:")

            for header_dict in bypass_headers:
                header_name = list(header_dict.keys())[0]
                header_value = list(header_dict.values())[0]

                data = await client.post("/api/session/request", json={
                    "session": session,
                    "method": method,
                    "path": path,
                    "headers": {header_name: header_value},
                })

                if "error" in data:
                    lines.append(f"    {header_name}: ERROR - {data['error'][:60]}")
                    continue

                status = data.get("status", data.get("status_code", 0))
                bypassed = status != 429
                marker = "BYPASSED" if bypassed else "blocked"
                lines.append(f"    {header_name}: [{status}] {marker}")

        # Summary
        lines.append("")
        if rate_limited:
            lines.append(f"  Result: Rate limited after {rate_limit_at} requests. Check bypass results above.")
        else:
            lines.append(f"  Result: No rate limiting after {requests_count} requests.")

        return "\n".join(lines)
