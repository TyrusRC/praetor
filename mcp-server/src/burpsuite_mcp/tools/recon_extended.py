"""Python-only external recon tools — no Go binaries required.

Provides certificate transparency lookups, Wayback Machine URL harvesting,
DNS analysis, and subdomain takeover detection. All tools use httpx for
external APIs and asyncio subprocess for dig commands.

``test_rate_limit`` lives in ``tools/testing/rate_limit.py`` — it's a behavior
probe, not external recon.
"""

import asyncio
import re
import socket

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
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", domain, record_type, "+short",
            # Same rationale as _run_cmd: never inherit the MCP stdio pipe.
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout_b.decode(errors="replace").strip()
    except asyncio.TimeoutError:
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
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


# Subdomain takeover fingerprints. Source: can-i-take-over-xyz + current hosts.
TAKEOVER_FINGERPRINTS = {
    "github.io": {"cname": "github.io", "body": "There isn't a GitHub Pages site here"},
    "githubusercontent.com": {"cname": "githubusercontent.com", "body": "404: Not Found"},
    "gitlab.io": {"cname": "gitlab.io", "body": "404 Not Found"},
    "herokuapp.com": {"cname": "herokuapp.com", "body": "no-such-app"},
    "herokudns.com": {"cname": "herokudns.com", "body": "no such app"},
    "s3.amazonaws.com": {"cname": "s3.amazonaws.com", "body": "NoSuchBucket"},
    "s3-website": {"cname": "s3-website", "body": "NoSuchBucket"},
    "azurewebsites.net": {"cname": "azurewebsites.net", "body": "404 Web Site not found"},
    "cloudapp.net": {"cname": "cloudapp.net", "body": "404 Web Site not found"},
    "trafficmanager.net": {"cname": "trafficmanager.net", "body": "404 Web Site not found"},
    "blob.core.windows.net": {"cname": "blob.core.windows.net", "body": "The specified blob does not exist"},
    "azurestaticapps.net": {"cname": "azurestaticapps.net", "body": "404 Not Found"},
    "cloudfront.net": {"cname": "cloudfront.net", "body": "Bad Request"},
    "elasticbeanstalk.com": {"cname": "elasticbeanstalk.com", "body": "404 Not Found"},
    "pantheon.io": {"cname": "pantheon.io", "body": "404 error unknown site"},
    "shopify.com": {"cname": "shopify.com", "body": "Sorry, this shop is currently unavailable"},
    "myshopify.com": {"cname": "myshopify.com", "body": "Sorry, this shop is currently unavailable"},
    "surge.sh": {"cname": "surge.sh", "body": "project not found"},
    "ghost.io": {"cname": "ghost.io", "body": "The thing you were looking for is no longer here"},
    "bitbucket.io": {"cname": "bitbucket.io", "body": "Repository not found"},
    "wordpress.com": {"cname": "wordpress.com", "body": "doesn't exist"},
    "tumblr.com": {"cname": "tumblr.com", "body": "There's nothing here"},
    "domains.tumblr.com": {"cname": "domains.tumblr.com", "body": "Whatever you were looking for doesn't currently exist at this address"},
    "zendesk.com": {"cname": "zendesk.com", "body": "Help Center Closed"},
    "readme.io": {"cname": "readme.io", "body": "Project doesnt exist"},
    "cargo.site": {"cname": "cargo.site", "body": "404 Not Found"},
    "fastly.net": {"cname": "fastly.net", "body": "Fastly error: unknown domain"},
    "global.fastly.net": {"cname": "global.fastly.net", "body": "Fastly error: unknown domain"},
    "feedpress.me": {"cname": "feedpress.me", "body": "The feed has not been found"},
    "fly.io": {"cname": "fly.io", "body": "404 Not Found"},
    "fly.dev": {"cname": "fly.dev", "body": "404 Not Found"},
    "freshdesk.com": {"cname": "freshdesk.com", "body": "May be this is still fresh"},
    "getresponse.com": {"cname": "getresponse.com", "body": "With GetResponse Landing Pages"},
    "hatenablog.com": {"cname": "hatenablog.com", "body": "404 Blog is not found"},
    "helpjuice.com": {"cname": "helpjuice.com", "body": "We could not find what you're looking for"},
    "helpscoutdocs.com": {"cname": "helpscoutdocs.com", "body": "No settings were found for this company"},
    "intercom.help": {"cname": "intercom.help", "body": "This page is reserved for artistic dogs"},
    "kinsta.com": {"cname": "kinsta.com", "body": "No Site For Domain"},
    "launchrock.com": {"cname": "launchrock.com", "body": "It looks like you may have taken a wrong turn somewhere"},
    "mashery.com": {"cname": "mashery.com", "body": "Unrecognized domain"},
    "ngrok.io": {"cname": "ngrok.io", "body": "Tunnel.*not found"},
    "ngrok-free.app": {"cname": "ngrok-free.app", "body": "Tunnel.*not found"},
    "pageserve.co": {"cname": "pageserve.co", "body": "404 Not Found"},
    "smartling.com": {"cname": "smartling.com", "body": "Domain is not configured"},
    "smugmug.com": {"cname": "smugmug.com", "body": "Page Not Found"},
    "statuspage.io": {"cname": "statuspage.io", "body": "You are being redirected"},
    "strikinglydns.com": {"cname": "strikinglydns.com", "body": "PAGE NOT FOUND"},
    "tave.com": {"cname": "tave.com", "body": "Error 404: Page Not Found"},
    "teamwork.com": {"cname": "teamwork.com", "body": "Oops - We didn't find your site"},
    "thinkific.com": {"cname": "thinkific.com", "body": "You may have mistyped the address"},
    "tilda.cc": {"cname": "tilda.cc", "body": "Please renew your subscription"},
    "uberflip.com": {"cname": "uberflip.com", "body": "The URL you've accessed does not provide a hub"},
    "unbouncepages.com": {"cname": "unbouncepages.com", "body": "The requested URL was not found on this server"},
    "uservoice.com": {"cname": "uservoice.com", "body": "This UserVoice subdomain is currently available"},
    "vend.com": {"cname": "vend.com", "body": "Looks like you've traveled too far into cyberspace"},
    "webflow.io": {"cname": "webflow.io", "body": "The page you are looking for doesn't exist or has been moved"},
    "wishpond.com": {"cname": "wishpond.com", "body": "wishpond.com/404"},
    "wufoo.com": {"cname": "wufoo.com", "body": "Hmmm....something is not right"},
    "agilecrm.com": {"cname": "agilecrm.com", "body": "Sorry, this page is no longer available"},
    "aha.io": {"cname": "aha.io", "body": "There is no portal here"},
    "anima.io": {"cname": "anima.io", "body": "If this is your website and you've just created it"},
    "bigcartel.com": {"cname": "bigcartel.com", "body": "Oops! We couldn"},
    "campaignmonitor.com": {"cname": "createsend.com", "body": "Double check the URL"},
    "clickfunnels.com": {"cname": "clickfunnels.com", "body": "Not found"},
    "desk.com": {"cname": "desk.com", "body": "Sorry, We Couldn't Find That Page"},
    "vercel.app": {"cname": "vercel-dns.com", "body": "The deployment could not be found"},
    "vercel-dns.com": {"cname": "vercel-dns.com", "body": "The deployment could not be found"},
    "netlify.app": {"cname": "netlify.app", "body": "Not Found - Request ID:"},
    "onrender.com": {"cname": "onrender.com", "body": "Not Found"},
    "railway.app": {"cname": "railway.app", "body": "Application not found"},
    "pages.dev": {"cname": "pages.dev", "body": "404 not found"},
    "supabase.co": {"cname": "supabase.co", "body": "project is paused"},
    "firebaseapp.com": {"cname": "firebaseapp.com", "body": "Site Not Found"},
    "web.app": {"cname": "web.app", "body": "Site Not Found"},
    "appspot.com": {"cname": "appspot.com", "body": "404 Not Found"},
    "run.app": {"cname": "run.app", "body": "Service Unavailable"},
    "cloudfunctions.net": {"cname": "cloudfunctions.net", "body": "404 Not Found"},
    "dnsimple.com": {"cname": "dnsimple.com", "body": "Domain is not configured"},
    "fastmail.com": {"cname": "fastmail.com", "body": "404 page not found"},
    "frontify.com": {"cname": "frontify.com", "body": "Frontify"},
    "happyfox.com": {"cname": "happyfox.com", "body": "No settings were found for this company"},
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

        # Defensive: archive.org may return an error envelope (dict) instead of
        # the documented list-of-lists shape under maintenance / rate limit.
        if not isinstance(rows, list):
            return f"Error: Wayback Machine returned unexpected payload: {str(rows)[:200]}"
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

