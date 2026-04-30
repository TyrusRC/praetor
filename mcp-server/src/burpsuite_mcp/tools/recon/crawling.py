"""Web crawling tools."""

from mcp.server.fastmcp import FastMCP

from ._common import _check_tool, _run_cmd, _sanitize_domain, _USER_AGENT, BURP_PROXY_URL


def register(mcp: FastMCP):

    @mcp.tool()
    async def run_katana(
        target: str,
        depth: int = 3,
        crawl_mode: str = "hybrid",
        js_crawl: bool = True,
        known_files: bool = False,
        form_fill: bool = False,
        filter_similar: bool = True,
        scope_domain: str = "",
        use_proxy: bool = True,
        timeout: int = 300,
    ) -> str:
        """Crawl a target with katana to discover URLs, endpoints, and JS-rendered paths. Requires katana installed.

        Args:
            target: Target URL
            depth: Crawl depth (default 3, max 10)
            crawl_mode: 'standard', 'headless', or 'hybrid' (default)
            js_crawl: Parse JS files for endpoints (default True)
            known_files: Probe robots.txt, sitemap.xml
            form_fill: Auto-fill and submit forms (experimental)
            filter_similar: Deduplicate similar URLs (default True)
            scope_domain: Restrict to domain regex (auto from target if empty)
            use_proxy: Route through Burp proxy (default True)
            timeout: Max seconds (default 300)
        """
        if not _check_tool("katana"):
            return "Error: katana not installed. Install: CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest"

        depth = min(depth, 10)
        cmd = ["katana", "-u", target, "-silent", "-no-color",
               "-d", str(depth),
               "-H", f"User-Agent: {_USER_AGENT}",
               "-rl", "100", "-c", "10",
               "-e", "cdn,private-ips",           # exclude CDN and private IP ranges
               "-td",                              # tech detection via wappalyzer
               "-kb"]                              # knowledge base classification

        # Crawl mode
        # -nos = no-sandbox (required for root/WSL)
        # -xhr = extract XHR request URLs (finds hidden API calls)
        if crawl_mode == "hybrid":
            cmd.extend(["-hh", "-nos", "-xhr"])
        elif crawl_mode == "headless":
            cmd.extend(["-hl", "-nos", "-xhr"])

        if js_crawl:
            cmd.append("-jc")
        if known_files and depth >= 3:
            cmd.extend(["-kf", "all"])
        if form_fill:
            cmd.append("-aff")
        if filter_similar:
            cmd.append("-fsu")
        if scope_domain:
            cmd.extend(["-fs", _sanitize_domain(scope_domain)])
        if use_proxy:
            # Burp MITMs HTTPS. Katana's headless browser ignores cert errors
            # by default (Chrome --no-sandbox mode), so HTTPS via Burp works.
            # For HTTP mode (-d without -hh/-hl), requests may fail on bad certs —
            # install the Burp CA if running repeatedly: http://burp/cert from a
            # browser pointed at Burp's proxy.
            cmd.extend(["-proxy", BURP_PROXY_URL])

        stdout, stderr, code = await _run_cmd(cmd, timeout)

        if code != 0 and not stdout:
            return f"katana failed (exit {code}): {stderr[:500]}"

        urls = [line.strip() for line in stdout.strip().split("\n") if line.strip()]

        if not urls:
            return f"No URLs discovered by katana for {target}"

        # Categorize URLs
        js_urls = [u for u in urls if u.endswith(".js") or ".js?" in u]
        api_urls = [u for u in urls if "/api/" in u or "/v1/" in u or "/v2/" in u or "/graphql" in u]
        form_urls = [u for u in urls if "?" in u]
        other_urls = [u for u in urls if u not in js_urls and u not in api_urls and u not in form_urls]

        lines = [f"Katana crawl of {target} ({len(urls)} URLs, depth={depth}):", ""]

        if api_urls:
            lines.append(f"  API endpoints ({len(api_urls)}):")
            for u in api_urls[:20]:
                lines.append(f"    {u}")
            if len(api_urls) > 20:
                lines.append(f"    ... +{len(api_urls) - 20} more")

        if form_urls:
            lines.append(f"\n  Parameterized URLs ({len(form_urls)}):")
            for u in form_urls[:20]:
                lines.append(f"    {u}")
            if len(form_urls) > 20:
                lines.append(f"    ... +{len(form_urls) - 20} more")

        if js_urls:
            lines.append(f"\n  JavaScript files ({len(js_urls)}):")
            for u in js_urls[:15]:
                lines.append(f"    {u}")
            if len(js_urls) > 15:
                lines.append(f"    ... +{len(js_urls) - 15} more")

        if other_urls:
            lines.append(f"\n  Other pages ({len(other_urls)}):")
            for u in other_urls[:20]:
                lines.append(f"    {u}")
            if len(other_urls) > 20:
                lines.append(f"    ... +{len(other_urls) - 20} more")

        lines.append(f"\nTotal: {len(urls)} URLs ({len(api_urls)} API, {len(form_urls)} parameterized, {len(js_urls)} JS)")
        if use_proxy:
            lines.append("All requests went through Burp proxy — check proxy history.")

        return "\n".join(lines)
