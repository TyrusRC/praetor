"""Navigation tools: navigate, crawl, close."""

from mcp.server.fastmcp import FastMCP

from ._lifecycle import _ensure_browser, _shutdown_browser


def register(mcp: FastMCP):

    @mcp.tool()
    async def browser_navigate(url: str, wait_until: str = "domcontentloaded") -> str:
        """Navigate headless browser to a URL through Burp's proxy. All traffic appears in proxy history.

        Args:
            url: URL to navigate to
            wait_until: Navigation event to wait for ('domcontentloaded', 'load', 'networkidle')
        """
        # Rule 1 (HARD) — the headless browser pulls every sub-resource
        # referenced by the page. If the entry URL is OOS we have no business
        # touching it; sub-resources can still go off-scope when in-scope
        # pages embed CDN/analytics, but the entry gate at least matches the
        # other Java handlers' scope discipline.
        from burpsuite_mcp import client as _client
        try:
            scope_resp = await _client.post("/api/scope/check", json={"url": url})
        except Exception as e:  # pragma: no cover — scope handler should be reachable
            return f"Error: scope check unavailable ({type(e).__name__}: {e})"
        if "error" not in scope_resp and not scope_resp.get("in_scope", False):
            return (
                f"Out of scope: {url}\n"
                "Add the host to Burp scope (configure_scope) before navigating to it."
            )

        _, _, page = await _ensure_browser()

        try:
            resp = await page.goto(url, wait_until=wait_until, timeout=30000)
            status = resp.status if resp else "?"
            title = await page.title()
            frames = page.frames
            return (
                f"Navigated to: {url}\n"
                f"  Status: {status}\n"
                f"  Title: {title}\n"
                f"  Frames: {len(frames)}\n\n"
                f"All traffic now in Burp proxy history. Use get_proxy_history() to inspect."
            )
        except Exception as e:
            return f"Error navigating to {url}: {e}"

    @mcp.tool()
    async def browser_crawl(  # cost: expensive (scales with max_pages)
        url: str,
        max_pages: int = 20,
        same_origin: bool = True,
    ) -> str:
        """Auto-crawl a target by visiting pages and clicking links through Burp's proxy.

        Args:
            url: Starting URL to crawl from
            max_pages: Maximum pages to visit (default 20)
            same_origin: Only follow same-origin links (default True)
        """
        from urllib.parse import urlparse
        from burpsuite_mcp.tools.intel.cost_cap import budget_gate
        _over = budget_gate(urlparse(url).hostname or "")
        if _over:
            return _over

        _, _, page = await _ensure_browser()

        visited: set[str] = set()
        to_visit: list[str] = [url]
        results: list[str] = []

        try:
            from urllib.parse import urlparse
            origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        except Exception:
            origin = ""

        while to_visit and len(visited) < max_pages:
            current = to_visit.pop(0)
            if current in visited:
                continue

            try:
                resp = await page.goto(current, wait_until="domcontentloaded", timeout=15000)
                status = resp.status if resp else "?"
                visited.add(current)
                results.append(f"  [{status}] {current}")

                await page.wait_for_timeout(1000)

                links = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.href)
                        .filter(h => h.startsWith('http'));
                }""")

                for link in links:
                    if link not in visited and link not in to_visit:
                        if same_origin and not link.startswith(origin):
                            continue
                        skip = any(x in link.lower() for x in [
                            '.css', '.js', '.png', '.jpg', '.gif', '.svg',
                            '.woff', '.ico', '/logout', '/signout', '/delete'
                        ])
                        if not skip:
                            to_visit.append(link)

            except Exception as e:
                results.append(f"  [ERR] {current}: {e}")
                visited.add(current)

        lines = [f"Crawl complete: {len(visited)} pages visited\n"]
        lines.extend(results)
        lines.append(f"\nAll {len(visited)} pages in Burp proxy history. Use get_proxy_history() to inspect.")
        return "\n".join(lines)

    @mcp.tool()
    async def browser_close() -> str:
        """Close the headless browser and free resources. Auto-restarts on next browser_navigate."""
        was_running = await _shutdown_browser()
        return "Browser closed" if was_running else "No browser was running"
