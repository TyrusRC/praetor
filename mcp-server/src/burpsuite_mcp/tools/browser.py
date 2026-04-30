"""Stealth headless browser routed through Burp proxy — populates proxy history automatically.

All browser traffic (pages, XHR, WebSocket, JS) flows through Burp's proxy,
making it visible in proxy history for analysis, fuzzing, and extraction.
"""

import asyncio
import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.config import BURP_PROXY_HOST, BURP_PROXY_PORT

# Lazy-loaded browser state (survives across tool calls within a session)
_playwright = None
_browser = None
_context = None
_page = None
_lock = asyncio.Lock()

# Stealth settings to avoid bot detection
_STEALTH_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--disable-features=IsolateOrigins,site-per-process",
    "--disable-infobars",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-timer-throttling",
    "--disable-renderer-backgrounding",
    "--disable-backgrounding-occluded-windows",
]

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


async def _ensure_browser():
    """Launch browser if not already running. Returns (browser, context, page)."""
    global _playwright, _browser, _context, _page

    async with _lock:
        if _browser and _browser.is_connected():
            if _page and not _page.is_closed():
                return _browser, _context, _page
            _page = await _context.new_page()
            return _browser, _context, _page

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise RuntimeError(
                "Playwright not installed. Run: uv pip install playwright && playwright install chromium"
            )

        _playwright = await async_playwright().start()

        proxy_url = f"http://{BURP_PROXY_HOST}:{BURP_PROXY_PORT}"

        _browser = await _playwright.chromium.launch(
            headless=True,
            args=_STEALTH_ARGS,
            proxy={"server": proxy_url},
        )

        _context = await _browser.new_context(
            user_agent=_USER_AGENT,
            viewport={"width": 1920, "height": 1080},
            locale="en-US",
            timezone_id="America/New_York",
            ignore_https_errors=True,  # Burp's CA cert
            java_script_enabled=True,
            extra_http_headers={
                "Accept-Language": "en-US,en;q=0.9",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Sec-Ch-Ua": '"Chromium";v="131", "Not_A Brand";v="24"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
            },
        )

        # Apply playwright-stealth to bypass bot detection
        try:
            from playwright_stealth import stealth_async
            await stealth_async(_context)
        except ImportError:
            await _context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
                window.chrome = { runtime: {} };
            """)

        _page = await _context.new_page()
        return _browser, _context, _page


def register(mcp: FastMCP):

    @mcp.tool()
    async def browser_navigate(url: str, wait_until: str = "domcontentloaded") -> str:
        """Navigate headless browser to a URL through Burp's proxy. All traffic appears in proxy history.

        Args:
            url: URL to navigate to
            wait_until: Navigation event to wait for ('domcontentloaded', 'load', 'networkidle')
        """
        _, _, page = await _ensure_browser()

        try:
            resp = await page.goto(url, wait_until=wait_until, timeout=30000)
            status = resp.status if resp else "?"
            title = await page.title()

            # Count sub-resources loaded
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
    async def browser_click(selector: str, wait_after: int = 2000) -> str:
        """Click an element on the current page. All resulting traffic flows through Burp's proxy.

        Args:
            selector: CSS selector of element to click
            wait_after: Milliseconds to wait after click for network activity (default 2000)
        """
        _, _, page = await _ensure_browser()

        try:
            await page.click(selector, timeout=10000)
            await page.wait_for_timeout(wait_after)
            title = await page.title()
            return f"Clicked: {selector}\n  Now at: {page.url}\n  Title: {title}"
        except Exception as e:
            return f"Error clicking '{selector}': {e}"

    @mcp.tool()
    async def browser_fill(selector: str, value: str) -> str:
        """Fill a form field with a value. Use before browser_click to submit forms.

        Args:
            selector: CSS selector of input field
            value: Value to type into the field
        """
        _, _, page = await _ensure_browser()

        try:
            await page.fill(selector, value, timeout=10000)
            return f"Filled '{selector}' with '{value[:50]}{'...' if len(value) > 50 else ''}'"
        except Exception as e:
            return f"Error filling '{selector}': {e}"

    @mcp.tool()
    async def browser_submit_form(
        fields: dict[str, str],
        submit_selector: str = "",
    ) -> str:
        """Fill multiple form fields and submit. All traffic goes through Burp's proxy.

        Args:
            fields: Dict of CSS selector -> value pairs
            submit_selector: CSS selector for submit button (auto-detected if empty)
        """
        _, _, page = await _ensure_browser()

        try:
            for selector, value in fields.items():
                await page.fill(selector, value, timeout=5000)

            if submit_selector:
                await page.click(submit_selector, timeout=10000)
            else:
                # Try common submit patterns
                for sel in ['button[type=submit]', 'input[type=submit]', 'button:has-text("Login")', 'button:has-text("Submit")']:
                    try:
                        await page.click(sel, timeout=3000)
                        break
                    except Exception:
                        continue

            await page.wait_for_timeout(2000)
            title = await page.title()
            return f"Form submitted\n  Now at: {page.url}\n  Title: {title}\n  Fields filled: {len(fields)}"
        except Exception as e:
            return f"Error submitting form: {e}"

    @mcp.tool()
    async def browser_crawl(
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

                # Wait for dynamic content
                await page.wait_for_timeout(1000)

                # Extract links
                links = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.href)
                        .filter(h => h.startsWith('http'));
                }""")

                for link in links:
                    if link not in visited and link not in to_visit:
                        if same_origin and not link.startswith(origin):
                            continue
                        # Skip static resources, anchors, logout
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
    async def browser_get_links(same_origin: bool = True) -> str:
        """Get all links on the current page.

        Args:
            same_origin: Only return same-origin links (default True)
        """
        _, _, page = await _ensure_browser()

        try:
            from urllib.parse import urlparse
            current_origin = f"{urlparse(page.url).scheme}://{urlparse(page.url).netloc}"
        except Exception:
            current_origin = ""

        try:
            links = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('a[href]')).map(a => ({
                    href: a.href,
                    text: a.innerText.trim().substring(0, 60),
                }));
            }""")

            if same_origin:
                links = [l for l in links if l["href"].startswith(current_origin)]

            # Deduplicate
            seen = set()
            unique = []
            for l in links:
                if l["href"] not in seen:
                    seen.add(l["href"])
                    unique.append(l)

            if not unique:
                return f"No links found on {page.url}"

            lines = [f"Links on {page.url} ({len(unique)}):"]
            for l in unique:
                text = l.get("text", "")
                lines.append(f"  {l['href']}" + (f" [{text}]" if text else ""))
            return "\n".join(lines)
        except Exception as e:
            return f"Error getting links: {e}"

    @mcp.tool()
    async def browser_get_page_info() -> str:
        """Get current page URL, title, cookies, forms, and key elements."""
        _, _, page = await _ensure_browser()

        try:
            info = await page.evaluate("""() => {
                const forms = Array.from(document.forms).map(f => ({
                    action: f.action,
                    method: f.method,
                    inputs: Array.from(f.elements).filter(e => e.name).map(e => ({
                        name: e.name, type: e.type, value: e.type === 'hidden' ? e.value : ''
                    }))
                }));
                const metas = Array.from(document.querySelectorAll('meta')).map(m => ({
                    name: m.name || m.httpEquiv || m.getAttribute('property') || '',
                    content: (m.content || '').substring(0, 100)
                })).filter(m => m.name);
                return {
                    title: document.title,
                    url: location.href,
                    forms: forms,
                    metas: metas,
                    inputCount: document.querySelectorAll('input,textarea,select').length,
                    linkCount: document.querySelectorAll('a[href]').length,
                    scriptCount: document.querySelectorAll('script[src]').length,
                };
            }""")

            cookies = await page.context.cookies()

            lines = [f"Page: {info.get('title', '?')}"]
            lines.append(f"  URL: {info.get('url', '?')}")
            lines.append(f"  Elements: {info.get('inputCount', 0)} inputs, {info.get('linkCount', 0)} links, {info.get('scriptCount', 0)} scripts")

            forms = info.get("forms", [])
            if forms:
                lines.append(f"\n  Forms ({len(forms)}):")
                for f in forms:
                    lines.append(f"    {f.get('method','GET').upper()} {f.get('action','')}")
                    for inp in f.get("inputs", [])[:10]:
                        val = f" = {inp['value']}" if inp.get("value") else ""
                        lines.append(f"      [{inp.get('type','text')}] {inp.get('name','')}{val}")

            if cookies:
                lines.append(f"\n  Cookies ({len(cookies)}):")
                for c in cookies[:10]:
                    lines.append(f"    {c['name']} = {str(c['value'])[:40]}{'...' if len(str(c['value'])) > 40 else ''}")

            return "\n".join(lines)
        except Exception as e:
            return f"Error getting page info: {e}"

    @mcp.tool()
    async def browser_execute_js(script: str) -> str:
        """Execute JavaScript on the current page and return the result.

        Args:
            script: JavaScript code to execute (must return a value)
        """
        _, _, page = await _ensure_browser()

        try:
            result = await page.evaluate(script)
            if isinstance(result, (dict, list)):
                return json.dumps(result, indent=2, default=str)
            return str(result)
        except Exception as e:
            return f"Error executing JS: {e}"

    @mcp.tool()
    async def browser_close() -> str:
        """Close the headless browser and free resources. Auto-restarts on next browser_navigate."""
        global _playwright, _browser, _context, _page

        was_running = _browser is not None or _playwright is not None
        if _browser:
            try:
                await _browser.close()
            except Exception:
                pass
        if _playwright:
            try:
                await _playwright.stop()
            except Exception:
                pass
        # Always reset globals to clean state
        _playwright = None
        _browser = None
        _context = None
        _page = None
        return "Browser closed" if was_running else "No browser was running"

    @mcp.tool()
    async def browser_interact_all(url: str, max_clicks: int = 30) -> str:
        """Navigate to a URL and interact with all buttons, links, dropdowns for maximum proxy coverage. Scope-checked per link.

        Args:
            url: Starting URL (must be in scope)
            max_clicks: Maximum interactions to perform (default 30)
        """
        from burpsuite_mcp import client as burp_client

        # Scope check before we do anything
        scope_resp = await burp_client.post("/api/scope/check", json={"url": url})
        if "error" not in scope_resp and not scope_resp.get("in_scope", False):
            return f"Error: {url} is OUT OF SCOPE. Add to scope first or use a scoped URL."

        _, _, page = await _ensure_browser()

        try:
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(2000)

            interactions = 0
            skipped_oos = 0
            results = [f"Starting interaction sweep on {url}\n"]

            # 1. Click all buttons (not submit/logout)
            buttons = await page.query_selector_all("button:not([type=submit]), [role=button], .btn, .button")
            for btn in buttons[:max_clicks // 3]:
                try:
                    text = await btn.inner_text()
                    text = text.strip()[:30]
                    if any(x in text.lower() for x in ["logout", "delete", "remove", "cancel"]):
                        continue
                    await btn.click(timeout=3000)
                    await page.wait_for_timeout(500)
                    interactions += 1
                    results.append(f"  [btn] {text}")
                except Exception:
                    pass

            # 2. Click navigation links — scope-checked per href
            nav_links = await page.query_selector_all("nav a[href], .nav a[href], header a[href]")
            from urllib.parse import urlparse
            origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

            for link in nav_links[:max_clicks // 3]:
                try:
                    href = await link.get_attribute("href")
                    if not href:
                        continue
                    # Normalize relative → absolute
                    if href.startswith("/"):
                        href = origin + href
                    elif not href.startswith(("http://", "https://")):
                        continue  # mailto:, tel:, javascript:, etc.
                    if any(x in href.lower() for x in ["/logout", "/signout", "/delete"]):
                        continue
                    # Scope check — skip out-of-scope links silently
                    scope_check = await burp_client.post("/api/scope/check", json={"url": href})
                    if "error" not in scope_check and not scope_check.get("in_scope", False):
                        skipped_oos += 1
                        continue
                    text = await link.inner_text()
                    await page.goto(href, wait_until="domcontentloaded", timeout=10000)
                    await page.wait_for_timeout(1000)
                    interactions += 1
                    results.append(f"  [nav] {text.strip()[:30]} -> {href}")
                except Exception:
                    pass

            # 3. Expand dropdowns and toggles
            toggles = await page.query_selector_all("[data-toggle], [aria-expanded=false], details:not([open])")
            for toggle in toggles[:max_clicks // 3]:
                try:
                    await toggle.click(timeout=2000)
                    await page.wait_for_timeout(300)
                    interactions += 1
                    results.append(f"  [toggle] expanded element")
                except Exception:
                    pass

            # Navigate back to original
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=10000)
            except Exception:
                pass

            results.append(f"\nCompleted: {interactions} interactions")
            if skipped_oos:
                results.append(f"Skipped {skipped_oos} out-of-scope links.")
            results.append(f"Check Burp proxy history for all captured traffic.")
            return "\n".join(results)
        except Exception as e:
            return f"Error during interaction sweep: {e}"
