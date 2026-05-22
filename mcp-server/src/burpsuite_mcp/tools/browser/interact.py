"""Interaction tools: click, fill, submit_form, interact_all."""

from mcp.server.fastmcp import FastMCP

from ._lifecycle import _ensure_browser


def register(mcp: FastMCP):

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
    async def browser_interact_all(url: str, max_clicks: int = 30) -> str:
        """Navigate to a URL and interact with all buttons, links, dropdowns for maximum proxy coverage. Scope-checked per link.

        Args:
            url: Starting URL (must be in scope)
            max_clicks: Maximum interactions to perform (default 30)
        """
        from burpsuite_mcp import client as burp_client

        scope_resp = await burp_client.check_scope(url)
        if "error" not in scope_resp and not scope_resp.get("in_scope", False):
            return f"Error: {url} is OUT OF SCOPE. Add to scope first or use a scoped URL."

        _, _, page = await _ensure_browser()

        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
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
                    if href.startswith("/"):
                        href = origin + href
                    elif not href.startswith(("http://", "https://")):
                        continue  # mailto:, tel:, javascript:, etc.
                    if any(x in href.lower() for x in ["/logout", "/signout", "/delete"]):
                        continue
                    scope_check = await burp_client.check_scope(href)
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
