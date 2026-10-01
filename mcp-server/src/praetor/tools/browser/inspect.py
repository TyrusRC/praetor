"""Inspection tools: get_page_info, execute_js, screenshot."""

import json

from mcp.server.fastmcp import FastMCP

from ._lifecycle import _ensure_browser


def register(mcp: FastMCP):

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
    async def browser_storage(max_value_len: int = 200) -> str:
        """Dump client-side storage of the current page (PTK-style storage inspection).

        Reads localStorage + sessionStorage key/value pairs and the IndexedDB
        database names for the current origin — the client-side state Burp's
        proxy view can't show. Assumes a prior browser_navigate / browser_crawl.
        Values are truncated to max_value_len; keys that look like secrets
        (token/jwt/session/key/secret/password/auth) are flagged so a leaked
        bearer in localStorage (the classic SPA XSS-to-ATO pivot) is obvious.

        Args:
            max_value_len: per-value truncation length (default 200).
        """
        _, _, page = await _ensure_browser()
        try:
            data = await page.evaluate(
                """(cap) => {
                    const dump = (s) => {
                        const o = {};
                        for (let i = 0; i < s.length; i++) {
                            const k = s.key(i);
                            let v = s.getItem(k);
                            if (v && v.length > cap)
                                v = v.slice(0, cap) + '…(+' + (v.length - cap) + 'B)';
                            o[k] = v;
                        }
                        return o;
                    };
                    const p = (async () => {
                        let dbs = [];
                        try {
                            if (indexedDB.databases)
                                dbs = (await indexedDB.databases())
                                    .map(d => d.name + (d.version ? ' v' + d.version : ''));
                        } catch (e) {}
                        return dbs;
                    })();
                    return p.then(dbs => ({
                        origin: location.origin,
                        local: dump(window.localStorage),
                        session: dump(window.sessionStorage),
                        indexedDB: dbs,
                    }));
                }""",
                max_value_len,
            )
        except Exception as e:  # noqa: BLE001 — surface any eval failure as text
            return f"Error reading storage: {e}"

        import re
        sens = re.compile(r"token|jwt|session|secret|password|passwd|auth|api[-_]?key|bearer", re.I)

        def _section(title: str, kv: dict) -> list[str]:
            if not kv:
                return [f"  {title}: (empty)"]
            rows = [f"  {title} ({len(kv)}):"]
            for k, v in kv.items():
                tag = " [sensitive]" if sens.search(k or "") else ""
                rows.append(f"    {k}{tag} = {v}")
            return rows

        lines = [f"Client-side storage — origin {data.get('origin', '?')}"]
        lines += _section("localStorage", data.get("local", {}))
        lines += _section("sessionStorage", data.get("session", {}))
        dbs = data.get("indexedDB", []) or []
        lines.append(f"  IndexedDB databases: {', '.join(dbs) if dbs else '(none)'}")
        return "\n".join(lines)

    @mcp.tool()
    async def browser_screenshot(
        url: str = "",
        full_page: bool = True,
        out_path: str = "",
    ) -> str:
        """Capture a screenshot through the headless browser (Burp-proxied).

        Visual triage tool. Useful for:
          - Aquatone-style "show me what every host looks like" sweeps
          - Hidden admin panel hunting (404 pages that render real content)
          - SPA state capture before / after a destructive button click
          - Report screenshots without leaving the MCP session

        Args:
            url: URL to load. Empty = screenshot current page (assumes prior
                browser_navigate / browser_crawl call).
            full_page: True = entire scroll height; False = viewport only.
            out_path: Output file path. Empty = auto-named under
                .burp-intel/<domain>/screenshots/<timestamp>.png.
        """
        from praetor import client as burp_client
        from pathlib import Path
        import time

        if url:
            scope_resp = await burp_client.check_scope(url)
            if "error" not in scope_resp and not scope_resp.get("in_scope", False):
                return f"Error: {url} is OUT OF SCOPE."

        _, _, page = await _ensure_browser()

        if url:
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_timeout(1500)
            except Exception as e:
                return f"Navigation to {url} failed: {e}"

        if not out_path:
            from urllib.parse import urlparse
            target = url or page.url or "current"
            host = urlparse(target).hostname or "unknown"
            ts = time.strftime("%Y%m%d-%H%M%S")
            out_dir = Path.cwd() / ".burp-intel" / host / "screenshots"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = str(out_dir / f"{ts}.png")
        else:
            Path(out_path).parent.mkdir(parents=True, exist_ok=True)

        try:
            await page.screenshot(path=out_path, full_page=full_page)
            sz = Path(out_path).stat().st_size
            return (
                f"Screenshot captured: {out_path}\n"
                f"  url: {page.url}\n"
                f"  size: {sz} bytes  full_page={full_page}"
            )
        except Exception as e:
            return f"Screenshot failed: {e}"
