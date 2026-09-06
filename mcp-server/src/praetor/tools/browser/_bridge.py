"""Drive the shared headless page from non-tool probe code.

There is no `/api/browser/*` HTTP route on the Burp extension — the headless
browser is an in-process Playwright page owned by `_lifecycle`. Probes that
need to navigate or run JS must go through the page, not a (non-existent) REST
call. These helpers return the small dict shapes their callers already expect
(`html` / `result` / `error`) so call sites stay unchanged.
"""

import json


async def navigate(url: str, wait_until: str = "domcontentloaded",
                   timeout_ms: int = 15000) -> dict:
    """Navigate the shared page and return {'html': ...} or {'error': ...}."""
    from ._lifecycle import _ensure_browser
    try:
        _, _, page = await _ensure_browser()
        await page.goto(url, wait_until=wait_until, timeout=timeout_ms)
        return {"html": await page.content()}
    except Exception as e:  # pragma: no cover — needs a live browser
        return {"error": f"{type(e).__name__}: {e}"}


async def execute_js(script: str) -> dict:
    """Run JS on the shared page. Returns {'result': <str>} or {'error': ...}.

    The result is stringified when the script returns a non-string (mirrors the
    browser_execute_js tool), so callers can `json.loads` a JSON-returning
    script exactly as before.
    """
    from ._lifecycle import _ensure_browser
    try:
        _, _, page = await _ensure_browser()
        res = await page.evaluate(script)
        return {"result": res if isinstance(res, str) else json.dumps(res, default=str)}
    except Exception as e:  # pragma: no cover — needs a live browser
        return {"error": f"{type(e).__name__}: {e}", "result": ""}
