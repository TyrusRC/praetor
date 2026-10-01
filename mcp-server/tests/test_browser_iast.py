"""In-browser IAST: formatter taint-flagging + enable/read wiring.

The shim itself is browser-side JS (exercised only in a live browser); these
tests cover the Python layer — the source-correlation formatting and that enable
injects the shim at context + page level and the reader projects the buffer.
"""

import unittest
from unittest.mock import AsyncMock, patch

from praetor.tools.browser import iast as I


def _fn(name):
    from praetor import server
    return server.mcp._tool_manager._tools[name].fn


class IastFormatTest(unittest.TestCase):

    def test_tainted_hit_flagged_with_source(self):
        recs = [{"sink": "innerHTML", "value": "<img src=x onerror=alert(1)>",
                 "sources": ["location.hash"], "url": "https://t.io/#x"}]
        out = I._fmt(recs, source_only=False)
        self.assertIn("[TAINTED]", out)
        self.assertIn("innerHTML", out)
        self.assertIn("location.hash", out)

    def test_source_only_filters_untainted(self):
        recs = [{"sink": "innerHTML", "value": "safe", "sources": []},
                {"sink": "eval", "value": "x", "sources": ["location.search"]}]
        out = I._fmt(recs, source_only=True)
        self.assertIn("eval", out)
        self.assertNotIn("innerHTML", out)

    def test_empty_buffer_hints_enable(self):
        out = I._fmt([], source_only=False)
        self.assertIn("browser_iast_enable()", out)


class IastWiringTest(unittest.IsolatedAsyncioTestCase):

    async def test_enable_injects_at_context_and_page(self):
        ctx = AsyncMock(); page = AsyncMock()
        with patch.object(I, "_ensure_browser",
                          new=AsyncMock(return_value=(None, ctx, page))):
            out = await _fn("browser_iast_enable")()
        ctx.add_init_script.assert_awaited_once()   # covers future navigations
        page.evaluate.assert_awaited()              # hooks current page now
        self.assertIn("IAST enabled", out)

    async def test_read_projects_buffer(self):
        page = AsyncMock()
        page.evaluate = AsyncMock(return_value=[
            {"sink": "document.write", "value": "<script>", "sources": ["location.hash"],
             "url": "https://t.io/#p"}])
        with patch.object(I, "_ensure_browser",
                          new=AsyncMock(return_value=(None, None, page))):
            out = await _fn("browser_iast")()
        self.assertIn("document.write", out)
        self.assertIn("[TAINTED]", out)


if __name__ == "__main__":
    unittest.main()
