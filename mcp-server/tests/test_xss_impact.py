"""xss_impact_proof — benign XSS execution->impact payload generator + the httpx
page-type noise filter."""

import asyncio
import unittest

from praetor.tools import xss_impact as X
from praetor.tools.recon.scanning.dns_intel import _page_type


class _FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self, *a, **k):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


class XssImpactTest(unittest.TestCase):
    def setUp(self):
        self.mcp = _FakeMCP()
        X.register(self.mcp)

    def _call(self, **kw):
        return asyncio.run(self.mcp.tools["xss_impact_proof"](**kw))

    def test_requires_callback_rule9a(self):
        out = self._call(capture="cookie")
        self.assertIn("error", out)
        self.assertIn("9a", out["error"])

    def test_callback_normalized(self):
        out = self._call(callback="abc.oastify.com")
        self.assertEqual(out["callback"], "https://abc.oastify.com")

    def test_cookie_proves_session_theft(self):
        out = self._call(callback="cb", capture="cookie")
        self.assertTrue(any("document.cookie" in p["payload"] for p in out["payloads"]))

    def test_marker_sends_zero_page_data(self):
        out = self._call(callback="cb", capture="marker")
        joined = " ".join(p["payload"] for p in out["payloads"])
        self.assertNotIn("document.cookie", joined)
        self.assertNotIn("localStorage", joined)

    def test_storage_sends_key_names_not_values(self):
        out = self._call(callback="cb", capture="storage")
        joined = " ".join(p["payload"] for p in out["payloads"])
        self.assertIn("Object.keys(localStorage)", joined)   # key names only
        self.assertNotIn("localStorage.getItem", joined)     # never dumps values

    def test_token_needs_selector(self):
        self.assertIn("selector", self._call(callback="cb", capture="token")["error"])
        ok = self._call(callback="cb", capture="token", selector="#csrf")
        self.assertTrue(any("querySelector('#csrf')" in p["payload"] for p in ok["payloads"]))

    def test_unknown_capture(self):
        self.assertIn("unknown capture", self._call(callback="cb", capture="everything")["error"])

    def test_safety_banner_present(self):
        out = self._call(callback="cb")
        self.assertIn("own session", out["safety"])
        self.assertIn("Not a C2", out["safety"])


class PageTypeFilterTest(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(_page_type("https://x [200] [Login - Acme]"), "login")
        self.assertEqual(_page_type("http://y [200] [Just a moment...]"), "captcha")
        self.assertEqual(_page_type("http://z [200] [this domain is for sale]"), "parked")
        self.assertEqual(_page_type("http://a [200] [Admin Dashboard]"), "")


if __name__ == "__main__":
    unittest.main()
