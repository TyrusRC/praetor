"""Reflection-liveness / sanitizer FP guard (2026-07-25 FP-reduction pass).

The #1 reflected-injection false positive: payload echoed back but ENCODED, so
it never executes. The assess gate must suppress a CONFIRMED for that case.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from burpsuite_mcp import server
from burpsuite_mcp.tools.advisor._liveness import reflection_liveness


class ReflectionLivenessUnit(unittest.TestCase):

    def test_raw_reflection_is_live(self):
        live, san = reflection_liveness(
            "q=<script>alert(1)</script>",
            "<html>hello <script>alert(1)</script> world</html>",
        )
        self.assertIn("<script", live)
        self.assertEqual(san, [])

    def test_html_encoded_reflection_is_sanitized(self):
        live, san = reflection_liveness(
            "q=<script>alert(1)</script>",
            "<html>hello &lt;script&gt;alert(1)&lt;/script&gt; world</html>",
        )
        self.assertEqual(live, [])
        self.assertIn("<script", san)

    def test_page_own_script_not_flagged(self):
        # Payload carried no dangerous token; the page's own <script> must not
        # register as live or sanitized.
        live, san = reflection_liveness(
            "q=hello",
            "<html><script>var app=1;</script></html>",
        )
        self.assertEqual(live, [])
        self.assertEqual(san, [])

    def test_js_unicode_escape_is_sanitized(self):
        # The tag-former <img is JS-\u-escaped → neutralized. A bare onerror=
        # echoed raw does not count as live (no live tag to host it).
        live, san = reflection_liveness(
            "name=<img src=x onerror=alert(1)>",
            'var n="\\u003cimg src=x onerror=alert(1)\\u003e";',
        )
        self.assertEqual(live, [])
        self.assertIn("<img", san)

    def test_attribute_breakout_is_live(self):
        live, san = reflection_liveness(
            'q="><svg onload=alert(1)>',
            '<input value="\"><svg onload=alert(1)>">',
        )
        self.assertTrue(live)


class ReflectionLivenessGate(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.assess = staticmethod(server.mcp._tool_manager._tools["assess_finding"].fn)
        cls.tmpdir = Path(tempfile.mkdtemp(prefix="burp-intel-liveness-"))
        cls.original_cwd = Path.cwd()
        os.chdir(cls.tmpdir)

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.original_cwd)
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    async def _call(self, detail: dict, **kwargs) -> str:
        async def fake_post(path, json=None):
            return {"in_scope": True}
        async def fake_get(path, params=None):
            if "proxy/history" in path:
                return detail
            return {}
        with patch("burpsuite_mcp.client.post", fake_post), \
             patch("burpsuite_mcp.client.get", fake_get):
            return await self.assess(**kwargs)

    async def test_encoded_reflection_suppressed(self):
        detail = {
            "url": "https://ex.com/search?q=<script>alert(1)</script>",
            "request_body": "",
            "status_code": 200,
            "response_headers": [],
            "response_body": "<html>results for &lt;script&gt;alert(1)&lt;/script&gt;</html>",
        }
        out = await self._call(
            detail,
            vuln_type="xss",
            endpoint="/search",
            parameter="q",
            evidence="payload reflected in response, alert( in output",
            domain="ex.com",
            logger_index=5,
        )
        self.assertIn("Q5 SANITIZED", out)

    async def test_live_reflection_not_suppressed(self):
        detail = {
            "url": "https://ex.com/search?q=<script>alert(1)</script>",
            "request_body": "",
            "status_code": 200,
            "response_headers": [],
            "response_body": "<html>results for <script>alert(1)</script></html>",
        }
        out = await self._call(
            detail,
            vuln_type="xss",
            endpoint="/search",
            parameter="q",
            evidence="payload reflected in executable context, alert( executed",
            domain="ex.com",
            logger_index=6,
        )
        self.assertNotIn("Q5 SANITIZED", out)


if __name__ == "__main__":
    unittest.main()
