"""build_engagement_checklist — scoped combined checklist markdown."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from praetor.tools.assurance._checklists.engagement import (
    _norm_scope, _scoped_kb, _standards_for, render_engagement_md,
)


class ScopeMappingTest(unittest.TestCase):

    def test_web_gets_top10_and_wstg(self):
        self.assertEqual(_standards_for(["web"]), ["owasp_top10", "wstg"])

    def test_mobile_adds_mastg(self):
        self.assertIn("mastg", _standards_for(["web", "mobile"]))

    def test_api_and_llm(self):
        self.assertIn("api_top10", _standards_for(["api"]))
        self.assertIn("ai_testing", _standards_for(["llm"]))

    def test_norm_scope_parses_and_defaults(self):
        self.assertEqual(_norm_scope("web, mobile"), ["web", "mobile"])
        self.assertEqual(_norm_scope(""), ["web"])

    def test_kb_edge_cases_scoped(self):
        # mobile-only excludes generic web classes; web includes them, not mobile ones.
        web = _scoped_kb(["web"])
        mob = _scoped_kb(["mobile"])
        self.assertIn("sqli", web)
        self.assertNotIn("sqli", mob)
        self.assertIn("mobile_deeplink", mob)
        self.assertNotIn("mobile_deeplink", web)


class RenderTest(unittest.TestCase):

    def test_web_markdown_has_all_sections(self):
        md = render_engagement_md("t.example", ["web"])
        self.assertIn("# Pentest Checklist — t.example", md)
        self.assertIn("OWASP Top 10 (2025)", md)
        self.assertIn("OWASP WSTG v4.2", md)
        self.assertIn("knowledge-base test classes", md)
        self.assertIn("WSTG-INFO-01", md)          # a real WSTG item rendered
        self.assertIn("A01-1", md)                  # OWASP Top 10 test case rendered
        self.assertIn("A05-1", md)                  # (was missing before the catalog fix)
        self.assertIn("auto_probe(categories=['sqli'])", md)

    def test_api_scope_renders_api_top10_cases(self):
        md = render_engagement_md("t.example", ["api"])
        self.assertIn("OWASP API Security Top 10 (2023)", md)
        self.assertIn("API1-1", md)                 # BOLA
        self.assertIn("API7-1", md)                 # SSRF — API top-10 items now present

    def test_mobile_scope_includes_masvs(self):
        md = render_engagement_md("t.example", ["mobile"])
        self.assertIn("MASVS", md)
        self.assertNotIn("WSTG-INFO-01", md)        # web-only standard excluded


class ToolWriteTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="chk-"))
        self.prev = Path.cwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.prev)
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_writes_file(self):
        from praetor import server
        fn = server.mcp._tool_manager._tools["build_engagement_checklist"].fn
        out = await fn(domain="t.example", scope="web mobile")
        self.assertIn("-checklist.md", out)
        written = self.tmp / ".burp-intel" / "t.example" / "reports" / "t.example-checklist.md"
        self.assertTrue(written.exists())
        self.assertIn("MASVS", written.read_text())


if __name__ == "__main__":
    unittest.main()
