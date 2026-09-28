"""Attack-path map section + Markdown->HTML report export with mermaid.js."""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from praetor.tools.report._attack_map import build_attack_map_section
from praetor.tools.report._html import markdown_to_html, wrap_html


class MarkdownToHtmlTest(unittest.TestCase):

    def test_headings_bold_code(self):
        h = markdown_to_html("# Title\n\nSome **bold** and `code`.")
        self.assertIn("<h1>Title</h1>", h)
        self.assertIn("<strong>bold</strong>", h)
        self.assertIn("<code>code</code>", h)

    def test_mermaid_fence_becomes_div(self):
        h = markdown_to_html("```mermaid\nflowchart LR\n  A-->B\n```")
        self.assertIn('<div class="mermaid">', h)
        self.assertIn("A-->B", h)                 # raw mermaid preserved, not escaped
        self.assertNotIn("<code>", h)

    def test_plain_code_fence_is_escaped(self):
        h = markdown_to_html("```\n<script>alert(1)</script>\n```")
        self.assertIn("<pre><code>", h)
        self.assertIn("&lt;script&gt;", h)        # payload shown, never executes

    def test_table(self):
        h = markdown_to_html("| A | B |\n|---|---|\n| 1 | 2 |")
        self.assertIn("<table>", h)
        self.assertIn("<th>A</th>", h)
        self.assertIn("<td>1</td>", h)

    def test_lists(self):
        self.assertIn("<ul><li>one</li><li>two</li></ul>", markdown_to_html("- one\n- two"))
        self.assertIn("<ol><li>first</li></ol>", markdown_to_html("1. first"))

    def test_inline_evidence_is_escaped(self):
        h = markdown_to_html("Payload: `<img src=x onerror=alert(1)>` reflected.")
        self.assertIn("&lt;img", h)

    def test_wrap_includes_mermaid_js(self):
        doc = wrap_html("T", "<h1>x</h1>")
        self.assertIn("<!doctype html>", doc)
        self.assertIn("mermaid.min.js", doc)
        self.assertIn("mermaid.initialize", doc)


class AttackMapSectionTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="amap-"))
        self.prev = Path.cwd()
        os.chdir(self.tmp)
        self.dom = self.tmp / ".burp-intel" / "t.example"
        self.dom.mkdir(parents=True)

    def tearDown(self):
        os.chdir(self.prev)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, findings):
        (self.dom / "findings.json").write_text(json.dumps({"findings": findings}))

    async def test_ssrf_maps_to_cloud_creds(self):
        self._write([{"id": "f001", "vuln_type": "ssrf", "severity": "high",
                      "status": "confirmed", "title": "SSRF", "endpoint": "https://t/x",
                      "impact": "internal", "evidence": {"proxy_history_index": 5}}])
        sec = await build_attack_map_section("t.example")
        self.assertIn("## Attack Path Map & Next Steps", sec)
        self.assertIn("```mermaid", sec)
        self.assertIn("Cloud IAM credential theft", sec)
        self.assertIn("Next steps", sec)

    async def test_empty_when_nothing_escalates(self):
        self._write([{"id": "f001", "vuln_type": "missing_headers", "severity": "low",
                      "status": "confirmed", "evidence": {"proxy_history_index": 1}}])
        self.assertEqual(await build_attack_map_section("t.example"), "")


if __name__ == "__main__":
    unittest.main()
