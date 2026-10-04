"""Engagement HTML view — the dsh-flow-style additions.

Covers the pieces that can silently break: the Flow/Force layout toggle + dagre
CDN, the header count chips, the tab counts, the dedicated Assets tab/tree, and
that no CJK leaks into the English-only UI.
"""

import re
import unittest

from praetor.tools.intel import _engagement as E
from praetor.tools.intel._engagement_html import render_engagement_html


def _sample():
    g = E.new_graph("testasp.vulnweb.com", "find one confirmed vuln", "authorized target")
    i1 = E.add_intent(g, "map surface + confirm a vuln")
    E.add_fact(g, "homepage HTTP 200; Server: Microsoft-IIS", i1)
    E.add_fact(g, "showforum.asp?id= reachable", i1)
    a1 = E.add_asset(g, "testasp.vulnweb.com", "host")
    E.add_asset(g, "/showforum.asp", "endpoint", a1)       # nested under the host
    E.add_finding(g, "f001", "showforum.asp?id numeric SQLi", i1,
                  assets=[a1], severity="high", repro=["id=1", "id=2-1"])
    return g


class EngagementHtmlTest(unittest.TestCase):

    def setUp(self):
        self.html = render_engagement_html("testasp.vulnweb.com", _sample())

    def test_layout_toggle_and_dagre(self):
        self.assertIn('data-layout="flow"', self.html)
        self.assertIn('data-layout="force"', self.html)
        self.assertIn("cytoscape-dagre", self.html)   # LR flow layout available

    def test_header_count_chips(self):
        self.assertIn('class="chips"', self.html)
        self.assertIn("Facts <b>2</b>", self.html)
        self.assertIn("Findings <b>1</b>", self.html)
        self.assertIn("Assets <b>2</b>", self.html)

    def test_tab_counts(self):
        self.assertIn('Findings <span class="cnt">(1)</span>', self.html)
        self.assertIn('Assets <span class="cnt">(2)</span>', self.html)

    def test_assets_tab_and_tree(self):
        self.assertIn('data-tab="assets"', self.html)
        self.assertIn('id="panel-assets"', self.html)
        self.assertIn("asset-tree", self.html)
        self.assertIn("/showforum.asp", self.html)     # nested endpoint rendered

    def test_no_cjk_in_english_ui(self):
        self.assertIsNone(re.search(r"[一-鿿]", self.html))

    def test_findings_still_render(self):
        self.assertIn("numeric SQLi", self.html)
        self.assertIn('data-tab="findings"', self.html)


if __name__ == "__main__":
    unittest.main()
