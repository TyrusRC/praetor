"""Engagement-graph MCP tool layer — persistence, finding enrichment, guards."""

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from praetor.tools.intel import engagement


class _FakeMCP:
    """Captures @mcp.tool()-registered coroutines by name."""
    def __init__(self):
        self.tools = {}

    def tool(self, *a, **k):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


class EngagementToolsTest(unittest.TestCase):
    def setUp(self):
        self.mcp = _FakeMCP()
        engagement.register(self.mcp)
        self.tmp = tempfile.mkdtemp()
        self._cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self._cwd)

    def _call(self, _tool, **kw):
        return asyncio.run(self.mcp.tools[_tool](**kw))

    def test_guard_before_goal(self):
        out = self._call("record_intent", domain="x.tld", title="poke")
        self.assertIn("record_goal first", out)

    def test_full_flow_persists_and_links_finding(self):
        dom = "acme.tld"
        # seed a saved finding the way findings.json stores it
        fdir = Path(self.tmp) / ".burp-intel" / "acme.tld"
        fdir.mkdir(parents=True)
        (fdir / "findings.json").write_text(json.dumps([{
            "id": "f007", "title": "IDOR on /orders", "severity": "high",
            "reproduction_steps": ["GET /orders/1001 as user B"],
        }]))

        self._call("record_goal", domain=dom, target="acme.tld",
                   objective="prove IDOR", authorization="SOW-9")
        i1 = self._call("record_intent", domain=dom, title="enumerate order ids")
        self.assertTrue(i1.startswith("intent-1"))
        self._call("record_fact", domain=dom, text="order_id is sequential", intent="intent-1")
        self._call("record_asset", domain=dom, name="/api/orders", atype="endpoint")
        linked = self._call("link_finding", domain=dom, finding_id="f007",
                            intent="intent-1", assets=["asset-1"])
        self.assertIn("finding-1", linked)
        self.assertIn("high", linked)                 # severity pulled from findings.json

        # persisted
        graph = json.loads((fdir / "engagement.json").read_text())
        self.assertEqual(graph["goal"]["authorization"], "SOW-9")
        self.assertEqual(graph["nodes"]["finding-1"]["finding_id"], "f007")

        # dsh replay carries the real repro step (dsh requires >=1)
        dsh = json.loads(self._call("engagement_graph", domain=dom, format="dsh"))
        add_find = [c for c in dsh if c["tool"] == "pentest_add_finding"][0]
        self.assertEqual(add_find["args"]["reproducibleSteps"], ["GET /orders/1001 as user B"])

    def test_link_unknown_finding_warns(self):
        dom = "b.tld"
        self._call("record_goal", domain=dom, target="b.tld", objective="o")
        self._call("record_intent", domain=dom, title="t")
        out = self._call("link_finding", domain=dom, finding_id="fZZ", intent="intent-1")
        self.assertIn("not found in findings.json", out)


if __name__ == "__main__":
    unittest.main()
