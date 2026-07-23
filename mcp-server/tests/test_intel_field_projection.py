"""E1.1 — load_target_intel(findings, fields=...) token-lean projection."""
import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from burpsuite_mcp.tools.intel import save_load

HEAVY_FINDING = {
    "id": "VULN-1", "title": "SQLi in id", "severity": "high", "status": "confirmed",
    "endpoint": "https://x.test/api", "vuln_type": "sqli",
    "poc_request": "GET /api?id=1'--" * 50,
    "evidence": {"logger_index": 9, "blob": "x" * 2000},
    "reproductions": [{"logger_index": 9}, {"logger_index": 10}],
    "description": "long " * 200, "remediation": "fix " * 100,
}


class FieldProjectionTest(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp()
        os.chdir(self._tmp)
        d = Path(".burp-intel/x.test")
        d.mkdir(parents=True)
        (d / "findings.json").write_text(json.dumps({"findings": [HEAVY_FINDING]}))
        mcp = FastMCP("t")
        save_load.register(mcp)
        self.load = mcp._tool_manager.get_tool("load_target_intel").fn

    def tearDown(self):
        os.chdir(self._cwd)

    def test_projection_drops_heavy_fields(self):
        out = asyncio.run(self.load("x.test", category="findings",
                                    fields="id,title,severity,status,endpoint,vuln_type"))
        data = json.loads(out)
        f = data["findings"][0]
        self.assertEqual(set(f.keys()),
                         {"id", "title", "severity", "status", "endpoint", "vuln_type"})
        self.assertNotIn("poc_request", f)
        self.assertNotIn("evidence", f)
        self.assertLess(len(out), 600, "projected payload should be small")

    def test_full_load_keeps_heavy_fields(self):
        out = asyncio.run(self.load("x.test", category="findings"))
        f = json.loads(out)["findings"][0]
        self.assertIn("poc_request", f)
        self.assertIn("evidence", f)


if __name__ == "__main__":
    unittest.main()
