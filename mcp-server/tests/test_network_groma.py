"""Network lane: run_groma (groma JSON parse, inventory persistence,
web-lane bridge, HARD safety/scope guards). All offline — a fixture JSON
report stands in for a live scan, same pattern as test_network_recon.py's
run_nmap coverage.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock, patch

from praetor import server
from praetor.tools.network.groma import _groma_to_inventory, _vuln_findings

FIXTURE = {
    "version": "1.0.0",
    "tool": "groma",
    "targets": ["10.10.11.5"],
    "duration_ms": 1200,
    "findings": [
        {"id": "a", "type": "open_port", "severity": "info", "host": "10.10.11.5",
         "port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH",
         "version": "9.6", "title": "Port 22/tcp open (OpenSSH 9.6)"},
        {"id": "b", "type": "open_port", "severity": "info", "host": "10.10.11.5",
         "port": 80, "protocol": "tcp", "service": "http", "product": "nginx",
         "version": "1.18", "title": "Port 80/tcp open (nginx 1.18)"},
        {"id": "c", "type": "CVE-2021-41773", "severity": "critical", "host": "10.10.11.5",
         "port": 80, "protocol": "tcp", "title": "Apache path traversal / RCE",
         "evidence": "Observed apache 2.4.50 on port 80/tcp", "cwe": ["CWE-22"]},
    ],
    "summary": {"total_findings": 3, "critical": 1, "info": 2},
}


class TestGromaConversion(unittest.TestCase):
    def test_groma_to_inventory_keeps_only_open_port_rows(self):
        inv = _groma_to_inventory("10.10.11.5", FIXTURE)
        self.assertEqual(len(inv["hosts"]), 1)
        host = inv["hosts"][0]
        self.assertEqual(host["ip"], "10.10.11.5")
        ports = {p["port"]: p for p in host["ports"]}
        self.assertEqual(set(ports), {22, 80})
        self.assertEqual(ports[80]["product"], "nginx")
        self.assertEqual(ports[80]["version"], "1.18")

    def test_groma_to_inventory_empty_when_no_open_ports(self):
        inv = _groma_to_inventory("10.10.11.5", {"findings": []})
        self.assertEqual(inv["hosts"], [])

    def test_vuln_findings_drops_open_port_type(self):
        vuln = _vuln_findings(FIXTURE)
        self.assertEqual(len(vuln), 1)
        self.assertEqual(vuln[0]["type"], "CVE-2021-41773")


def _tool(name):
    return server.mcp._tool_manager._tools[name].fn


class TestRunGromaGuards(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / ".burp-intel").mkdir()
        self._cwd = mock.patch("pathlib.Path.cwd", return_value=self.root)
        self._cwd.start()

    def tearDown(self):
        self._cwd.stop()
        self._tmp.cleanup()

    async def test_shell_metachar_target_rejected(self):
        out = await _tool("run_groma")("10.10.11.5; rm -rf /")
        self.assertIn("illegal character", out)

    async def test_strict_mode_blocks(self):
        from praetor.tools import _scope_mode
        _scope_mode.set_mode("strict")
        try:
            out = await _tool("run_groma")("10.10.11.5")
            self.assertIn("SCOPE (strict)", out)
        finally:
            _scope_mode.set_mode("operator")

    async def test_not_installed_hint(self):
        with patch("praetor.tools.network.groma._check_tool", return_value=False):
            out = await _tool("run_groma")("10.10.11.5")
        self.assertIn("groma not installed", out)

    async def test_full_run_parses_persists_and_bridges(self):
        with patch("praetor.tools.network.groma._check_tool", return_value=True), \
             patch("praetor.tools.network.groma._run_cmd",
                   new=AsyncMock(return_value=(json.dumps(FIXTURE), "", 0))):
            out = await _tool("run_groma")("10.10.11.5", domain="box.htb",
                                            checks_dir="/opt/checks")
        self.assertIn("2 open port", out)
        self.assertIn("1 check finding", out)
        self.assertIn("Apache path traversal", out)
        self.assertIn("import_scan_results", out)  # leads, not auto-saved

        inv = json.loads((self.root / ".burp-intel" / "box.htb" / "network.json").read_text())
        self.assertEqual(inv["hosts"][0]["ip"], "10.10.11.5")
        self.assertEqual({p["port"] for p in inv["hosts"][0]["ports"]}, {22, 80})

        oplog = (self.root / ".burp-intel" / "box.htb" / "network" / "oplog.jsonl").read_text()
        self.assertIn("groma", oplog)

    async def test_no_output_is_an_error_not_a_silent_empty_result(self):
        with patch("praetor.tools.network.groma._check_tool", return_value=True), \
             patch("praetor.tools.network.groma._run_cmd",
                   new=AsyncMock(return_value=("", "connection refused", 1))):
            out = await _tool("run_groma")("10.10.11.5")
        self.assertIn("groma:", out)
        self.assertIn("connection refused", out)


if __name__ == "__main__":
    unittest.main()
