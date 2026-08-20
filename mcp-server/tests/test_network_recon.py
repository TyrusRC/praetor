"""Network recon lane: nmap parse, inventory persistence, web-lane bridge,
and the HARD safety/scope guards. All offline — a fixture XML stands in for a
live scan.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock, patch

from praetor import server
from praetor.tools.network._nmap_parse import (
    http_targets,
    is_http_service,
    parse_nmap_xml,
)

FIXTURE = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.10.11.5" addrtype="ipv4"/>
    <hostnames><hostname name="web01.htb"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2"/></port>
      <port protocol="tcp" portid="80"><state state="open"/>
        <service name="http" product="nginx" version="1.18"/></port>
      <port protocol="tcp" portid="443"><state state="open"/>
        <service name="http" product="nginx" tunnel="ssl"/></port>
      <port protocol="tcp" portid="445"><state state="open"/>
        <service name="microsoft-ds"/></port>
      <port protocol="tcp" portid="3306"><state state="closed"/>
        <service name="mysql"/></port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.10.11.6" addrtype="ipv4"/>
  </host>
</nmaprun>"""


class TestParser(unittest.TestCase):
    def test_up_host_open_ports_only(self):
        inv = parse_nmap_xml(FIXTURE)
        self.assertEqual(len(inv["hosts"]), 1)  # down host dropped
        host = inv["hosts"][0]
        self.assertEqual(host["ip"], "10.10.11.5")
        self.assertEqual(host["hostnames"], ["web01.htb"])
        ports = {p["port"] for p in host["ports"]}
        self.assertEqual(ports, {22, 80, 443, 445})  # 3306 closed -> dropped

    def test_http_detection(self):
        inv = parse_nmap_xml(FIXTURE)
        ports = {p["port"]: p for p in inv["hosts"][0]["ports"]}
        self.assertTrue(is_http_service(ports[80]))
        self.assertTrue(is_http_service(ports[443]))
        self.assertFalse(is_http_service(ports[22]))
        self.assertFalse(is_http_service(ports[445]))

    def test_web_bridge_urls(self):
        urls = http_targets(parse_nmap_xml(FIXTURE))
        self.assertIn("http://web01.htb", urls)          # port 80 default
        self.assertIn("https://web01.htb", urls)         # 443 tls -> https default
        self.assertNotIn("http://web01.htb:22", urls)

    def test_malformed_xml_raises(self):
        with self.assertRaises(ValueError):
            parse_nmap_xml("<nmaprun><host>")


def _tool(name):
    return server.mcp._tool_manager._tools[name].fn


class TestRunNmapGuards(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / ".burp-intel").mkdir()
        self._cwd = mock.patch("pathlib.Path.cwd", return_value=self.root)
        self._cwd.start()

    def tearDown(self):
        self._cwd.stop()
        self._tmp.cleanup()

    async def test_destructive_nse_refused(self):
        out = await _tool("run_nmap")("10.10.11.5", flags="--script dos")
        self.assertIn("refused", out)
        self.assertIn("HARD", out)

    async def test_brute_nse_refused(self):
        out = await _tool("run_nmap")("10.10.11.5", flags="--script brute")
        self.assertIn("refused", out)

    async def test_shell_metachar_target_rejected(self):
        out = await _tool("run_nmap")("10.10.11.5; rm -rf /")
        self.assertIn("illegal character", out)

    async def test_strict_mode_blocks(self):
        from praetor.tools import _scope_mode
        _scope_mode.set_mode("strict")
        try:
            out = await _tool("run_nmap")("10.10.11.5")
            self.assertIn("SCOPE (strict)", out)
        finally:
            _scope_mode.set_mode("operator")

    async def test_full_run_parses_persists_and_bridges(self):
        # operator mode (default). Mock the subprocess to return the fixture XML.
        with patch("praetor.tools.network.nmap._check_tool", return_value=True), \
             patch("praetor.tools.network.nmap._run_cmd",
                   new=AsyncMock(return_value=(FIXTURE, "", 0))):
            out = await _tool("run_nmap")("10.10.11.5", domain="box.htb")
        self.assertIn("1 hosts up", out)
        self.assertIn("web01.htb", out)
        self.assertIn("https://web01.htb", out)  # bridge present
        # Inventory persisted.
        inv = json.loads((self.root / ".burp-intel" / "box.htb" / "network.json").read_text())
        self.assertEqual(inv["hosts"][0]["ip"], "10.10.11.5")
        # Run recorded in the operator log (evidence) with ATT&CK auto-tag.
        oplog = (self.root / ".burp-intel" / "box.htb" / "network" / "oplog.jsonl").read_text()
        self.assertIn("nmap", oplog)
        self.assertIn("T1046", oplog)  # Network Service Discovery auto-mapped


if __name__ == "__main__":
    unittest.main()
