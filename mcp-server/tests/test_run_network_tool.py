"""run_network_tool: sanctioned runner + HARD guards + auto operator-log."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock, patch

from praetor import server
from praetor.tools.network.run_tool import _SANCTIONED
from praetor.tools.redteam._oplog import read_oplog


def _tool():
    return server.mcp._tool_manager._tools["run_network_tool"].fn


class TestRunNetworkTool(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / ".burp-intel").mkdir()
        self._cwd = mock.patch("pathlib.Path.cwd", return_value=self.root)
        self._cwd.start()

    def tearDown(self):
        self._cwd.stop()
        self._tmp.cleanup()

    async def test_unsanctioned_tool_refused(self):
        out = await _tool()("rm", "-rf /", domain="box")
        self.assertIn("REFUSED", out)

    async def test_online_brute_refused_rule6(self):
        out = await _tool()("hydra", "-l admin -P rockyou.txt ssh://10.0.0.1", domain="box")
        self.assertIn("Rule 6", out)

    async def test_destructive_args_refused(self):
        out = await _tool()("impacket-wmiexec", "DOM/u:p@10.0.0.1 'rm -rf /var'", domain="box")
        self.assertIn("REFUSED", out)

    async def test_sanctioned_run_logs_with_attack(self):
        with patch("praetor.tools.network.run_tool._check_tool", return_value=True), \
             patch("praetor.tools.network.run_tool._run_cmd",
                   new=AsyncMock(return_value=("[*] Dumping\naad3b...:31d6c...", "", 0))):
            out = await _tool()("impacket-secretsdump",
                                "DOM/u:p@10.0.0.5", domain="box.htb", target="10.0.0.5",
                                description="domain hash dump")
        self.assertIn("operator-log op", out)
        entries = read_oplog("box.htb")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["technique"], "T1003")  # secretsdump auto-map
        self.assertEqual(entries[0]["target"], "10.0.0.5")

    async def test_not_installed_points_to_guide(self):
        with patch("praetor.tools.network.run_tool._check_tool", return_value=False):
            out = await _tool()("netexec", "smb 10.0.0.1", domain="box")
        self.assertIn("not installed", out)
        self.assertIn("redteam_tool_guide", out)

    def test_new_recon_binaries_sanctioned(self):
        for b in ("showmount", "snmpwalk", "snmp-check", "smtp-user-enum"):
            self.assertIn(b, _SANCTIONED)

    async def test_new_binary_destructive_args_refused(self):
        # A newly-sanctioned binary still goes through validate_payload on the
        # full command line — a shell-injection / destructive tail is refused.
        out = await _tool()("showmount", "-e 10.0.0.1; rm -rf /var", domain="box")
        self.assertIn("REFUSED", out)
        self.assertIn("destructive", out)

    async def test_strict_scope_blocks_with_target(self):
        from praetor.tools import _scope_mode
        _scope_mode.set_mode("strict")
        try:
            with patch("praetor.tools.network.run_tool._check_tool", return_value=True):
                out = await _tool()("netexec", "smb 10.0.0.1", domain="box", target="10.0.0.1")
            self.assertIn("SCOPE (strict)", out)
        finally:
            _scope_mode.set_mode("operator")


if __name__ == "__main__":
    unittest.main()
