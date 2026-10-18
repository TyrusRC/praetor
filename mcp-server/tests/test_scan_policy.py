"""save_scan_policy / get_scan_policy / list_scan_policies / delete_scan_policy,
and run_assay(policy=...) consuming a saved policy.

Gap vs a commercial scanner's named scan profiles: run_assay's profile= was a
single enum per call with no way to save a reusable {profile, scope_host,
rate, templates, auto_network_check, timeout} bundle and reference it by name
across targets/engagements."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from praetor.tools.recon.scanning.vuln_scan import register
from praetor.tools.recon.scanning.vuln_scan.scan_policy import load_scan_policy


class _ToolCapture:
    def __init__(self):
        self.tools = {}

    def tool(self, *a, **k):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


class ScanPolicyTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="scan-policy-"))
        self.cwd = Path.cwd()
        os.chdir(self.tmpdir)
        cap = _ToolCapture()
        register(cap)
        self.tools = cap.tools

    def tearDown(self):
        os.chdir(self.cwd)
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    async def test_save_then_get_roundtrips(self):
        out = await self.tools["save_scan_policy"](
            "pci-quarterly", profile="thorough", scope_host="app.example.com",
            rate=5.0, auto_network_check=True, notes="quarterly PCI")
        self.assertIn("scan policy saved: pci-quarterly", out)
        self.assertIn("policy='pci-quarterly'", out)
        got = json.loads(await self.tools["get_scan_policy"]("pci-quarterly"))
        self.assertEqual(got["profile"], "thorough")
        self.assertEqual(got["scope_host"], "app.example.com")
        self.assertEqual(got["rate"], 5.0)
        self.assertTrue(got["auto_network_check"])

    async def test_invalid_profile_rejected(self):
        out = await self.tools["save_scan_policy"]("x", profile="bogus")
        self.assertIn("profile must be one of", out)
        self.assertEqual(load_scan_policy("x"), {})

    async def test_get_missing_policy(self):
        out = await self.tools["get_scan_policy"]("nope")
        self.assertIn("no scan policy named", out)

    async def test_list_empty_then_populated(self):
        out = await self.tools["list_scan_policies"]()
        self.assertIn("no scan policies saved yet", out)
        await self.tools["save_scan_policy"]("quick-check", profile="quick")
        await self.tools["save_scan_policy"]("full-recheck", profile="thorough",
                                             notes="post-release")
        out = await self.tools["list_scan_policies"]()
        self.assertIn("quick-check", out)
        self.assertIn("full-recheck", out)
        self.assertIn("post-release", out)

    async def test_delete_policy(self):
        await self.tools["save_scan_policy"]("temp", profile="quick")
        out = await self.tools["delete_scan_policy"]("temp")
        self.assertIn("deleted scan policy", out)
        self.assertEqual(load_scan_policy("temp"), {})
        out2 = await self.tools["delete_scan_policy"]("temp")
        self.assertIn("no scan policy named", out2)

    async def test_name_is_slugified_safely(self):
        from praetor.tools.recon.scanning.vuln_scan.scan_policy import _policies_dir
        await self.tools["save_scan_policy"]("Weird Name!!/../etc", profile="quick")
        policies_dir = _policies_dir().resolve()
        written = list(policies_dir.glob("*.json"))
        self.assertEqual(len(written), 1)
        # The real safety property: the file landed INSIDE the policies dir,
        # not escaped via traversal — '/' is stripped so no path separator
        # survives into the slug, however many '.' or '..' characters remain
        # as plain (non-separator) characters in the one flat filename.
        self.assertEqual(written[0].resolve().parent, policies_dir)


class RunAssayPolicyWiringTest(unittest.IsolatedAsyncioTestCase):
    """run_assay(policy=...) pulls its settings from the saved policy."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="scan-policy-run-"))
        self.cwd = Path.cwd()
        os.chdir(self.tmpdir)
        cap = _ToolCapture()
        register(cap)
        self.tools = cap.tools
        self.fake_report = json.dumps({"scan_result": {"findings": [
            {"severity": "high", "title": "XSS", "url": "https://t/x"}]}})

    def tearDown(self):
        os.chdir(self.cwd)
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    async def test_unknown_policy_name_errors_cleanly(self):
        out = await self.tools["run_assay"]("https://t", policy="nope")
        self.assertIn("no scan policy named", out)

    async def test_policy_values_drive_the_scan(self):
        await self.tools["save_scan_policy"]("net-pivot", profile="thorough",
                                             auto_network_check=True, rate=2.0)
        captured_cmd = {}

        async def fake_run_cmd(cmd, timeout, bypass_proxy=False):
            captured_cmd["cmd"] = cmd
            return (self.fake_report, "", 0)

        with patch("praetor.tools.recon.scanning.vuln_scan._g1._check_tool", return_value=True), \
             patch("praetor.tools.recon.scanning.vuln_scan._g1._run_cmd", fake_run_cmd), \
             patch("praetor.tools.network.nmap.nmap_scan", return_value={"ok": True, "target": "h",
                   "n_hosts": 1, "n_ports": 1, "parsed": {}, "http_targets": []}), \
             patch("praetor.tools.recon_pd._impl.run_tlsx", return_value="tlsx: ok"):
            out = await self.tools["run_assay"]("https://t")
            out_with_policy = await self.tools["run_assay"]("https://t", policy="net-pivot")

        # Without the policy: no network pivot (default auto_network_check=False).
        self.assertNotIn("Network/TLS pivot", out)
        # With the policy: thorough profile + rate 2.0 passed to assay, and the
        # network pivot ran even though the call itself never set those flags.
        self.assertIn("Network/TLS pivot", out_with_policy)
        self.assertIn("--profile", captured_cmd["cmd"])
        self.assertIn("thorough", captured_cmd["cmd"])
        self.assertIn("--rate", captured_cmd["cmd"])
        self.assertIn("2.0", captured_cmd["cmd"])


if __name__ == "__main__":
    unittest.main()
