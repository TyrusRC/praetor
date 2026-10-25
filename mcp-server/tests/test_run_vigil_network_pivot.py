"""run_vigil(auto_network_check=True) — the network/TLS pivot addition.

Gap: web-scan tools never auto-triggered a port/TLS check of the underlying
host; the operator had to invoke the network lane manually. This is the
orchestration glue (no new detection logic) that closes it, opt-in."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from praetor.tools.recon.scanning.vuln_scan._g1 import _network_pivot, register


class _ToolCapture:
    def __init__(self):
        self.tools = {}

    def tool(self, *a, **k):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


class NetworkPivotHelperTest(unittest.IsolatedAsyncioTestCase):
    """_network_pivot in isolation — host derivation + fail-open behavior."""

    async def test_derives_host_from_full_url(self):
        with patch("praetor.tools.network.nmap.nmap_scan", return_value={"ok": True, "target": "h",
                   "n_hosts": 0, "n_ports": 0, "parsed": {}, "http_targets": []}) as nm, \
             patch("praetor.tools.recon_pd._impl.run_tlsx", return_value="tlsx ok"):
            await _network_pivot("https://example.com:8443/path?x=1", "")
        self.assertEqual(nm.call_args.args[0], "example.com")

    async def test_bare_host_without_scheme(self):
        with patch("praetor.tools.network.nmap.nmap_scan", return_value={"ok": True, "target": "h",
                   "n_hosts": 0, "n_ports": 0, "parsed": {}, "http_targets": []}) as nm, \
             patch("praetor.tools.recon_pd._impl.run_tlsx", return_value="tlsx ok"):
            await _network_pivot("example.com", "")
        self.assertEqual(nm.call_args.args[0], "example.com")

    async def test_nmap_error_does_not_raise_or_block_tlsx(self):
        with patch("praetor.tools.network.nmap.nmap_scan", side_effect=RuntimeError("boom")), \
             patch("praetor.tools.recon_pd._impl.run_tlsx", return_value="tlsx ok") as tx:
            out = await _network_pivot("https://example.com", "")
        self.assertIn("nmap pivot error", out)
        self.assertIn("tlsx ok", out)
        tx.assert_called_once()

    async def test_tlsx_error_does_not_raise(self):
        with patch("praetor.tools.network.nmap.nmap_scan", return_value={"ok": True, "target": "h",
                   "n_hosts": 0, "n_ports": 0, "parsed": {}, "http_targets": []}), \
             patch("praetor.tools.recon_pd._impl.run_tlsx", side_effect=RuntimeError("boom")):
            out = await _network_pivot("https://example.com", "")
        self.assertIn("tlsx pivot error", out)


class RunVigilAutoNetworkCheckTest(unittest.IsolatedAsyncioTestCase):
    """The run_vigil wiring: off by default, appended only when requested."""

    def setUp(self):
        cap = _ToolCapture()
        register(cap)
        self.run_vigil = cap.tools["run_vigil"]
        self.fake_report = json.dumps({"scan_result": {"findings": [
            {"severity": "high", "title": "XSS", "url": "https://example.com/x"}]}})

    async def test_off_by_default_no_pivot_section(self):
        with patch("praetor.tools.recon.scanning.vuln_scan._g1._check_tool", return_value=True), \
             patch("praetor.tools.recon.scanning.vuln_scan._g1._run_cmd",
                   return_value=(self.fake_report, "", 0)):
            out = await self.run_vigil("https://example.com")
        self.assertNotIn("Network/TLS pivot", out)

    async def test_enabled_appends_pivot_section(self):
        with patch("praetor.tools.recon.scanning.vuln_scan._g1._check_tool", return_value=True), \
             patch("praetor.tools.recon.scanning.vuln_scan._g1._run_cmd",
                   return_value=(self.fake_report, "", 0)), \
             patch("praetor.tools.network.nmap.nmap_scan", return_value={"ok": True, "target": "h",
                   "n_hosts": 1, "n_ports": 2, "parsed": {}, "http_targets": []}), \
             patch("praetor.tools.recon_pd._impl.run_tlsx", return_value="tlsx: TLS 1.3, no issues"):
            out = await self.run_vigil("https://example.com", auto_network_check=True)
        self.assertIn("Network/TLS pivot: example.com", out)
        self.assertIn("tlsx: TLS 1.3", out)
        self.assertIn("XSS", out)  # the original web-scan result is still present


if __name__ == "__main__":
    unittest.main()
