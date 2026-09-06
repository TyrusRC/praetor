"""run_network_recon pipeline: discovery -> service routing -> enum -> leads.

Offline: nmap_scan and run_sanctioned are mocked so routing/lead/loot/coverage
logic is exercised deterministically without touching the network.
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock, patch

from praetor import server
from praetor.tools.network import _routing


def _tool():
    return server.mcp._tool_manager._tools["run_network_recon"].fn


def _scan(hosts, http=None):
    return {"ok": True, "error": "", "target": "10.0.0.5", "domain": "box",
            "parsed": {"hosts": hosts}, "inventory": {"hosts": hosts},
            "http_targets": http or [], "run_id": "op0001",
            "n_hosts": len(hosts), "n_ports": sum(len(h["ports"]) for h in hosts)}


def _host(ip, ports):
    return {"ip": ip, "hostnames": [], "ports": [
        {"port": p, "proto": "tcp", "state": "open", "service": s,
         "product": "", "version": "", "tunnel": ""} for p, s in ports]}


class TestRouting(unittest.TestCase):
    def test_smb_routes_smb_tools(self):
        steps = _routing.plans_for("microsoft-ds", 445, have_creds=False)
        self.assertTrue(any(s["tool"] == "nxc" for s in steps))

    def test_no_smb_no_smb_tools(self):
        self.assertEqual(_routing.plans_for("ssh", 22, have_creds=False), [])

    def test_cred_gated_steps_hidden_without_creds(self):
        no = _routing.plans_for("ldap", 389, have_creds=False)
        yes = _routing.plans_for("ldap", 389, have_creds=True)
        self.assertTrue(len(yes) > len(no))
        self.assertTrue(any(s["tool"] == "certipy" for s in yes))

    def test_nfs_smtp_snmp_chain_plans(self):
        self.assertTrue(any(s["tool"] == "showmount"
                            for s in _routing.plans_for("nfs", 2049, have_creds=False)))
        self.assertTrue(any(s["tool"] == "showmount"
                            for s in _routing.plans_for("rpcbind", 111, have_creds=False)))
        self.assertTrue(any(s["tool"] == "smtp-user-enum"
                            for s in _routing.plans_for("smtp", 25, have_creds=False)))
        snmp = _routing.plans_for("snmp", 161, have_creds=False)
        self.assertTrue(any(s["tool"] == "snmp-check" and s.get("needs") == "community"
                            for s in snmp))

    def test_lead_and_loot_extraction(self):
        out = "user@dom: $krb5asrep$23$user@DOM:aabb...\nsigning: False"
        leads = {l["type"] for l in _routing.extract_leads(out)}
        self.assertIn("asrep_hash", leads)
        self.assertIn("smb_signing_off", leads)
        loot = _routing.extract_loot(out)
        self.assertTrue(any(t == "asrep_hash" for t, _ in loot))


class TestPipeline(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / ".burp-intel").mkdir()
        self._cwd = mock.patch("pathlib.Path.cwd", return_value=self.root)
        self._cwd.start()

    def tearDown(self):
        self._cwd.stop()
        self._tmp.cleanup()

    async def test_routes_enum_and_extracts_leads(self):
        hosts = [_host("10.0.0.5", [(445, "microsoft-ds"), (88, "kerberos"), (22, "ssh")])]
        san = AsyncMock(return_value={
            "ok": True, "error": "", "oplog_id": "op0002", "rc": 0,
            "output": "[+] shares\n$krb5asrep$23$u@D:deadbeef", "output_path": "", "tool": "nxc", "target": "10.0.0.5"})
        with patch("praetor.tools.network.pipeline.nmap_scan",
                   new=AsyncMock(return_value=_scan(hosts, http=["http://10.0.0.5"]))), \
             patch("praetor.tools.network.pipeline.run_sanctioned", new=san):
            out = await _tool()("10.0.0.5", domain="box")
        self.assertIn("discovery: 1 hosts", out)
        self.assertIn("LEADS", out)
        self.assertIn("asrep_hash", out)
        self.assertIn("LOOT captured", out)          # hash auto-looted
        self.assertIn("http://10.0.0.5", out)         # web bridge surfaced
        # ssh (22) has no plan -> nxc only called for smb+kerberos services
        self.assertTrue(san.await_count >= 1)

    async def test_skip_covered_on_rerun(self):
        hosts = [_host("10.0.0.5", [(445, "microsoft-ds")])]
        san = AsyncMock(return_value={"ok": True, "error": "", "oplog_id": "op0002",
                                      "rc": 0, "output": "ok", "output_path": "", "tool": "nxc", "target": "10.0.0.5"})
        with patch("praetor.tools.network.pipeline.nmap_scan",
                   new=AsyncMock(return_value=_scan(hosts))), \
             patch("praetor.tools.network.pipeline.run_sanctioned", new=san):
            await _tool()("10.0.0.5", domain="box")
            first = san.await_count
            out2 = await _tool()("10.0.0.5", domain="box")
        self.assertEqual(san.await_count, first)      # nothing re-run
        self.assertIn("skipped (covered)", out2)

    async def test_snmp_community_chain(self):
        hosts = [_host("10.0.0.9", [(161, "snmp")])]
        outputs = {"onesixtyone": "10.0.0.9 [public] Linux box 5.15",
                   "snmp-check": "[*] System information"}

        async def fake_san(tool, args, *a, **k):
            return {"ok": True, "error": "", "oplog_id": "op0003", "rc": 0,
                    "output": outputs.get(tool, ""), "output_path": "",
                    "tool": tool, "target": "10.0.0.9"}
        san = AsyncMock(side_effect=fake_san)
        with patch("praetor.tools.network.pipeline.nmap_scan",
                   new=AsyncMock(return_value=_scan(hosts))), \
             patch("praetor.tools.network.pipeline.run_sanctioned", new=san):
            await _tool()("10.0.0.9", domain="box")
        called = [c.args[0] for c in san.await_args_list]
        self.assertIn("onesixtyone", called)
        self.assertIn("snmp-check", called)
        # snmp-check ran with the community captured from onesixtyone output
        chk = next(c for c in san.await_args_list if c.args[0] == "snmp-check")
        self.assertIn("-c public", chk.args[1])

    async def test_snmp_no_community_skips_check(self):
        hosts = [_host("10.0.0.9", [(161, "snmp")])]

        async def fake_san(tool, args, *a, **k):
            return {"ok": True, "error": "", "oplog_id": "op0003", "rc": 0,
                    "output": "", "output_path": "", "tool": tool, "target": "10.0.0.9"}
        san = AsyncMock(side_effect=fake_san)
        with patch("praetor.tools.network.pipeline.nmap_scan",
                   new=AsyncMock(return_value=_scan(hosts))), \
             patch("praetor.tools.network.pipeline.run_sanctioned", new=san):
            await _tool()("10.0.0.9", domain="box")
        called = [c.args[0] for c in san.await_args_list]
        self.assertIn("onesixtyone", called)
        self.assertNotIn("snmp-check", called)   # no community -> no blind run

    async def test_discovery_failure_reported(self):
        with patch("praetor.tools.network.pipeline.nmap_scan",
                   new=AsyncMock(return_value={"ok": False, "error": "nmap not installed"})):
            out = await _tool()("10.0.0.5", domain="box")
        self.assertIn("discovery failed", out)


if __name__ == "__main__":
    unittest.main()
