"""External-tool run ledger (_tool_ledger.py) — secret-safe, fail-open.

Answers "did this CLI tool run against this target?" so no recon/scan lane is
silently skipped (Rules 19 / 19a). The oplog tool-call ledger times MCP calls
but drops args, so it cannot answer the target question — this one can.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from praetor.tools import _tool_ledger as L


class TargetExtractionTest(unittest.TestCase):
    def test_url_target_normalised_to_host(self):
        self.assertEqual(
            L._targets_from_argv(["sqlmap", "-u", "https://Shop.Example.COM/item?id=1"]),
            ["shop.example.com"],
        )

    def test_bare_host_and_ip(self):
        self.assertEqual(
            L._targets_from_argv(["nmap", "-p", "80,443", "scanme.example.org", "10.0.0.5"]),
            ["scanme.example.org", "10.0.0.5"],
        )

    def test_url_userinfo_stripped(self):
        # user:pass@host — the password must NOT survive; only the host.
        self.assertEqual(
            L._targets_from_argv(["curl", "https://admin:S3cret!@target.example.net/x"]),
            ["target.example.net"],
        )

    def test_credential_values_never_stored(self):
        argv = ["sqlmap", "-u", "https://t.example.com/", "-H", "Authorization: Bearer eyJabc.def.ghi",
                "--password", "Summer2024!", "--cookie", "session=deadbeef", "--token", "sk-live-9f2a"]
        self.assertEqual(L._targets_from_argv(argv), ["t.example.com"])

    def test_flags_paths_versions_not_targets(self):
        argv = ["nuclei", "-o", "/tmp/out.json", "-severity", "high",
                "-t", "cves/", "--version", "3.1.2", "-u", "https://host.example.io"]
        self.assertEqual(L._targets_from_argv(argv), ["host.example.io"])

    def test_dedup_preserves_order(self):
        argv = ["httpx", "https://a.example.com", "https://a.example.com", "https://b.example.com"]
        self.assertEqual(L._targets_from_argv(argv), ["a.example.com", "b.example.com"])

    def test_key_value_flag_form(self):
        self.assertEqual(
            L._targets_from_argv(["x", "--url=https://kv.example.com/path"]),
            ["kv.example.com"],
        )


class GapsComputationTest(unittest.TestCase):
    def test_active_lanes_report_unrun_tools(self):
        runs = [
            {"tool": "vigil", "targets": ["t.example.com"]},
            {"tool": "subfinder", "targets": ["t.example.com"]},
        ]
        g = L.compute_gaps("t.example.com", runs)
        # recon + web-scan are always active
        self.assertTrue(g["lanes"]["web-scan"]["active"])
        self.assertTrue(g["lanes"]["recon"]["active"])
        self.assertIn("vigil", g["lanes"]["web-scan"]["ran"])
        self.assertIn("subfinder", g["lanes"]["recon"]["ran"])
        # sqlmap never ran -> it is a web-scan gap
        self.assertIn("web-scan/sqlmap", g["gaps"])
        # network lane never touched -> inactive, NOT a gap
        self.assertFalse(g["lanes"]["network"]["active"])
        self.assertNotIn("network/nmap", g["gaps"])

    def test_network_lane_becomes_active_once_a_tool_runs(self):
        runs = [{"tool": "nmap", "targets": ["10.0.0.5"]}]
        g = L.compute_gaps("10.0.0.5", runs)
        self.assertTrue(g["lanes"]["network"]["active"])
        self.assertIn("network/groma", g["gaps"])  # groma still unrun in now-active lane

    def test_domain_matching_subdomain_and_parent(self):
        runs = [{"tool": "nuclei", "targets": ["api.t.example.com"]}]
        g = L.compute_gaps("t.example.com", runs)
        # subdomain run credits the parent domain
        self.assertIn("nuclei", g["lanes"]["recon"]["ran"])

    def test_unrelated_target_does_not_credit(self):
        runs = [{"tool": "sqlmap", "targets": ["other.example.org"]}]
        g = L.compute_gaps("t.example.com", runs)
        self.assertNotIn("sqlmap", g["lanes"]["web-scan"]["ran"])
        self.assertIn("web-scan/sqlmap", g["gaps"])

    def test_equivalent_tools_credit_the_group(self):
        runs = [{"tool": "netexec", "targets": ["10.0.0.9"]}]
        g = L.compute_gaps("10.0.0.9", runs)
        # netexec satisfies the nxc roster slot
        self.assertNotIn("network/nxc", g["gaps"])


class RecordReadRoundTripTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._cwd = os.getcwd()
        os.chdir(self.tmp)
        os.environ.pop("PRAETOR_TOOLLOG", None)

    def tearDown(self):
        os.chdir(self._cwd)
        os.environ.pop("PRAETOR_TOOLLOG", None)

    def test_round_trip(self):
        L.record_run(["sqlmap", "-u", "https://t.example.com/x?id=1"])
        L.record_run(["nmap", "10.0.0.5"])
        runs = L.read_runs()
        self.assertEqual(len(runs), 2)
        tools = {r["tool"] for r in runs}
        self.assertEqual(tools, {"sqlmap", "nmap"})
        # stored line is secret-free: only ts / tool / targets
        for r in runs:
            self.assertEqual(set(r), {"ts", "tool", "targets"})

    def test_explicit_tool_name_override(self):
        L.record_run(["python3", "/tmp/exploit.py", "https://t.example.com"], tool="pyexploit")
        runs = L.read_runs()
        self.assertEqual(runs[0]["tool"], "pyexploit")
        self.assertEqual(runs[0]["targets"], ["t.example.com"])

    def test_disabled_writes_nothing(self):
        os.environ["PRAETOR_TOOLLOG"] = "off"
        L.record_run(["sqlmap", "https://t.example.com"])
        self.assertEqual(L.read_runs(), [])

    def test_record_run_never_raises(self):
        # malformed argv must fail-open, not crash the caller
        L.record_run([])
        L.record_run(None)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
