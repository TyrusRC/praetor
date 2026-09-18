"""Red-team kill-chain report section (ATT&CK narrative from the operator log)."""

import json
import os
import tempfile
import unittest

from praetor.tools.report._report_sections import build_killchain_section


class KillChainSectionTest(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        os.chdir(tempfile.mkdtemp())
        self.addCleanup(os.chdir, self._cwd)  # never leak cwd to other tests
        from praetor.tools.redteam._oplog import _oplog_path
        p = _oplog_path("acme.test")
        p.parent.mkdir(parents=True, exist_ok=True)
        rows = [
            {"seq": 1, "tactic": "Discovery", "technique": "T1046",
             "technique_name": "Network Service Discovery", "tool": "nmap",
             "target": "10.0.0.5", "description": "port scan", "detected": False},
            {"seq": 2, "tactic": "Credential Access", "technique": "T1110",
             "technique_name": "Brute Force", "tool": "nxc", "target": "DC01",
             "description": "spray", "detected": True},
        ]
        p.write_text("\n".join(json.dumps(r) for r in rows))
        self.findings = [{"status": "confirmed", "severity": "critical",
                          "title": "DA via Kerberoast", "endpoint": "DC01"}]

    def test_renders_tactics_techniques_stealth_impact(self):
        out = build_killchain_section("acme.test", self.findings)
        self.assertIn("Attack Narrative (Kill Chain)", out)
        self.assertIn("### Discovery", out)
        self.assertIn("T1110 Brute Force", out)
        self.assertIn("[DETECTED]", out)
        self.assertIn("MITRE ATT&CK techniques observed", out)
        self.assertIn("1 of 2 recorded actions were detected", out)
        self.assertIn("Objective Impact (1 confirmed)", out)
        self.assertIn("DA via Kerberoast", out)

    def test_no_oplog_prompts_for_recording(self):
        out = build_killchain_section("nobody.test", [])
        self.assertIn("record_redteam_action", out)


if __name__ == "__main__":
    unittest.main()
