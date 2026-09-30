"""assess_cve_exploitability — the exploitable_here gate (Rule 13b/13c).

A version/banner match alone is `reachable`, never `exploitable_here`; only a
benign PoC that actually FIRED and left citable evidence flips the gate.
"""

import unittest

from praetor.tools.fuzzing.cve_verdict import _assemble_cve_verdict


def _v(poc_verdict, phi, memcorr=False):
    return _assemble_cve_verdict(
        cve="CVE-2025-9999", cwe="", kev=False, epss=0.5,
        reachable=True, precondition_met=True,
        poc_verdict=poc_verdict, evidence={"proxy_history_index": phi},
        poc_summary="x", memcorr=memcorr,
    )


class ExploitableHereGate(unittest.TestCase):
    def test_version_match_only_is_reachable_not_exploitable(self):
        v = _v("NOT_FIRED", -1)
        self.assertTrue(v["reachable"])
        self.assertFalse(v["exploitable_here"])

    def test_benign_poc_evidence_is_exploitable(self):
        v = _v("CONFIRMED", 42)
        self.assertTrue(v["exploitable_here"])
        self.assertEqual(v["evidence"]["proxy_history_index"], 42)

    def test_confirmed_without_evidence_does_not_pass(self):
        self.assertFalse(_v("CONFIRMED", -1)["exploitable_here"])

    def test_memory_corruption_never_exploitable_over_web(self):
        v = _v("CONFIRMED", 7, memcorr=True)
        self.assertFalse(v["exploitable_here"])
        self.assertTrue(v["next"].startswith("memory-corruption"))


if __name__ == "__main__":
    unittest.main()
