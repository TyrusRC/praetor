"""Tests for the beam-search attack-path planner and CWE->CAPEC derivation.

Two additions, each with one focused test per behaviour that can actually break:
- plan_attack_paths: seed -> multi-hop kill-chain; near-miss names a grantable class.
- framework_tags: CAPEC derived from CWE; unmapped CWE degrades to "".
"""

from __future__ import annotations

import unittest

from praetor.tools._framework_map import attack_tag_list, framework_tags
from praetor.tools.advisor.attack_path import (
    _beam_chains, _closure, _near_misses, _seed_capabilities,
)


class AttackPathPlannerTest(unittest.TestCase):

    def test_ssrf_chains_to_cloud_creds(self):
        # SSRF alone must beam-search through IMDS to the cloud-cred objective.
        pool = [{"id": "f1", "vuln_type": "ssrf", "severity": "high", "status": "confirmed"}]
        seeds = _seed_capabilities(pool)
        chains = _beam_chains(seeds, beam_width=6, max_depth=5)
        objs = {c["objective_cap"] for c in chains}
        self.assertIn("cloud_creds", objs)
        chain = next(c for c in chains if c["objective_cap"] == "cloud_creds")
        # ordered hops end at the objective, and the chain is attributed to f1.
        self.assertEqual(chain["steps"][-1]["capability"], "cloud_creds")
        self.assertTrue(any("f1" in s for s in chain["seed_findings"]))
        self.assertGreater(chain["score"], 0)

    def test_near_miss_only_names_grantable_classes(self):
        # open_redirect alone reaches no objective, but ATO is one capability away.
        pool = [{"id": "f2", "vuln_type": "open_redirect", "severity": "low", "status": "confirmed"}]
        seeds = _seed_capabilities(pool)
        self.assertEqual(_beam_chains(seeds, 6, 5), [])
        near = _near_misses(_closure(set(seeds)), seeds)
        self.assertTrue(near)
        # every next_proof must be a real vuln class an operator can hunt,
        # never a bare intermediate capability token.
        for n in near:
            self.assertTrue(n["next_proof_needed"])
            self.assertNotIn("token_theft", n["next_proof_needed"])
            self.assertNotIn("session_theft", n["next_proof_needed"])

    def test_no_findings_map_to_capability(self):
        seeds = _seed_capabilities([{"id": "f3", "vuln_type": "missing_headers"}])
        self.assertEqual(seeds, {})


class CapecDerivationTest(unittest.TestCase):

    def test_capec_derived_from_cwe(self):
        row = framework_tags("sqli")
        self.assertEqual(row["cwe"], "CWE-89")
        self.assertEqual(row["capec"], "CAPEC-66")
        self.assertIn("capec:CAPEC-66", attack_tag_list("sqli"))

    def test_unmapped_cwe_degrades_to_empty(self):
        # An unknown class has no CWE and therefore no CAPEC, and no capec: tag.
        row = framework_tags("totally_unknown_class")
        self.assertEqual(row["capec"], "")
        self.assertFalse(any(t.startswith("capec:") for t in attack_tag_list("totally_unknown_class")))


if __name__ == "__main__":
    unittest.main()
