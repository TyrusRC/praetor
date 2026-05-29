"""W14-T2 — integration test: VerdictResult -> is_actionable -> to_assess_evidence
-> assess_finding (the full per-finding pipeline a senior-engineer agent runs).

Uses synthetic VerdictResult dicts (not live tools) to keep the test
deterministic. The point is to prove the schema flows through the gate.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from burpsuite_mcp.tools.testing._verdict import (
    error_verdict,
    is_actionable,
    make_verdict,
    to_assess_evidence,
    verdict_from_tally,
)


class VerdictToAssessProjectionTest(unittest.TestCase):

    def test_confirmed_projects_to_actionable_evidence(self):
        v = make_verdict(
            "CONFIRMED", 0.85,
            "SSRF confirmed via cloud_metadata reach (ami-id reflected)",
            vuln_type="ssrf",
            logger_indices=[42, 43],
            collaborator_interactions=["abc.oastify.com"],
            reproductions=[
                {"logger_index": 42, "elapsed_ms": 120, "status_code": 200},
                {"logger_index": 43, "elapsed_ms": 118, "status_code": 200},
                {"logger_index": 44, "elapsed_ms": 121, "status_code": 200},
            ],
            details={"url": "https://t.example.com/api/fetch"},
            summary="*** SSRF CONFIRMED ***",
        )
        self.assertTrue(is_actionable(v))

        ev = to_assess_evidence(v)
        # Collaborator wins over logger when both are present.
        self.assertEqual(ev["collaborator_interaction_id"], "abc.oastify.com")
        # Logger index still included.
        self.assertEqual(ev["logger_index"], 42)
        # Reproductions pass through.
        self.assertEqual(len(ev["reproductions"]), 3)
        # Confidence pass through.
        self.assertAlmostEqual(ev["confidence"], 0.85, places=3)

    def test_failed_verdict_not_actionable(self):
        v = make_verdict("FAILED", 0.1, "no anomaly", vuln_type="ssrf")
        self.assertFalse(is_actionable(v))

    def test_error_verdict_not_actionable(self):
        v = error_verdict("scope reject", vuln_type="ssrf")
        self.assertFalse(is_actionable(v))

    def test_suspected_below_floor_not_actionable(self):
        v = make_verdict("SUSPECTED", 0.30, "weak signal", vuln_type="ssrf")
        self.assertFalse(is_actionable(v))

    def test_suspected_at_floor_actionable(self):
        v = make_verdict("SUSPECTED", 0.45, "borderline", vuln_type="ssrf")
        self.assertTrue(is_actionable(v))


class VerdictTallyConsistencyTest(unittest.TestCase):

    def test_tally_outputs_match_make_verdict_levels(self):
        # FAILED outputs at floor; SUSPECTED above floor; CONFIRMED clearly above.
        v_fail = make_verdict(*verdict_from_tally(0), "0 hits", vuln_type="csrf")
        v_susp = make_verdict(*verdict_from_tally(1), "1 hit", vuln_type="csrf")
        v_conf = make_verdict(*verdict_from_tally(2), "2 hits", vuln_type="csrf")
        self.assertEqual(v_fail["verdict"], "FAILED")
        self.assertEqual(v_susp["verdict"], "SUSPECTED")
        self.assertEqual(v_conf["verdict"], "CONFIRMED")
        self.assertFalse(is_actionable(v_fail))
        self.assertTrue(is_actionable(v_susp))
        self.assertTrue(is_actionable(v_conf))


class FullPipelineTest(unittest.IsolatedAsyncioTestCase):

    async def test_verdict_feeds_assess_finding(self):
        """End-to-end: VerdictResult -> assess_finding_impl returns advisor verdict."""
        from burpsuite_mcp.tools.advisor.assess import assess_finding_impl

        v = make_verdict(
            "CONFIRMED", 0.85,
            "SSRF confirmed — ami-id reflected from 169.254.169.254",
            vuln_type="ssrf",
            logger_indices=[42],
            collaborator_interactions=["abc.oastify.com"],
            details={"url": "https://target.example.com/api/fetch"},
            summary="...",
        )
        ev = to_assess_evidence(v)

        async def _fake_get(path, **kwargs):
            # Mock the Burp proxy-history lookup the Q5 evidence augmenter
            # consults — returns a stub entry with SSRF cloud-metadata markers
            # so the gate sees concrete evidence.
            return {
                "method": "GET",
                "url": "https://target.example.com/api/fetch?url=http://169.254.169.254/",
                "response_body": "ami-id: ami-1234abcd\ninstance-id: i-0987",
                "status_code": 200,
            }

        with patch(
            "burpsuite_mcp.tools.advisor._evidence_augment.client.get",
            side_effect=_fake_get,
        ):
            result = await assess_finding_impl(
                vuln_type=v["vuln_type"],
                evidence=v["evidence_summary"],
                endpoint="https://target.example.com/api/fetch",
                parameter="url",
                logger_index=ev["logger_index"],
                domain="target.example.com",
            )

        # The advisor returns a string verdict. Confirmed SSRF should pass
        # the gate or at minimum NOT return DO NOT REPORT.
        self.assertIsInstance(result, str)
        self.assertNotIn("DO NOT REPORT", result)


if __name__ == "__main__":
    unittest.main()
