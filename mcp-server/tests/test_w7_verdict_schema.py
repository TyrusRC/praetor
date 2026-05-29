"""Tests for the W7 structured-verdict schema.

Verifies the contract assess_finding depends on (logger_index pass-through,
reproductions[] shape, confidence floor).
"""

from __future__ import annotations

import unittest

from burpsuite_mcp.tools.testing._verdict import (
    error_verdict,
    is_actionable,
    make_verdict,
    to_assess_evidence,
)


class VerdictSchemaTest(unittest.TestCase):

    def test_make_verdict_confirmed(self):
        v = make_verdict(
            "CONFIRMED", 0.9, "matcher fired; OOB DNS interaction observed",
            vuln_type="ssrf",
            logger_indices=[42, 43],
            collaborator_interactions=["abc.oastify.com"],
            summary="*** SSRF CONFIRMED ***",
        )
        self.assertEqual(v["verdict"], "CONFIRMED")
        self.assertEqual(v["confidence"], 0.9)
        self.assertEqual(v["logger_indices"], [42, 43])
        self.assertEqual(v["collaborator_interactions"], ["abc.oastify.com"])
        self.assertEqual(v["vuln_type"], "ssrf")
        self.assertEqual(v["details"]["summary"], "*** SSRF CONFIRMED ***")
        self.assertEqual(v["human_summary"], "*** SSRF CONFIRMED ***")

    def test_invalid_verdict_rejected(self):
        with self.assertRaises(ValueError):
            make_verdict("MAYBE", 0.5, "x")  # type: ignore[arg-type]

    def test_confidence_clamped(self):
        self.assertEqual(make_verdict("FAILED", -0.5, "x")["confidence"], 0.0)
        self.assertEqual(make_verdict("CONFIRMED", 99.0, "x")["confidence"], 1.0)

    def test_is_actionable(self):
        self.assertTrue(is_actionable(make_verdict("CONFIRMED", 0.1, "x")))
        self.assertTrue(is_actionable(make_verdict("SUSPECTED", 0.5, "x")))
        self.assertFalse(is_actionable(make_verdict("SUSPECTED", 0.3, "x")))
        self.assertFalse(is_actionable(make_verdict("FAILED", 0.9, "x")))
        self.assertFalse(is_actionable(make_verdict("ERROR", 0.0, "x")))

    def test_to_assess_evidence_prefers_collaborator(self):
        v = make_verdict(
            "CONFIRMED", 0.8, "ev",
            logger_indices=[7],
            collaborator_interactions=["x.oast"],
        )
        ev = to_assess_evidence(v)
        self.assertEqual(ev["collaborator_interaction_id"], "x.oast")
        self.assertEqual(ev["logger_index"], 7)

    def test_to_assess_evidence_logger_then_proxy(self):
        v = make_verdict(
            "SUSPECTED", 0.6, "ev",
            logger_indices=[3],
            proxy_indices=[99],
        )
        ev = to_assess_evidence(v)
        self.assertEqual(ev["logger_index"], 3)
        self.assertNotIn("proxy_history_index", ev)

        v2 = make_verdict("SUSPECTED", 0.6, "ev", proxy_indices=[99])
        ev2 = to_assess_evidence(v2)
        self.assertEqual(ev2["proxy_history_index"], 99)

    def test_error_verdict_shape(self):
        v = error_verdict("burp not reachable", vuln_type="sqli")
        self.assertEqual(v["verdict"], "ERROR")
        self.assertEqual(v["confidence"], 0.0)
        self.assertEqual(v["vuln_type"], "sqli")
        self.assertIn("error", v["details"])
        self.assertFalse(is_actionable(v))

    def test_reproductions_passed_through(self):
        reps = [
            {"logger_index": 1, "elapsed_ms": 120, "status_code": 200},
            {"logger_index": 2, "elapsed_ms": 119, "status_code": 200},
            {"logger_index": 3, "elapsed_ms": 121, "status_code": 200},
        ]
        v = make_verdict("CONFIRMED", 0.8, "stable timing", reproductions=reps)
        self.assertEqual(len(v["reproductions"]), 3)
        ev = to_assess_evidence(v)
        self.assertEqual(ev["reproductions"], reps)


if __name__ == "__main__":
    unittest.main()
