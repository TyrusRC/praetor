"""Verdict system: make_verdict validation, tally logic, helpers.

Pure stdlib — no Burp, no async. Run with:
    uv run python -m unittest tests.test_confirm_verdict -v
"""

import unittest

from praetor.tools.testing._verdict import (
    make_verdict,
    verdict_from_tally,
    is_actionable,
    to_assess_evidence,
    error_verdict,
    inconclusive_verdict,
)


class MakeVerdictValidation(unittest.TestCase):

    def test_accepts_confirmed(self):
        v = make_verdict("CONFIRMED", 0.85, "Payload reflected in exec context")
        self.assertEqual(v["verdict"], "CONFIRMED")
        self.assertAlmostEqual(v["confidence"], 0.85)

    def test_accepts_suspected(self):
        v = make_verdict("SUSPECTED", 0.55, "Anomaly vs baseline")
        self.assertEqual(v["verdict"], "SUSPECTED")

    def test_accepts_failed(self):
        v = make_verdict("FAILED", 0.10, "No anomaly observed")
        self.assertEqual(v["verdict"], "FAILED")

    def test_accepts_inconclusive(self):
        v = make_verdict("INCONCLUSIVE", 0.0, "Payload may not have reached sink")
        self.assertEqual(v["verdict"], "INCONCLUSIVE")

    def test_accepts_error(self):
        v = make_verdict("ERROR", 0.0, "Connection refused")
        self.assertEqual(v["verdict"], "ERROR")

    def test_rejects_not_vulnerable(self):
        with self.assertRaises(ValueError) as ctx:
            make_verdict("NOT_VULNERABLE", 0.7, "denied")
        self.assertIn("NOT_VULNERABLE", str(ctx.exception))

    def test_rejects_arbitrary_string(self):
        with self.assertRaises(ValueError):
            make_verdict("MAYBE", 0.5, "unsure")

    def test_rejects_lowercase_variant(self):
        with self.assertRaises(ValueError):
            make_verdict("confirmed", 0.85, "yes")

    def test_confidence_clamped_to_0_1(self):
        v = make_verdict("CONFIRMED", 2.5, "over")
        self.assertAlmostEqual(v["confidence"], 1.0)
        v2 = make_verdict("FAILED", -0.5, "under")
        self.assertAlmostEqual(v2["confidence"], 0.0)

    def test_omits_empty_lists(self):
        v = make_verdict("CONFIRMED", 0.8, "ok", logger_indices=[], reproductions=[])
        self.assertNotIn("logger_indices", v)
        self.assertNotIn("reproductions", v)

    def test_includes_nonempty_lists(self):
        v = make_verdict("CONFIRMED", 0.8, "ok", logger_indices=[42])
        self.assertEqual(v["logger_indices"], [42])

    def test_vuln_type_stored(self):
        v = make_verdict("SUSPECTED", 0.6, "anom", vuln_type="sqli")
        self.assertEqual(v["vuln_type"], "sqli")

    def test_summary_becomes_human_summary(self):
        v = make_verdict("FAILED", 0.1, "nope", summary="Not found on /login")
        self.assertEqual(v["human_summary"], "Not found on /login")

    def test_details_included_when_nonempty(self):
        v = make_verdict("CONFIRMED", 0.8, "yes", details={"method": "UNION"})
        self.assertEqual(v["details"]["method"], "UNION")

    def test_details_omitted_when_empty(self):
        v = make_verdict("CONFIRMED", 0.8, "yes", details={})
        self.assertNotIn("details", v)


class VerdictFromTally(unittest.TestCase):

    def test_zero_hits_is_failed(self):
        verdict, conf = verdict_from_tally(0)
        self.assertEqual(verdict, "FAILED")
        self.assertAlmostEqual(conf, 0.10)

    def test_one_hit_is_suspected(self):
        verdict, conf = verdict_from_tally(1)
        self.assertEqual(verdict, "SUSPECTED")
        self.assertAlmostEqual(conf, 0.55)

    def test_two_hits_is_confirmed(self):
        verdict, conf = verdict_from_tally(2)
        self.assertEqual(verdict, "CONFIRMED")
        self.assertAlmostEqual(conf, 0.85)

    def test_many_hits_still_confirmed(self):
        verdict, _ = verdict_from_tally(10)
        self.assertEqual(verdict, "CONFIRMED")

    def test_custom_threshold(self):
        verdict, _ = verdict_from_tally(3, confirmed_threshold=5)
        self.assertEqual(verdict, "SUSPECTED")
        verdict2, _ = verdict_from_tally(5, confirmed_threshold=5)
        self.assertEqual(verdict2, "CONFIRMED")

    def test_valid_runs_zero_is_inconclusive(self):
        verdict, conf = verdict_from_tally(0, valid_runs=0)
        self.assertEqual(verdict, "INCONCLUSIVE")
        self.assertAlmostEqual(conf, 0.0)

    def test_valid_runs_nonzero_still_works(self):
        verdict, _ = verdict_from_tally(0, valid_runs=5)
        self.assertEqual(verdict, "FAILED")


class IsActionable(unittest.TestCase):

    def test_confirmed_is_actionable(self):
        v = make_verdict("CONFIRMED", 0.85, "yes")
        self.assertTrue(is_actionable(v))

    def test_suspected_above_threshold(self):
        v = make_verdict("SUSPECTED", 0.50, "maybe")
        self.assertTrue(is_actionable(v))

    def test_suspected_below_threshold(self):
        v = make_verdict("SUSPECTED", 0.30, "weak")
        self.assertFalse(is_actionable(v))

    def test_failed_not_actionable(self):
        v = make_verdict("FAILED", 0.10, "nope")
        self.assertFalse(is_actionable(v))

    def test_inconclusive_not_actionable(self):
        v = make_verdict("INCONCLUSIVE", 0.0, "unsure")
        self.assertFalse(is_actionable(v))

    def test_error_not_actionable(self):
        v = make_verdict("ERROR", 0.0, "broke")
        self.assertFalse(is_actionable(v))


class ToAssessEvidence(unittest.TestCase):

    def test_collaborator_preferred_over_logger(self):
        v = make_verdict("CONFIRMED", 0.9, "yes",
                         collaborator_interactions=["abc123"],
                         logger_indices=[42])
        ev = to_assess_evidence(v)
        self.assertEqual(ev["collaborator_interaction_id"], "abc123")
        self.assertEqual(ev["proxy_history_index"], 42)

    def test_logger_index_used_when_no_collaborator(self):
        v = make_verdict("CONFIRMED", 0.9, "yes", logger_indices=[10])
        ev = to_assess_evidence(v)
        self.assertEqual(ev["proxy_history_index"], 10)
        self.assertNotIn("collaborator_interaction_id", ev)

    def test_reproductions_passed_through(self):
        repro = [{"proxy_history_index": 50, "status_code": 200}]
        v = make_verdict("CONFIRMED", 0.9, "yes", reproductions=repro)
        ev = to_assess_evidence(v)
        self.assertEqual(ev["reproductions"], repro)


class ErrorVerdictShortcut(unittest.TestCase):

    def test_error_verdict_shape(self):
        v = error_verdict("scope block", vuln_type="xss", reason="out_of_scope")
        self.assertEqual(v["verdict"], "ERROR")
        self.assertAlmostEqual(v["confidence"], 0.0)
        self.assertEqual(v["details"]["reason"], "out_of_scope")
        self.assertEqual(v["vuln_type"], "xss")


class InconclusiveVerdictShortcut(unittest.TestCase):

    def test_inconclusive_verdict_shape(self):
        v = inconclusive_verdict("sink not reached", vuln_type="ssti",
                                 reason="sink_not_reached", logger_indices=[7])
        self.assertEqual(v["verdict"], "INCONCLUSIVE")
        self.assertAlmostEqual(v["confidence"], 0.0)
        self.assertEqual(v["details"]["reason"], "sink_not_reached")
        self.assertEqual(v["logger_indices"], [7])


if __name__ == "__main__":
    unittest.main()
