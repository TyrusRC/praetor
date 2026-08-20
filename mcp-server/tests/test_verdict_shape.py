"""Token-lean verdict shape (Spec E1.2): no duplicate summary, no empty lists."""
import unittest

from praetor.tools.testing._verdict import make_verdict, to_assess_evidence


class VerdictShapeTest(unittest.TestCase):
    def test_no_duplicate_summary(self):
        v = make_verdict("FAILED", 0.1, "no anomaly", summary="FAILED — clean")
        self.assertEqual(v["human_summary"], "FAILED — clean")
        self.assertNotIn("summary", v.get("details", {}),
                         "details.summary duplicates human_summary")

    def test_empty_evidence_lists_omitted(self):
        v = make_verdict("FAILED", 0.1, "no anomaly", summary="x")
        for k in ("logger_indices", "proxy_indices",
                  "collaborator_interactions", "reproductions", "details"):
            self.assertNotIn(k, v, f"empty {k} should be omitted")

    def test_populated_evidence_lists_kept(self):
        v = make_verdict("CONFIRMED", 0.9, "hit", summary="x",
                         logger_indices=[412])
        self.assertEqual(v["logger_indices"], [412])
        self.assertNotIn("proxy_indices", v)

    def test_to_assess_evidence_survives_omitted_keys(self):
        # The internal consumer must still work when empty keys are absent.
        v = make_verdict("FAILED", 0.1, "clean")
        ev = to_assess_evidence(v)
        self.assertNotIn("logger_index", ev)
        self.assertNotIn("collaborator_interaction_id", ev)


if __name__ == "__main__":
    unittest.main()
