"""Report-integrity: a locked finding's reported verdict cannot flip silently."""

import unittest

from praetor.tools.notes._findings_dedupe import _dedupe_finding
from praetor.tools.notes.lock import _evidence_line, _set_lock


def _f(**kw):
    base = {"id": "f001", "endpoint": "https://x.test/a", "vuln_type": "sqli",
            "title": "SQLi in id", "parameter": "id", "status": "confirmed",
            "severity": "high"}
    base.update(kw)
    return base


class DedupeLockGuardTest(unittest.TestCase):
    def test_unlocked_status_is_overwritten_as_before(self):
        existing = [_f(status="confirmed")]
        _, action, i = _dedupe_finding(existing, _f(status="likely_false_positive"))
        self.assertEqual(action, "updated")
        self.assertEqual(existing[i]["status"], "likely_false_positive")

    def test_locked_status_change_is_blocked_and_logged(self):
        existing = [_f(status="confirmed", severity="high", locked=True)]
        out, action, i = _dedupe_finding(existing, _f(status="likely_false_positive",
                                                      severity="low"))
        self.assertEqual(action, "locked_conflict")
        # reported verdict preserved
        self.assertEqual(out[i]["status"], "confirmed")
        self.assertEqual(out[i]["severity"], "high")
        # divergence captured, not lost
        self.assertEqual(out[i]["discrepancy_log"][0]["observed_status"],
                         "likely_false_positive")
        self.assertEqual(out[i]["discrepancy_log"][0]["kept_status"], "confirmed")

    def test_locked_same_status_merges_nonfrozen_fields(self):
        existing = [_f(status="confirmed", locked=True)]
        out, action, i = _dedupe_finding(
            existing, _f(status="confirmed", evidence={"logger_index": 9}))
        self.assertEqual(action, "updated_locked")
        self.assertEqual(out[i]["status"], "confirmed")
        self.assertEqual(out[i]["evidence"], {"logger_index": 9})  # new evidence kept
        self.assertNotIn("discrepancy_log", out[i])  # no divergence

    def test_lock_flag_survives_merge(self):
        existing = [_f(locked=True)]
        out, _, i = _dedupe_finding(existing, _f(locked=False))  # incoming tries to clear
        self.assertTrue(out[i]["locked"])


class LockHelpersTest(unittest.TestCase):
    def test_set_and_clear_lock(self):
        f = _set_lock(_f(), True, reason="reported", at="2026-09-18T00:00:00Z")
        self.assertTrue(f["locked"])
        self.assertEqual(f["locked_reason"], "reported")
        f = _set_lock(f, False)
        self.assertNotIn("locked", f)
        self.assertNotIn("locked_at", f)

    def test_evidence_line_shows_index(self):
        line = _evidence_line(_f(evidence={"logger_index": 42}))
        self.assertIn("f001", line)
        self.assertIn("[high]", line)
        self.assertIn("evidence: 42", line)

    def test_evidence_line_missing_index_shows_dash(self):
        self.assertIn("evidence: —", _evidence_line(_f(evidence={})))


if __name__ == "__main__":
    unittest.main()
