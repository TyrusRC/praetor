"""checklist_update / checklist_record_batch — evidence gate on confirmed/finding.

Root cause #2 of the reported "checklist items skip even on a full-coverage
pentest" bug: only not_applicable required a note; confirmed/finding could be
written with zero evidence (a bare status flip), and checklist_record_batch's
`status=` bypass path (no `verdict=`) had no note requirement at all. Fixed:
confirmed/finding/not_applicable all require a note now; a verdict-mapped
result still gets an automatic note (unaffected)."""

from __future__ import annotations

import asyncio
import shutil
import unittest

from praetor.tools.notes._helpers import _intel_dir, _sanitized


class _ToolCapture:
    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self, *a, **k):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


class ChecklistUpdateEvidenceTest(unittest.TestCase):
    DOMAIN = "w-ckev.test-throwaway.example"

    def setUp(self) -> None:
        from praetor.tools.assurance._checklists import _tools as mod
        self.cap = _ToolCapture()
        mod.register(self.cap)
        self.update = self.cap.tools["checklist_update"]

    def tearDown(self) -> None:
        shutil.rmtree(_intel_dir() / _sanitized(self.DOMAIN), ignore_errors=True)

    def _items(self):
        from praetor.tools.assurance._checklists._status import _load_status
        return _load_status(self.DOMAIN)

    def test_confirmed_without_note_is_rejected(self):
        out = asyncio.run(self.update(self.DOMAIN, "owasp_top10", "A01", "confirmed"))
        self.assertIn("requires a note", out)
        self.assertEqual(self._items(), {})  # nothing written

    def test_finding_without_note_is_rejected(self):
        out = asyncio.run(self.update(self.DOMAIN, "owasp_top10", "A01", "finding"))
        self.assertIn("requires a note", out)
        self.assertEqual(self._items(), {})

    def test_not_applicable_without_note_is_rejected(self):
        out = asyncio.run(self.update(self.DOMAIN, "owasp_top10", "A01", "not_applicable"))
        self.assertIn("requires a note", out)
        self.assertEqual(self._items(), {})

    def test_confirmed_with_note_is_written(self):
        out = asyncio.run(self.update(self.DOMAIN, "owasp_top10", "A01", "confirmed",
                                      note="tested via auto_probe, no injection possible"))
        self.assertIn("owasp_top10:A01 -> confirmed", out)
        self.assertEqual(self._items()["owasp_top10:A01"]["status"], "confirmed")

    def test_open_never_needs_a_note(self):
        # Re-opening an item is not a reportable claim — no evidence required.
        out = asyncio.run(self.update(self.DOMAIN, "owasp_top10", "A01", "open"))
        self.assertIn("owasp_top10:A01 -> open", out)

    def test_invalid_status_rejected_before_note_check(self):
        out = asyncio.run(self.update(self.DOMAIN, "owasp_top10", "A01", "maybe"))
        self.assertIn("status must be one of", out)


class ChecklistRecordBatchEvidenceTest(unittest.TestCase):
    DOMAIN = "w-ckevb.test-throwaway.example"

    def setUp(self) -> None:
        from praetor.tools.assurance._checklists import _tools as mod
        self.cap = _ToolCapture()
        mod.register(self.cap)
        self.batch = self.cap.tools["checklist_record_batch"]

    def tearDown(self) -> None:
        shutil.rmtree(_intel_dir() / _sanitized(self.DOMAIN), ignore_errors=True)

    def _items(self):
        from praetor.tools.assurance._checklists._status import _load_status
        return _load_status(self.DOMAIN)

    def test_bare_status_with_no_note_is_rejected_not_silently_closed(self):
        out = asyncio.run(self.batch(self.DOMAIN, "owasp_top10",
                                     [{"item_id": "A01", "status": "confirmed"}]))
        self.assertIn("0 test case(s)", out)
        self.assertIn("1 malformed", out)
        self.assertEqual(self._items(), {})  # the real fix: nothing closes silently

    def test_bare_not_applicable_no_longer_auto_fills_a_placeholder_note(self):
        out = asyncio.run(self.batch(self.DOMAIN, "owasp_top10",
                                     [{"item_id": "A01", "status": "not_applicable"}]))
        self.assertIn("1 malformed", out)
        self.assertEqual(self._items(), {})

    def test_bare_status_with_note_closes_the_item(self):
        out = asyncio.run(self.batch(self.DOMAIN, "owasp_top10",
                                     [{"item_id": "A01", "status": "confirmed",
                                       "note": "tested, no finding"}]))
        self.assertIn("1 test case(s)", out)
        self.assertEqual(self._items()["owasp_top10:A01"]["note"], "tested, no finding")

    def test_verdict_mapped_result_still_gets_an_automatic_note(self):
        # The verdict path is unaffected — it has always supplied an auto note.
        out = asyncio.run(self.batch(self.DOMAIN, "owasp_top10",
                                     [{"item_id": "A01", "verdict": "CONFIRMED"}]))
        self.assertIn("1 test case(s)", out)
        self.assertEqual(self._items()["owasp_top10:A01"]["status"], "finding")
        self.assertIn("auto:", self._items()["owasp_top10:A01"]["note"])

    def test_non_decisive_verdict_leaves_item_open_no_note_needed(self):
        out = asyncio.run(self.batch(self.DOMAIN, "owasp_top10",
                                     [{"item_id": "A01", "verdict": "INCONCLUSIVE"}]))
        self.assertIn("1 left OPEN", out)
        self.assertEqual(self._items(), {})

    def test_mixed_batch_counts_each_outcome_correctly(self):
        out = asyncio.run(self.batch(self.DOMAIN, "owasp_top10", [
            {"item_id": "A01", "verdict": "CONFIRMED"},          # closes (auto note)
            {"item_id": "A02", "status": "confirmed"},            # rejected, no note
            {"item_id": "A03", "status": "confirmed", "note": "x"},  # closes
            {"item_id": "A04", "verdict": "INCONCLUSIVE"},        # stays open
            {"not_item_id": "bad"},                               # malformed shape
        ]))
        self.assertIn("2 test case(s)", out)
        self.assertIn("1 left OPEN", out)
        self.assertIn("2 malformed", out)
        items = self._items()
        self.assertIn("owasp_top10:A01", items)
        self.assertNotIn("owasp_top10:A02", items)
        self.assertIn("owasp_top10:A03", items)
        self.assertNotIn("owasp_top10:A04", items)


if __name__ == "__main__":
    unittest.main()
