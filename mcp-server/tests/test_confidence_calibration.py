"""Confidence-calibration layer (RLCD-inspired) — pure math, ledger, hooks.

Covers testing/_calibration.py (scoring), intel/calibration.py (ledger + tools),
and the two ground-truth hooks that feed it (record_retest → true_positive,
mark_finding_false_positive → false_positive).
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

from praetor import server
from praetor.tools.intel import calibration as CAL
from praetor.tools.notes._helpers import _safe_findings_path
from praetor.tools import _calibration as C


def _tool(name: str):
    return server.mcp._tool_manager._tools[name].fn


# --------------------------------------------------------------------------- #
# Pure scoring math                                                           #
# --------------------------------------------------------------------------- #
class OutcomeLabelTest(unittest.TestCase):

    def test_positive_aliases(self):
        for o in ("true_positive", "confirmed", "accepted", "regressed", "fixed", "TP"):
            self.assertEqual(C.outcome_label(o), 1, o)

    def test_negative_aliases(self):
        for o in ("false_positive", "rejected", "duplicate", "invalid", "N/A"):
            self.assertEqual(C.outcome_label(o), 0, o)

    def test_unknown_is_none(self):
        for o in ("", "maybe", "pending", "inconclusive"):
            self.assertIsNone(C.outcome_label(o))


class BinLabelTest(unittest.TestCase):

    def test_boundaries(self):
        self.assertEqual(C.bin_label(0.0), "0.0-0.1")
        self.assertEqual(C.bin_label(0.45), "0.4-0.5")
        self.assertEqual(C.bin_label(0.85), "0.8-0.9")
        # 1.0 folds into the top bin, never a degenerate 1.0-1.1
        self.assertEqual(C.bin_label(1.0), "0.9-1.0")


class BrierTest(unittest.TestCase):

    def test_known_value(self):
        recs = [
            {"confidence": 0.9, "outcome": "true_positive"},
            {"confidence": 0.1, "outcome": "false_positive"},
        ]
        # ((0.9-1)^2 + (0.1-0)^2)/2 = 0.01
        self.assertAlmostEqual(C.brier_score(recs), 0.01, places=4)

    def test_empty_is_none(self):
        self.assertIsNone(C.brier_score([]))
        # unknown outcomes are not scoreable
        self.assertIsNone(C.brier_score([{"confidence": 0.5, "outcome": "pending"}]))


class ReliabilityTableTest(unittest.TestCase):

    def test_bin_tp_rate_and_gap(self):
        # four verdicts at 0.85; 1 real, 3 not -> tp_rate 0.25, gap +0.60
        recs = [{"confidence": 0.85, "outcome": o}
                for o in ("true_positive", "fp", "fp", "fp")]
        rows = C.reliability_table(recs)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["bin"], "0.8-0.9")
        self.assertEqual(row["n"], 4)
        self.assertAlmostEqual(row["tp_rate"], 0.25)
        self.assertAlmostEqual(row["gap"], 0.6, places=2)


class PerClassTest(unittest.TestCase):

    def _recs(self):
        recs = []
        # sqli: overconfident — 4 @ 0.85, only 1 real (tp_rate 0.25)
        recs += [{"vuln_type": "sqli", "confidence": 0.85, "outcome": o}
                 for o in ("tp", "fp", "fp", "fp")]
        # xss: underconfident — 3 @ 0.5, all real (tp_rate 1.0)
        recs += [{"vuln_type": "xss", "confidence": 0.5, "outcome": "tp"}
                 for _ in range(3)]
        # ssti: too few samples
        recs += [{"vuln_type": "ssti", "confidence": 0.9, "outcome": "tp"},
                 {"vuln_type": "ssti", "confidence": 0.9, "outcome": "fp"}]
        return recs

    def test_flags_and_suggestions(self):
        rows = {r["vuln_type"]: r for r in C.per_class_calibration(self._recs(), min_samples=3)}
        self.assertEqual(rows["sqli"]["verdict"], "overconfident")
        self.assertAlmostEqual(rows["sqli"]["suggested_confidence"], 0.25)
        self.assertEqual(rows["xss"]["verdict"], "underconfident")
        self.assertAlmostEqual(rows["xss"]["suggested_confidence"], 1.0)
        self.assertEqual(rows["ssti"]["verdict"], "insufficient")
        self.assertIsNone(rows["ssti"]["suggested_confidence"])

    def test_worst_first_ordering(self):
        rows = C.per_class_calibration(self._recs(), min_samples=3)
        # insufficient always last; sqli (gap .60) before xss (gap -.50)
        self.assertEqual(rows[-1]["vuln_type"], "ssti")
        self.assertEqual(rows[0]["vuln_type"], "sqli")


class SummaryTest(unittest.TestCase):

    def test_excludes_unresolved(self):
        recs = [
            {"vuln_type": "sqli", "confidence": 0.8, "outcome": "tp"},
            {"vuln_type": "sqli", "confidence": 0.8, "outcome": "fp"},
            {"vuln_type": "sqli", "confidence": 0.8, "outcome": "pending"},  # unknown
        ]
        s = C.calibration_summary(recs)
        self.assertEqual(s["records_total"], 3)
        self.assertEqual(s["scored"], 2)
        self.assertEqual(s["unresolved"], 1)
        self.assertEqual(s["true_positives"], 1)
        self.assertEqual(s["false_positives"], 1)
        self.assertAlmostEqual(s["base_rate"], 0.5)


# --------------------------------------------------------------------------- #
# Ledger + tools (temp ledger, no ~/.praetor pollution)                       #
# --------------------------------------------------------------------------- #
class LedgerTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="calib-ledger-"))
        self.ledger = self.tmp / "ledger.jsonl"
        self.patcher = patch.object(CAL, "_ledger_path", return_value=self.ledger)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_record_and_filter(self):
        self.assertTrue(CAL.record_calibration("sqli", 0.85, "true_positive"))
        self.assertTrue(CAL.record_calibration("xss", 0.5, "false_positive"))
        rows = CAL._load_ledger()
        self.assertEqual(len(rows), 2)
        only = CAL._load_ledger("sqli")
        self.assertEqual(len(only), 1)
        self.assertEqual(only[0]["vuln_type"], "sqli")

    def test_record_clamps_and_lowercases(self):
        CAL.record_calibration("SQLI", 1.7, "TP")
        row = CAL._load_ledger()[0]
        self.assertEqual(row["vuln_type"], "sqli")
        self.assertEqual(row["confidence"], 1.0)

    async def test_report_empty(self):
        out = await _tool("calibration_report")()
        self.assertIn("empty", out.lower())

    async def test_report_renders_after_data(self):
        for o in ("tp", "fp", "fp", "fp"):
            CAL.record_calibration("sqli", 0.85, o)
        out = await _tool("calibration_report")()
        self.assertIn("Brier", out)
        self.assertIn("sqli", out)
        self.assertIn("overconfident", out)

    async def test_manual_outcome_rejects_unknown(self):
        out = await _tool("record_calibration_outcome")(
            vuln_type="sqli", confidence=0.8, outcome="maybe")
        self.assertIn("does not resolve", out)
        self.assertFalse(self.ledger.exists())

    async def test_manual_outcome_records(self):
        out = await _tool("record_calibration_outcome")(
            vuln_type="idor", confidence=0.7, outcome="accepted")
        self.assertIn("true positive", out)
        self.assertEqual(len(CAL._load_ledger("idor")), 1)


# --------------------------------------------------------------------------- #
# Ground-truth hooks                                                          #
# --------------------------------------------------------------------------- #
def _make_finding(fid="f001", status="confirmed", conf=0.5, vt="xss") -> dict:
    return {
        "id": fid, "title": f"finding {fid}", "description": "x",
        "severity": "MEDIUM", "endpoint": f"https://t.example/{fid}",
        "evidence": {"proxy_history_index": 1}, "evidence_text": "",
        "status": status, "parameter": "p", "vuln_type": vt, "confidence": conf,
        "chain_with": [], "reproductions": [], "human_verified": False,
        "overrides": [], "verdict": "SUSPECTED",
        "last_updated": datetime.now(timezone.utc).isoformat(), "burp_id": "",
    }


class HookTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="calib-hook-"))
        self.prev_cwd = Path.cwd()
        os.chdir(self.tmp)
        self.ledger = self.tmp / "ledger.jsonl"
        self.patcher = patch.object(CAL, "_ledger_path", return_value=self.ledger)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        os.chdir(self.prev_cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seed(self, findings):
        path = _safe_findings_path("t.example")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"findings": findings, "last_modified": ""}))

    async def test_retest_confirmed_logs_true_positive(self):
        self._seed([_make_finding(conf=0.55, vt="sqli")])
        out = await _tool("record_retest")(
            finding_id="f001", domain="t.example", status="confirmed",
            date="2026-09-24")
        self.assertIn("Retest", out)
        rows = CAL._load_ledger()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["vuln_type"], "sqli")
        self.assertEqual(rows[0]["confidence"], 0.55)
        self.assertEqual(C.outcome_label(rows[0]["outcome"]), 1)
        self.assertEqual(rows[0]["source"], "record_retest")

    async def test_fp_delete_logs_false_positive(self):
        # confidence < 0.6 -> Tier-1 immediate hard delete
        self._seed([_make_finding(conf=0.3, vt="open_redirect")])
        with patch("praetor.tools.notes._helpers.client.delete",
                   new=AsyncMock(return_value={"ok": True})):
            out = await _tool("mark_finding_false_positive")(
                finding_id="f001", domain="t.example")
        self.assertIn("Hard-deleted", out)
        rows = CAL._load_ledger()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["vuln_type"], "open_redirect")
        self.assertEqual(rows[0]["confidence"], 0.3)
        self.assertEqual(C.outcome_label(rows[0]["outcome"]), 0)
        self.assertEqual(rows[0]["source"], "mark_finding_false_positive")

    async def test_fp_refusal_does_not_log(self):
        # high-confidence refusal (no delete) must NOT create a calibration point
        self._seed([_make_finding(conf=0.9, vt="sqli")])
        out = await _tool("mark_finding_false_positive")(
            finding_id="f001", domain="t.example")
        self.assertIn("REFUSING", out)
        self.assertFalse(self.ledger.exists())


if __name__ == "__main__":
    unittest.main()
