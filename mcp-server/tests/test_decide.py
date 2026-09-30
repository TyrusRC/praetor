"""decide — the JEV-style typed+calibrated decision envelope.

Each test drives one branch that can actually break: verdict routing (report /
keep_testing / escalate), the Rule-33 no-signal escalation, the completion stop,
and calibration capping an overconfident class.
"""

import unittest
from unittest.mock import AsyncMock, patch

from praetor.tools import decide as D


def _fn(name):
    from praetor import server
    return server.mcp._tool_manager._tools[name].fn


class DecideVerdictTest(unittest.TestCase):

    def test_confirmed_routes_to_report(self):
        d = D._decide_verdict("sqli", "CONFIRMED", 0.85)
        self.assertEqual(d.action, "report")
        self.assertEqual(d.band, "high")
        self.assertIn("assess_finding", d.route["next"])

    def test_inconclusive_high_value_escalates(self):
        d = D._decide_verdict("sqli", "INCONCLUSIVE", -1.0)
        self.assertEqual(d.action, "escalate")
        self.assertEqual(d.route["to"], "opus")
        self.assertEqual(d.band, "low")

    def test_inconclusive_low_value_keeps_testing_not_covered(self):
        d = D._decide_verdict("missing_headers", "INCONCLUSIVE", -1.0)
        self.assertEqual(d.action, "keep_testing")
        # Rule 13b: the route must explicitly forbid marking it covered
        self.assertIn("do not mark covered", d.route.get("next", "").lower())

    def test_suspected_below_bar_keeps_testing(self):
        d = D._decide_verdict("xss", "SUSPECTED", 0.55)
        self.assertEqual(d.action, "keep_testing")
        self.assertEqual(d.band, "medium")

    def test_suspected_high_confidence_reports(self):
        d = D._decide_verdict("xss", "SUSPECTED", 0.80)
        self.assertEqual(d.action, "report")

    def test_error_asks_never_covered(self):
        d = D._decide_verdict("sqli", "ERROR", -1.0)
        self.assertEqual(d.action, "ask")
        self.assertIn("32a", d.route["why"])

    def test_missing_verdict_asks(self):
        d = D._decide_verdict("sqli", "", -1.0)
        self.assertEqual(d.action, "ask")


class DecideCalibrationTest(unittest.TestCase):

    def test_overconfident_class_caps_confidence(self):
        cal = {"cal_verdict": "overconfident", "suggested_confidence": 0.40}
        # eyeballed 0.85 must not survive when the ledger says the class runs 0.40
        self.assertEqual(D._calibrate(0.85, cal), 0.40)

    def test_thin_data_never_raises_confidence(self):
        cal = {"cal_verdict": "insufficient", "suggested_confidence": None}
        self.assertEqual(D._calibrate(0.55, cal), 0.55)

    def test_confirmed_verdict_downgraded_by_ledger(self):
        cal = {"cal_verdict": "overconfident", "suggested_confidence": 0.30,
               "n": 8, "tp_rate": 0.30}
        with patch.object(D, "_class_calibration", return_value=cal):
            d = D._decide_verdict("sqli", "CONFIRMED", 0.85)
        # capped to 0.30 → drops out of the high band → no longer a clean report
        self.assertEqual(d.confidence, 0.30)
        self.assertEqual(d.band, "low")


class DecideNextTest(unittest.IsolatedAsyncioTestCase):

    async def test_complete_routes_to_stop(self):
        with patch.object(D, "judge_completion_data",
                          return_value={"complete": True}):
            d = await D._decide_next("acme.tld", "", None)
        self.assertEqual(d.action, "stop")
        self.assertIn("generate_report", d.route["next"])

    async def test_auto_signal_routes_to_run(self):
        with patch.object(D, "judge_completion_data",
                          return_value={"complete": False, "gaps": []}), \
             patch.object(D, "route_signals", new=AsyncMock(return_value={
                 "auto": [{"tool": "auto_probe", "args": {"categories": ["sqli"]},
                           "rationale": "sql error signal"}],
                 "ask": [], "dropped": []})):
            d = await D._decide_next("acme.tld", "", None)
        self.assertEqual(d.action, "run")
        self.assertEqual(d.route["tool"], "auto_probe")

    async def test_only_ask_signal_requires_approval(self):
        with patch.object(D, "judge_completion_data",
                          return_value={"complete": False, "gaps": []}), \
             patch.object(D, "route_signals", new=AsyncMock(return_value={
                 "auto": [], "ask": [{"tool": "run_pacu", "args": {}}], "dropped": []})):
            d = await D._decide_next("acme.tld", "", None)
        self.assertEqual(d.action, "ask")

    async def test_no_signal_not_complete_escalates(self):
        with patch.object(D, "judge_completion_data", return_value={
                 "complete": False, "gaps": ["business-logic pass not proven"],
                 "recommended_next": "test_business_logic"}), \
             patch.object(D, "route_signals", new=AsyncMock(return_value={
                 "auto": [], "ask": [], "dropped": []})):
            d = await D._decide_next("acme.tld", "", None)
        self.assertEqual(d.action, "escalate")
        self.assertEqual(d.route["to"], "opus")
        self.assertEqual(d.route["fallback_next"], "test_business_logic")

    async def test_next_needs_domain(self):
        d = await D._decide_next("", "", None)
        self.assertEqual(d.action, "ask")


class DecideToolWiringTest(unittest.IsolatedAsyncioTestCase):

    async def test_tool_registered_and_returns_envelope(self):
        out = await _fn("decide")(question="verdict", vuln_type="sqli",
                                  verdict="CONFIRMED", confidence=0.85)
        self.assertEqual(out["action"], "report")
        # the envelope shape every host consumes
        for key in ("question", "choice", "action", "confidence", "band",
                    "route", "rationale", "human_summary"):
            self.assertIn(key, out)
        self.assertIn("REPORT", out["human_summary"])


if __name__ == "__main__":
    unittest.main()
