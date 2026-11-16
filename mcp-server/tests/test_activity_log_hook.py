"""activity-log PostToolUse hook — silent, append-only state feed for live-check / multi-agent."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOK = (Path(__file__).resolve().parents[2]
        / ".claude" / "hooks" / "activity-log.py")


class ActivityLogHookTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def _run(self, payload) -> str:
        env = {"CLAUDE_PROJECT_DIR": str(self.dir), "PATH": "/usr/bin:/bin"}
        p = subprocess.run([sys.executable, str(HOOK)],
                           input=(payload if isinstance(payload, str)
                                  else json.dumps(payload)),
                           capture_output=True, text=True, cwd=str(self.dir), env=env)
        return p.stdout

    def _lines(self):
        f = self.dir / ".burp-intel" / "_activity.jsonl"
        return f.read_text().splitlines() if f.exists() else []

    def test_silent_zero_stdout(self):
        out = self._run({"tool_name": "mcp__praetor__save_finding",
                         "session_id": "a", "tool_input": {"domain": "d"},
                         "tool_response": "Saved [high] X"})
        self.assertEqual(out, "")  # no tokens injected

    def test_logs_state_event_with_fields(self):
        self._run({"tool_name": "mcp__praetor__save_finding", "session_id": "agent1",
                   "tool_input": {"domain": "acme.test", "finding_id": "f012"},
                   "tool_response": "Saved [high] SQLi"})
        rows = [json.loads(x) for x in self._lines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "finding")
        self.assertEqual(rows[0]["domain"], "acme.test")
        self.assertEqual(rows[0]["id"], "f012")

    def test_ignores_non_state_tools(self):
        self._run({"tool_name": "mcp__praetor__curl_request", "session_id": "a",
                   "tool_input": {"url": "http://x"}})
        self.assertEqual(self._lines(), [])

    def test_multi_agent_sessions_distinct(self):
        self._run({"tool_name": "mcp__praetor__lock_findings", "session_id": "agentA",
                   "tool_input": {"domain": "d"}, "tool_response": "Locked 2"})
        self._run({"tool_name": "mcp__praetor__record_retest", "session_id": "agentB",
                   "tool_input": {"domain": "d", "finding_id": "f001"},
                   "tool_response": "Retest v2"})
        sids = {json.loads(x)["sid"] for x in self._lines()}
        self.assertEqual(sids, {"agentA", "agentB"})

    def test_fail_open_on_malformed(self):
        out = self._run("not json")
        self.assertEqual(out, "")
        self.assertEqual(self._lines(), [])

    def test_logs_confirm_poc_with_verdict_detail(self):
        """Every confirm_*/escalate_* call is a real PoC attempt — logged so
        "did you already test this" is answered from the trail, not memory."""
        self._run({"tool_name": "mcp__praetor__confirm_ssti", "session_id": "agent1",
                   "tool_input": {"endpoint": "https://shop.example.com/search",
                                  "parameter": "q"},
                   "tool_response": {"verdict": "CONFIRMED", "confidence": 0.9,
                                     "vuln_type": "ssti",
                                     "evidence_summary": "engine=twig expected='392' reflected",
                                     "logger_indices": [42]}})
        rows = [json.loads(x) for x in self._lines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "poc")
        self.assertEqual(rows[0]["domain"], "shop.example.com")
        self.assertEqual(rows[0]["id"], "q")
        self.assertIn("CONFIRMED", rows[0]["note"])
        self.assertIn("ssti", rows[0]["note"])
        self.assertIn("42", rows[0]["note"])

    def test_logs_a_failed_poc_too_not_only_confirmed_ones(self):
        """A FAILED attempt must also land in the log — otherwise re-reading
        it can't tell "not tried yet" apart from "tried, came back empty"."""
        self._run({"tool_name": "mcp__praetor__confirm_sqli", "session_id": "agent1",
                   "tool_input": {"endpoint": "https://shop.example.com/item",
                                  "parameter": "id"},
                   "tool_response": {"verdict": "FAILED", "confidence": 0.1,
                                     "vuln_type": "sqli",
                                     "evidence_summary": "no DBMS matched"}})
        rows = [json.loads(x) for x in self._lines()]
        self.assertEqual(len(rows), 1)
        self.assertIn("FAILED", rows[0]["note"])


if __name__ == "__main__":
    unittest.main()
