"""finding-guard PreToolUse hook — blocks silent re-verdict/delete of a LOCKED finding.

Runs the actual hook script as a subprocess (as Claude Code would), fail-open.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOK = (Path(__file__).resolve().parents[2]
        / ".claude" / "hooks" / "finding-guard.py")


def _run(cwd: Path, payload: dict) -> str:
    p = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(payload), capture_output=True, text=True, cwd=str(cwd),
    )
    return p.stdout


class FindingGuardHookTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        fdir = self.dir / ".burp-intel" / "acme.test"
        fdir.mkdir(parents=True)
        (fdir / "findings.json").write_text(json.dumps({"findings": [
            {"id": "f001", "status": "confirmed", "locked": True, "title": "SQLi"},
            {"id": "f002", "status": "confirmed", "title": "XSS"},
        ]}))

    def _denied(self, out: str) -> bool:
        if not out.strip():
            return False
        return json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_blocks_status_flip_on_locked(self):
        out = _run(self.dir, {"tool_name": "mcp__praetor__record_retest",
                              "tool_input": {"finding_id": "f001",
                                             "domain": "acme.test",
                                             "status": "regressed"}})
        self.assertTrue(self._denied(out))

    def test_blocks_false_positive_delete_on_locked(self):
        out = _run(self.dir, {"tool_name": "mcp__praetor__mark_finding_false_positive",
                              "tool_input": {"finding_id": "f001",
                                             "domain": "acme.test"}})
        self.assertTrue(self._denied(out))

    def test_allows_change_on_unlocked(self):
        out = _run(self.dir, {"tool_name": "mcp__praetor__record_retest",
                              "tool_input": {"finding_id": "f002",
                                             "domain": "acme.test",
                                             "status": "regressed"}})
        self.assertFalse(self._denied(out))

    def test_allows_same_status_on_locked(self):
        out = _run(self.dir, {"tool_name": "mcp__praetor__record_retest",
                              "tool_input": {"finding_id": "f001",
                                             "domain": "acme.test",
                                             "status": "confirmed"}})
        self.assertFalse(self._denied(out))

    def test_fails_open_on_malformed(self):
        p = subprocess.run([sys.executable, str(HOOK)], input="not json",
                           capture_output=True, text=True, cwd=str(self.dir))
        self.assertEqual(p.stdout.strip(), "")

    def test_blocks_via_project_dir_when_cwd_drifts(self):
        # Hook run from an unrelated cwd but CLAUDE_PROJECT_DIR points at the store:
        # must still find the locked finding (never silently allow on a cwd drift).
        other = Path(tempfile.mkdtemp())
        env = {**os.environ, "CLAUDE_PROJECT_DIR": str(self.dir)}
        p = subprocess.run(
            [sys.executable, str(HOOK)],
            input=json.dumps({"tool_name": "mcp__praetor__record_retest",
                              "tool_input": {"finding_id": "f001",
                                             "domain": "acme.test",
                                             "status": "regressed"}}),
            capture_output=True, text=True, cwd=str(other), env=env)
        self.assertTrue(self._denied(p.stdout))


if __name__ == "__main__":
    unittest.main()
