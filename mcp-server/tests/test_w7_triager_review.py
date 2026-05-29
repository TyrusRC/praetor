"""Tests for review_finding_for_submission (W7, T2)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from burpsuite_mcp.tools.notes import triager_review


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    return _Stub(), captured


class TriagerReviewTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cwd = os.getcwd()
        os.chdir(self.tmpdir)
        self.domain_dir = Path(self.tmpdir) / ".burp-intel" / "demo.example.com"
        self.domain_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        os.chdir(self.cwd)
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write(self, item: dict):
        (self.domain_dir / "findings.json").write_text(
            json.dumps({"findings": [item]}), encoding="utf-8"
        )

    async def _run(self, finding_id: str = "f1") -> dict:
        stub, captured = _stub_mcp()
        triager_review.register(stub)
        return await captured["review_finding_for_submission"](
            domain="demo.example.com", finding_id=finding_id
        )

    async def test_clean_critical_passes(self):
        self._write({
            "id": "f1", "vuln_type": "rce", "severity": "critical", "status": "confirmed",
            "endpoint": "https://demo.example.com/api/x",
            "evidence": {"logger_index": 5, "baseline_status": 200, "summary": "attacker executes id command; uid=33 output"},
            "impact": "attacker executes arbitrary commands as web user, reads /etc/shadow",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        })
        result = await self._run()
        self.assertTrue(result["ready_to_submit"], f"blockers: {result.get('blockers')}")

    async def test_severity_inflation_blocked(self):
        self._write({
            "id": "f1", "vuln_type": "open_redirect", "severity": "critical", "status": "confirmed",
            "endpoint": "https://demo.example.com/r",
            "evidence": {"logger_index": 5},
            "impact": "attacker redirects user to attacker.com",
        })
        result = await self._run()
        self.assertFalse(result["ready_to_submit"])
        self.assertTrue(any("inflated" in b for b in result["blockers"]))

    async def test_slop_phrasing_blocked(self):
        self._write({
            "id": "f1", "vuln_type": "sqli", "severity": "high", "status": "confirmed",
            "endpoint": "https://demo.example.com/q",
            "evidence": {"logger_index": 5},
            "description": "this could lead to potential database leakage, may allow data exfil",
        })
        result = await self._run()
        self.assertFalse(result["ready_to_submit"])
        self.assertTrue(any("weak impact phrasing" in b for b in result["blockers"]))

    async def test_no_burp_index_blocked(self):
        self._write({
            "id": "f1", "vuln_type": "xss", "severity": "medium", "status": "confirmed",
            "endpoint": "https://demo.example.com/x",
            "evidence": {},
            "impact": "attacker injects script in target.com context",
        })
        result = await self._run()
        self.assertFalse(result["ready_to_submit"])
        self.assertTrue(any("Burp index" in b for b in result["blockers"]))

    async def test_never_submit_alone_blocked(self):
        self._write({
            "id": "f1", "vuln_type": "csrf_logout", "severity": "low", "status": "confirmed",
            "endpoint": "https://demo.example.com/logout",
            "evidence": {"logger_index": 1},
            "impact": "logs user out without consent",
        })
        result = await self._run()
        self.assertFalse(result["ready_to_submit"])
        self.assertTrue(any("NEVER_SUBMIT" in b for b in result["blockers"]))

    async def test_self_xss_blocked(self):
        self._write({
            "id": "f1", "vuln_type": "xss", "severity": "high", "status": "confirmed",
            "endpoint": "https://demo.example.com/x",
            "evidence": {"logger_index": 5},
            "description": "user pastes <script>alert(1)</script> in devtools console",
        })
        result = await self._run()
        self.assertFalse(result["ready_to_submit"])

    async def test_suspected_status_blocked(self):
        self._write({
            "id": "f1", "vuln_type": "rce", "severity": "critical", "status": "suspected",
            "endpoint": "https://demo.example.com/x",
            "evidence": {"logger_index": 5},
            "impact": "attacker executes commands",
        })
        result = await self._run()
        self.assertFalse(result["ready_to_submit"])

    async def test_timing_class_requires_reproductions(self):
        self._write({
            "id": "f1", "vuln_type": "sqli_time", "severity": "high", "status": "confirmed",
            "endpoint": "https://demo.example.com/q",
            "evidence": {"logger_index": 5, "reproductions": [{"logger_index": 5, "elapsed_ms": 5100}]},
            "impact": "blind SQL injection via time-based delay",
        })
        result = await self._run()
        self.assertFalse(result["ready_to_submit"])
        self.assertTrue(any("reproductions" in b for b in result["blockers"]))


if __name__ == "__main__":
    unittest.main()
