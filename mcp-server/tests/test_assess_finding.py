"""Calibration tests for assess_finding verdicts.

Pure stdlib (unittest + asyncio) — no pytest required. Run with:
    uv run python -m unittest tests.test_assess_finding -v

Each test asserts a synthetic finding produces the expected verdict band.
Catches regressions in NEVER SUBMIT matching, IDOR evidence, and dedup logic.
"""

import asyncio
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from burpsuite_mcp import server


class AssessFindingCalibration(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        # Wrap in staticmethod so instance access doesn't bind self
        cls.assess = staticmethod(server.mcp._tool_manager._tools["assess_finding"].fn)
        # Sandbox .burp-intel for dedup + program-policy tests
        cls.tmpdir = Path(tempfile.mkdtemp(prefix="burp-intel-test-"))
        cls.original_cwd = Path.cwd()
        os.chdir(cls.tmpdir)

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.original_cwd)
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    async def _call(self, **kwargs) -> str:
        # Default-stub the scope check: assume in-scope unless the test
        # explicitly overrides. The advisor calls /api/scope/check via httpx.
        async def fake_post(path, json=None):
            return {"in_scope": True}
        async def fake_get(path, params=None):
            return {}
        with patch("burpsuite_mcp.client.post", fake_post), \
             patch("burpsuite_mcp.client.get", fake_get):
            return await self.assess(**kwargs)

    async def test_self_xss_blocked(self):
        out = await self._call(
            vuln_type="xss",
            endpoint="/profile",
            evidence="payload only triggers when victim pastes JS into devtools — self-XSS",
            domain="example.com",
        )
        self.assertIn("DO NOT REPORT", out)
        self.assertIn("Self-XSS", out)

    async def test_self_xss_negated_passes(self):
        # "this is NOT self-xss because..." should not trip the gate
        out = await self._call(
            vuln_type="xss",
            endpoint="/profile",
            evidence="alert(1) executed in stored context, not a self-xss because attacker injects via /search",
            domain="example.com",
        )
        self.assertNotIn("DO NOT REPORT", out)
        # Negation must not redirect into a different rejection bucket.
        self.assertNotIn("Self-XSS", out)
        self.assertIn("VERDICT", out)

    async def test_idor_predictable_id_strong(self):
        out = await self._call(
            vuln_type="idor",
            endpoint="/api/users/{id}",
            evidence="user_id is sequential auto-increment; can fuzz id range to enumerate other accounts",
            domain="example.com",
        )
        # Must reach a positive verdict, NOT a "DO NOT REPORT" or weak-evidence rejection.
        self.assertIn("VERDICT: REPORT", out)
        self.assertNotIn("DO NOT REPORT", out)
        self.assertNotIn("Q5 WEAK EVIDENCE: IDOR", out)

    async def test_idor_no_evidence_weak(self):
        out = await self._call(
            vuln_type="idor",
            endpoint="/api/users/1",
            evidence="changed the id and got a different page",
            domain="example.com",
        )
        self.assertIn("Q5 WEAK EVIDENCE", out)

    async def test_sqli_strong_evidence_reports(self):
        out = await self._call(
            vuln_type="sqli",
            endpoint="/search",
            evidence="response time 5.2s with sleep(5), 0.1s baseline, confirmed 3/3 iterations",
            domain="example.com",
        )
        self.assertIn("VERDICT: REPORT", out)

    async def test_open_redirect_no_chain_blocked(self):
        out = await self._call(
            vuln_type="open_redirect_no_chain",
            endpoint="/redirect",
            evidence="redirects to evil.com via ?next=",
            domain="example.com",
        )
        self.assertIn("DO NOT REPORT", out)

    async def test_dedup_root_match_distinct_endpoints_pass(self):
        # Save a prior sqli finding at /a, then test /b — must not dedup
        intel = self.tmpdir / ".burp-intel" / "example.com"
        intel.mkdir(parents=True, exist_ok=True)
        (intel / "findings.json").write_text(json.dumps({
            "findings": [
                {"id": "f001", "endpoint": "/a", "vuln_type": "sqli",
                 "parameter": "q", "title": "sqli a"}
            ]
        }))
        out = await self._call(
            vuln_type="sqli",
            endpoint="/b",
            parameter="q",
            evidence="sleep(5) timing 5.1s baseline 0.1s 3/3 iterations",
            domain="example.com",
        )
        self.assertNotIn("Q4 DUPLICATE", out)

    async def test_dedup_root_match_same_endpoint_blocks(self):
        intel = self.tmpdir / ".burp-intel" / "example.com"
        intel.mkdir(parents=True, exist_ok=True)
        (intel / "findings.json").write_text(json.dumps({
            "findings": [
                {"id": "f002", "endpoint": "/c", "vuln_type": "sqli_blind",
                 "parameter": "q", "title": "blind sqli"}
            ]
        }))
        out = await self._call(
            vuln_type="sqli",
            endpoint="/c",
            parameter="q",
            evidence="sleep(5) confirmed 3/3 iterations",
            domain="example.com",
        )
        # sqli vs sqli_blind share root → dedup
        self.assertIn("Q4 DUPLICATE", out)

    async def test_human_verified_passes_weak_evidence(self):
        # Q5 evidence-strength check is skipped under human_verified=True;
        # the finding must reach a REPORT verdict despite thin prose.
        out = await self._call(
            vuln_type="idor",
            endpoint="/api/orders/1",
            parameter="id",
            evidence="changed id; got another user's order",
            human_verified=True,
            domain="example.com",
        )
        self.assertIn("VERDICT: REPORT", out)
        self.assertNotIn("Q5 WEAK EVIDENCE", out)

    async def test_overrides_q5_skips_evidence_gate(self):
        out = await self._call(
            vuln_type="idor",
            endpoint="/api/orders/2",
            parameter="id",
            evidence="lacks the magic words but verified by hand",
            overrides=["q5_evidence:hand-verified in Burp UI"],
            domain="example.com",
        )
        self.assertNotIn("Q5 WEAK EVIDENCE", out)

    async def test_clickjacking_never_submit_blocked(self):
        # Clickjacking on a non-sensitive page is in the NEVER SUBMIT list;
        # without chain_with[] it must not reach REPORT.
        out = await self._call(
            vuln_type="clickjacking",
            endpoint="/about",
            evidence="page can be framed; missing X-Frame-Options",
            domain="example.com",
        )
        self.assertIn("DO NOT REPORT", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
