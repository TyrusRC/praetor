"""scanner_proof gate: unverified scanner output is not a finding.

Policy: "scanner output with no proof-of-impact" is ineligible. This gate closes
the gap that Q3 (auto-passes impact-inherent classes) and Q5 (passes on any
class keyword the scanner's own output contains) leave open. Pure stdlib.

    uv run python -m unittest tests.test_scanner_proof_gate -v
"""

import unittest
from unittest.mock import patch

from praetor import server


class ScannerProofGate(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.assess = staticmethod(server.mcp._tool_manager._tools["assess_finding"].fn)

    async def _call(self, **kwargs) -> str:
        async def fake_post(path, json=None):
            return {"in_scope": True}
        async def fake_get(path, params=None):
            # No captured request behind any proxy_history_index in these tests.
            return {}
        with patch("praetor.client.post", fake_post), \
             patch("praetor.client.get", fake_get):
            return await self.assess(**kwargs)

    async def test_scanner_only_sqli_rejected(self):
        # SQLi is impact-inherent (Q3 auto-pass) and the scanner's own text
        # carries a Q5 keyword ("sql syntax error") — every other gate passes.
        # The scanner-proof gate is the one that must catch it.
        out = await self._call(
            vuln_type="sqli",
            endpoint="/search",
            parameter="q",
            evidence="nuclei template matched: response contained a sql syntax error",
            domain="example.com",
        )
        self.assertIn("SCANNER OUTPUT, NO PROOF OF IMPACT", out)
        self.assertNotIn("VERDICT: REPORT", out)

    async def test_scanner_only_rce_rejected(self):
        out = await self._call(
            vuln_type="rce",
            endpoint="/exec",
            evidence="acunetix scanner flagged possible command execution; command output suspected",
            domain="example.com",
        )
        self.assertIn("SCANNER OUTPUT, NO PROOF OF IMPACT", out)
        self.assertNotIn("VERDICT: REPORT", out)

    async def test_real_impact_class_without_scanner_passes(self):
        # Same class, real hand-written proof, no scanner provenance → the gate
        # stays silent and the finding reaches REPORT.
        out = await self._call(
            vuln_type="sqli",
            endpoint="/search",
            evidence="response time 5.2s with sleep(5), 0.1s baseline, confirmed 3/3 iterations",
            domain="example.com",
        )
        self.assertNotIn("SCANNER OUTPUT, NO PROOF OF IMPACT", out)
        self.assertIn("VERDICT: REPORT", out)

    async def test_scanner_lead_with_demonstrated_capability_passes(self):
        # Scanner found it, but the operator went on to demonstrate an attacker
        # capability (exfiltrated another user's data) — corroborated, so pass.
        out = await self._call(
            vuln_type="idor",
            endpoint="/api/orders/1",
            parameter="id",
            evidence=(
                "nuclei flagged idor; confirmed by replay — incrementing order_id "
                "returned another user's order data"
            ),
            domain="example.com",
        )
        self.assertNotIn("SCANNER OUTPUT, NO PROOF OF IMPACT", out)

    async def test_scanner_with_reproductions_passes(self):
        out = await self._call(
            vuln_type="sqli_blind",
            endpoint="/search",
            evidence="wpscan reported blind sqli; sleep(5) confirmed 3/3 iterations",
            reproductions=[
                {"proxy_history_index": 1, "elapsed_ms": 5100, "status_code": 200},
                {"proxy_history_index": 2, "elapsed_ms": 5050, "status_code": 200},
                {"proxy_history_index": 3, "elapsed_ms": 5200, "status_code": 200},
            ],
            domain="example.com",
        )
        self.assertNotIn("SCANNER OUTPUT, NO PROOF OF IMPACT", out)

    async def test_scanner_only_with_override_passes(self):
        out = await self._call(
            vuln_type="sqli",
            endpoint="/search",
            evidence="nuclei template matched: sql syntax error",
            overrides=["scanner_proof:manually reviewed the captured response"],
            domain="example.com",
        )
        self.assertIn("SCANNER-PROOF OVERRIDE", out)
        self.assertNotIn("SCANNER OUTPUT, NO PROOF OF IMPACT", out)

    async def test_non_scanner_prose_unaffected(self):
        # No scanner provenance at all → gate never fires (even if thin).
        out = await self._call(
            vuln_type="idor",
            endpoint="/api/users/{id}",
            evidence="user_id is sequential auto-increment; can fuzz id range to enumerate other accounts",
            domain="example.com",
        )
        self.assertNotIn("SCANNER OUTPUT, NO PROOF OF IMPACT", out)
        self.assertIn("VERDICT: REPORT", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
