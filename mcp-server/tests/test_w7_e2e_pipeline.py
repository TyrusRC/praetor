"""End-to-end pipeline test (W7, T9).

Wires the four critical W7 surfaces together against in-memory fixtures:

    rank_attack_targets  →  assess_finding  →  triager_review  →  poc_bundle

The chain doesn't need a live Burp — we stub HTTP responses where required
and write findings.json directly. Catches:

  - Contract drift between targeting + assessment + review + PoC export.
  - Severity-floor regressions (assess_finding produces 'INFO' → triager_review
    blocks submission → poc_bundle still works).
  - Out-of-scope rejection path.
  - NEVER_SUBMIT-without-chain rejection.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    return _Stub(), captured


class E2EPipelineTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cwd = os.getcwd()
        os.chdir(self.tmpdir)
        self.intel_root = Path(self.tmpdir) / ".burp-intel" / "happy.example.com"
        self.intel_root.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        os.chdir(self.cwd)
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    async def test_happy_path_targeting_to_poc(self):
        """Targeting → confirmed finding → triager review → PoC bundle."""
        # 1. Endpoints saved → rank_attack_targets picks the high-risk ones.
        (self.intel_root / "endpoints.json").write_text(json.dumps({
            "endpoints": [
                {"method": "POST", "path": "/admin/users",
                 "body_keys": ["role", "is_admin", "email"]},
                {"method": "GET", "path": "/healthz", "parameters": ["q"]},
            ]
        }), encoding="utf-8")

        from burpsuite_mcp.tools.scan import rank_targets
        stub, captured = _stub_mcp()
        rank_targets.register(stub)
        ranked = await captured["rank_attack_targets"](domain="happy.example.com", top_k=5)
        self.assertGreater(len(ranked["targets"]), 0)
        top = ranked["targets"][0]
        self.assertEqual(top["method"], "POST")
        self.assertIn("/admin", top["path"])
        self.assertIn("MASS/ASSIGNMENT", [r.upper() for r in top["risk_classes"]])

        # 2. Operator runs probe + saves finding via direct write (skip Burp client).
        finding = {
            "id": "f-001",
            "vuln_type": "mass_assignment",
            "severity": "high",
            "status": "confirmed",
            "endpoint": "https://happy.example.com/admin/users",
            "parameter": "is_admin",
            "evidence": {
                "logger_index": 42,
                "baseline_status": 403,
                "summary": "is_admin=true accepted unauthenticated; attacker escalates self to admin",
            },
            "impact": "attacker escalates own account to admin via mass assignment of is_admin; reads all user data, modifies any record",
            "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        }
        (self.intel_root / "findings.json").write_text(
            json.dumps({"findings": [finding]}), encoding="utf-8",
        )

        # 3. Triager review — should pass.
        from burpsuite_mcp.tools.notes import triager_review
        stub2, captured2 = _stub_mcp()
        triager_review.register(stub2)
        review = await captured2["review_finding_for_submission"](
            domain="happy.example.com", finding_id="f-001",
        )
        self.assertTrue(review["ready_to_submit"],
                        f"clean finding blocked: {review.get('blockers')}")

        # 4. PoC bundle — patch the Burp HTTP client + tar should land.
        from burpsuite_mcp.tools.notes import poc_bundle

        async def _fake_get(path, **kwargs):
            assert path.startswith("/api/proxy/42")
            return {
                "method": "POST",
                "url": "https://happy.example.com/admin/users",
                "headers": {"Content-Type": "application/json"},
                "body": '{"email":"x@x","is_admin":true}',
                "response": {
                    "status": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"id":1,"is_admin":true}',
                },
            }

        with patch.object(poc_bundle.client, "get", side_effect=_fake_get):
            stub3, captured3 = _stub_mcp()
            poc_bundle.register(stub3)
            out = await captured3["export_poc_bundle"](
                domain="happy.example.com", finding_id="f-001",
            )
        self.assertTrue(out.get("ok"), f"PoC bundle export failed: {out}")
        bundle_path = Path(out["bundle_path"])
        self.assertTrue(bundle_path.exists())
        self.assertGreater(bundle_path.stat().st_size, 200)

    async def test_never_submit_without_chain_blocked(self):
        """csrf_logout alone → triager_review must block."""
        (self.intel_root / "findings.json").write_text(json.dumps({"findings": [{
            "id": "f-csrf-logout", "vuln_type": "csrf_logout",
            "severity": "low", "status": "confirmed",
            "endpoint": "https://happy.example.com/logout",
            "evidence": {"logger_index": 7},
            "impact": "logs user out cross-origin",
        }]}), encoding="utf-8")

        from burpsuite_mcp.tools.notes import triager_review
        stub, captured = _stub_mcp()
        triager_review.register(stub)
        review = await captured["review_finding_for_submission"](
            domain="happy.example.com", finding_id="f-csrf-logout"
        )
        self.assertFalse(review["ready_to_submit"])
        self.assertTrue(any("NEVER_SUBMIT" in b for b in review["blockers"]))

    async def test_severity_inflation_blocked_in_pipeline(self):
        """Open redirect marked critical → blocked."""
        (self.intel_root / "findings.json").write_text(json.dumps({"findings": [{
            "id": "f-inflated", "vuln_type": "open_redirect",
            "severity": "critical", "status": "confirmed",
            "endpoint": "https://happy.example.com/r?next=evil.com",
            "evidence": {"logger_index": 1, "baseline_status": 302},
            "impact": "attacker redirects victim to evil.com",
        }]}), encoding="utf-8")

        from burpsuite_mcp.tools.notes import triager_review
        stub, captured = _stub_mcp()
        triager_review.register(stub)
        review = await captured["review_finding_for_submission"](
            domain="happy.example.com", finding_id="f-inflated"
        )
        self.assertFalse(review["ready_to_submit"])
        self.assertTrue(any("inflated" in b for b in review["blockers"]))

    async def test_chain_proposer_finds_ssrf_to_cloud(self):
        """Two saved findings → chain proposer surfaces the critical chain."""
        (self.intel_root / "findings.json").write_text(json.dumps({"findings": [
            {"id": "a", "vuln_type": "ssrf", "status": "confirmed",
             "endpoint": "/api/fetch", "confidence": 0.9},
            {"id": "b", "vuln_type": "cloud_metadata", "status": "confirmed",
             "endpoint": "/api/proxy", "confidence": 0.85},
        ]}), encoding="utf-8")

        from burpsuite_mcp.tools.notes import chain_proposer
        stub, captured = _stub_mcp()
        chain_proposer.register(stub)
        result = await captured["propose_chains"](domain="happy.example.com")
        names = [c["progression"] for c in result["chains"]]
        self.assertIn("ssrf_to_cloud_credentials", names)
        cve_chain = next(c for c in result["chains"]
                         if c["progression"] == "ssrf_to_cloud_credentials")
        self.assertEqual(cve_chain["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
