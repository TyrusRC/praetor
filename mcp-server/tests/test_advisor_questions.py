"""Per-question check() smoke tests.

Each module under advisor_kb (q1_scope, q2_repro, q4_dedup, q5_evidence,
q6_never_submit, q7_triager) exports `async def check(ctx) -> CheckResult`.
Tests construct an AssessContext directly, drive one check, and assert on
the verdict / issues / weak_evidence side-effects + the returned CheckResult.

Behaviour parity with the monolithic assess_finding_impl is covered by
tests/test_assess_finding.py and the _baseline_capture harness.
"""

import asyncio
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from burpsuite_mcp.tools.advisor._context import AssessContext
from burpsuite_mcp.tools.advisor_kb import (
    NEVER_SUBMIT_TYPES,
    SENSITIVE_ENDPOINT_PATTERNS,
    CheckResult,
    q1_scope,
    q2_repro,
    q3_impact,
    q4_dedup,
    q5_evidence,
    q6_never_submit,
    q7_triager,
)


def _ctx(**kw) -> AssessContext:
    """Build an AssessContext with sensible defaults the orchestrator would set."""
    ctx = AssessContext(
        vuln_type=kw.pop("vuln_type", "xss"),
        evidence=kw.pop("evidence", "alert(1) executed"),
        endpoint=kw.pop("endpoint", "/x"),
        parameter=kw.pop("parameter", ""),
        domain=kw.pop("domain", "example.com"),
        chain_with=kw.pop("chain_with", []),
        reproductions=kw.pop("reproductions", []),
        human_verified=kw.pop("human_verified", False),
        never_submit_types=dict(NEVER_SUBMIT_TYPES),
    )
    ctx.vuln_lower = ctx.vuln_type.lower()
    ctx.evidence_lower = ctx.evidence.lower()
    ctx.effective_domain = ctx.domain
    ctx.q2_class_root = ctx.vuln_lower
    ctx.endpoint_lower = ctx.endpoint.lower()
    ctx.endpoint_is_sensitive = any(
        p in ctx.endpoint_lower for p in SENSITIVE_ENDPOINT_PATTERNS
    )
    ctx.chain_provided = bool(ctx.chain_with)
    overrides = kw.pop("overrides", [])
    for ov in overrides:
        gate = (ov.split(":", 1)[0] if ":" in ov else ov).strip().lower()
        if gate:
            ctx.override_set.add(gate)
            ctx.audit_overrides.append(ov)
    for k, v in kw.items():
        setattr(ctx, k, v)
    return ctx


def _shape(result) -> bool:
    """Assert CheckResult shape: passed:bool, reason:str, evidence:dict."""
    return (
        isinstance(result, dict)
        and isinstance(result.get("passed"), bool)
        and isinstance(result.get("reason"), str)
        and isinstance(result.get("evidence"), dict)
    )


class Q1ScopeTest(unittest.IsolatedAsyncioTestCase):
    async def test_override_bypasses_scope_call(self):
        ctx = _ctx(overrides=["q1_scope:authorised"])
        result = await q1_scope.check(ctx)
        self.assertTrue(_shape(result))
        self.assertTrue(result["passed"])
        self.assertEqual(result["reason"], "override")
        self.assertTrue(any("Q1 OVERRIDE" in i for i in ctx.issues))

    async def test_operator_mode_passes_without_call(self):
        ctx = _ctx(domain="example.com")
        # Default _scope_mode returns "operator" in tests
        result = await q1_scope.check(ctx)
        self.assertTrue(result["passed"])
        self.assertTrue(any("operator-mode" in i for i in ctx.issues))
        self.assertNotEqual(ctx.verdict, "DO NOT REPORT")


class Q2ReproTest(unittest.IsolatedAsyncioTestCase):
    async def test_override_bypass(self):
        ctx = _ctx(overrides=["q2_repro:flaky-net"])
        result = await q2_repro.check(ctx)
        self.assertTrue(_shape(result))
        self.assertTrue(result["passed"])
        self.assertTrue(any("Q2 OVERRIDE" in i for i in ctx.issues))

    async def test_auth_state_dependent_exempt(self):
        ctx = _ctx(vuln_type="idor", q2_class_root="idor")
        result = await q2_repro.check(ctx)
        self.assertTrue(result["passed"])
        self.assertEqual(result["reason"], "auth-state-exempt")
        self.assertTrue(any("Q2 EXEMPT" in i for i in ctx.issues))

    async def test_intermittent_fails(self):
        ctx = _ctx(
            vuln_type="xss",
            evidence="alert(1) once, intermittent, could not reproduce",
        )
        result = await q2_repro.check(ctx)
        self.assertFalse(result["passed"])
        self.assertTrue(any("Q2 FAIL" in i for i in ctx.issues))


class Q4DedupTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="burp-q4-"))
        self.original_cwd = Path.cwd()
        os.chdir(self.tmpdir)

    async def asyncTearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    async def test_unique_passes(self):
        # Seed an unrelated finding so the findings.json exists but doesn't match
        intel = self.tmpdir / ".burp-intel" / "d.example"
        intel.mkdir(parents=True, exist_ok=True)
        (intel / "findings.json").write_text(json.dumps({
            "findings": [
                {"id": "f999", "endpoint": "/other", "vuln_type": "xss",
                 "parameter": "p", "title": "unrelated"}
            ]
        }))
        ctx = _ctx(vuln_type="sqli", endpoint="/a", parameter="q", domain="d.example")
        result = await q4_dedup.check(ctx)
        self.assertTrue(_shape(result))
        self.assertTrue(result["passed"])
        self.assertEqual(result["reason"], "unique")

    async def test_duplicate_blocks(self):
        intel = self.tmpdir / ".burp-intel" / "d.example"
        intel.mkdir(parents=True, exist_ok=True)
        (intel / "findings.json").write_text(json.dumps({
            "findings": [
                {"id": "f001", "endpoint": "/dup", "vuln_type": "sqli",
                 "parameter": "q", "title": "prior"}
            ]
        }))
        ctx = _ctx(vuln_type="sqli", endpoint="/dup", parameter="q", domain="d.example")
        result = await q4_dedup.check(ctx)
        self.assertFalse(result["passed"])
        self.assertEqual(ctx.verdict, "DO NOT REPORT")
        self.assertTrue(any("Q4 DUPLICATE" in i for i in ctx.issues))


class Q5EvidenceTest(unittest.IsolatedAsyncioTestCase):
    async def test_strong_evidence_passes(self):
        ctx = _ctx(vuln_type="xss", evidence="alert(1) executed in <script> context")
        result = await q5_evidence.check(ctx)
        self.assertTrue(_shape(result))
        self.assertTrue(result["passed"])
        self.assertFalse(ctx.weak_evidence)

    async def test_weak_evidence_flags(self):
        ctx = _ctx(vuln_type="xss", evidence="something happened on the page")
        result = await q5_evidence.check(ctx)
        self.assertFalse(result["passed"])
        self.assertTrue(ctx.weak_evidence)
        self.assertTrue(any("Q5 WEAK EVIDENCE" in i for i in ctx.issues))

    async def test_human_verified_skips(self):
        ctx = _ctx(vuln_type="idor", human_verified=True,
                   evidence="changed id; got other user")
        result = await q5_evidence.check(ctx)
        self.assertTrue(result["passed"])
        self.assertEqual(result["reason"], "human_verified")
        self.assertTrue(any("Q5 SKIP" in i for i in ctx.issues))

    async def test_unknown_vuln_marks_weak(self):
        ctx = _ctx(vuln_type="invented_class", evidence="anything")
        await q5_evidence.check(ctx)
        self.assertTrue(ctx.weak_evidence)
        self.assertTrue(any("Q5 UNKNOWN VULN TYPE" in i for i in ctx.issues))

    async def test_timing_requires_repros(self):
        ctx = _ctx(vuln_type="sqli_blind", evidence="sleep(5) triggers delay")
        ctx.vuln_lower = "sqli_blind"
        await q5_evidence.check(ctx)
        self.assertTrue(ctx.weak_evidence)
        self.assertTrue(any("Q5 TIMING RULE" in i for i in ctx.issues))

    async def test_timing_satisfied_by_reproductions(self):
        ctx = _ctx(
            vuln_type="sqli_blind",
            evidence="sleep(5) confirmed 3/3 iterations",
            reproductions=[
                {"logger_index": 1, "elapsed_ms": 5000, "status_code": 200},
                {"logger_index": 2, "elapsed_ms": 5050, "status_code": 200},
                {"logger_index": 3, "elapsed_ms": 5100, "status_code": 200},
            ],
        )
        ctx.vuln_lower = "sqli_blind"
        await q5_evidence.check(ctx)
        self.assertTrue(any("Q5 TIMING SATISFIED" in i for i in ctx.issues))


class Q6NeverSubmitTest(unittest.IsolatedAsyncioTestCase):
    async def test_self_xss_blocked(self):
        ctx = _ctx(
            vuln_type="self_xss",
            evidence="victim pastes payload into devtools",
        )
        result = await q6_never_submit.check(ctx)
        self.assertTrue(_shape(result))
        self.assertFalse(result["passed"])
        self.assertEqual(ctx.verdict, "DO NOT REPORT")
        self.assertTrue(any("Q6 NEVER SUBMIT" in i for i in ctx.issues))

    async def test_override_bypasses(self):
        ctx = _ctx(vuln_type="self_xss", overrides=["q6_never_submit:chained"])
        result = await q6_never_submit.check(ctx)
        self.assertTrue(result["passed"])
        self.assertNotEqual(ctx.verdict, "DO NOT REPORT")

    async def test_clickjacking_sensitive_endpoint_passes(self):
        ctx = _ctx(vuln_type="clickjacking", endpoint="/transfer-funds")
        # Recompute endpoint_is_sensitive
        ctx.endpoint_lower = ctx.endpoint.lower()
        ctx.endpoint_is_sensitive = any(
            p in ctx.endpoint_lower for p in SENSITIVE_ENDPOINT_PATTERNS
        )
        result = await q6_never_submit.check(ctx)
        self.assertTrue(result["passed"])
        self.assertNotEqual(ctx.verdict, "DO NOT REPORT")
        self.assertTrue(any("CONDITIONAL PASS" in i for i in ctx.issues))

    async def test_evidence_keyword_negation_skipped(self):
        ctx = _ctx(
            vuln_type="sqli",
            evidence="not a stack trace, but pg_query syntax error confirmed",
        )
        result = await q6_never_submit.check(ctx)
        self.assertTrue(result["passed"])
        self.assertNotEqual(ctx.verdict, "DO NOT REPORT")


class Q7TriagerTest(unittest.IsolatedAsyncioTestCase):
    async def test_override_bypass(self):
        ctx = _ctx(vuln_type="open_redirect", overrides=["q7_triager:chained"])
        result = await q7_triager.check(ctx)
        self.assertTrue(_shape(result))
        self.assertTrue(result["passed"])
        self.assertTrue(any("Q7 OVERRIDE" in i for i in ctx.issues))

    async def test_low_impact_weak_downgrades(self):
        ctx = _ctx(vuln_type="open_redirect", evidence="weak prose")
        ctx.weak_evidence = True
        ctx.verdict = "REPORT"
        result = await q7_triager.check(ctx)
        self.assertFalse(result["passed"])
        self.assertEqual(ctx.verdict, "NEEDS MORE EVIDENCE")
        self.assertTrue(any("Q7 TRIAGER TEST" in i for i in ctx.issues))

    async def test_chain_supplies_impact(self):
        ctx = _ctx(vuln_type="open_redirect", chain_with=["f1"])
        ctx.chain_provided = True
        ctx.weak_evidence = True
        result = await q7_triager.check(ctx)
        self.assertTrue(result["passed"])
        self.assertEqual(result["reason"], "chained")


class Q3PlaceholderTest(unittest.IsolatedAsyncioTestCase):
    async def test_q3_is_noop_pass(self):
        ctx = _ctx()
        result = await q3_impact.check(ctx)
        self.assertTrue(_shape(result))
        self.assertTrue(result["passed"])
        self.assertEqual(result["reason"], "delegated-to-impact-scoring")


class CheckResultShapeTest(unittest.IsolatedAsyncioTestCase):
    """Smoke test: every check returns a CheckResult-shaped dict."""

    async def test_all_modules_return_check_result(self):
        modules = (q1_scope, q2_repro, q3_impact, q4_dedup,
                   q5_evidence, q6_never_submit, q7_triager)
        for mod in modules:
            ctx = _ctx()
            result = await mod.check(ctx)
            self.assertTrue(_shape(result), f"{mod.__name__} returned malformed result")


if __name__ == "__main__":
    unittest.main(verbosity=2)
