"""W15 verdict refactor final batch — 6 tools + ref-only KB stability."""

from __future__ import annotations

import unittest


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    return _Stub(), captured


class W15TestingRefactorsTest(unittest.TestCase):

    def test_fuzz_parameter_returns_dict(self):
        from burpsuite_mcp.tools.testing import fuzz
        stub, captured = _stub_mcp()
        fuzz.register(stub)
        sig = captured["fuzz_parameter"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_fuzz_with_feedback_returns_dict(self):
        from burpsuite_mcp.tools.testing import fuzz_feedback
        stub, captured = _stub_mcp()
        fuzz_feedback.register(stub)
        sig = captured["fuzz_with_feedback"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))


class W15TestingExtendedRefactorsTest(unittest.TestCase):

    def test_internal_headers_returns_dict(self):
        from burpsuite_mcp.tools.testing_extended import internal_headers
        stub, captured = _stub_mcp()
        internal_headers.register(stub)
        sig = captured["probe_internal_headers"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_quota_window_returns_dict(self):
        from burpsuite_mcp.tools.testing_extended import quota_window
        stub, captured = _stub_mcp()
        quota_window.register(stub)
        sig = captured["probe_quota_window_edge"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_decimal_rounding_returns_dict(self):
        from burpsuite_mcp.tools.testing_extended import decimal_rounding
        stub, captured = _stub_mcp()
        decimal_rounding.register(stub)
        sig = captured["probe_float_decimal_rounding"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_cron_backfill_returns_dict(self):
        from burpsuite_mcp.tools.testing_extended import cron_backfill
        stub, captured = _stub_mcp()
        cron_backfill.register(stub)
        sig = captured["probe_cron_backfill"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))


class RefOnlyKBStabilityTest(unittest.TestCase):
    """W15 audit: lock in the ref-only set so future waves don't re-audit.

    Every entry must be in the W15 verdict-tools.md "Ref-only KB policy"
    table with a documented reason. If you intentionally promote an entry,
    remove it from this expected set AND from the skill table.
    """

    EXPECTED_REF_ONLY = {
        "captcha_bypass",
        "ci_actions_injection",
        "dependency_confusion",
        "desktop_electron",
        "h2_continuation_flood",
        "http2_connect_portscan",
        "http3_quic",
        "kubernetes_exposed",
        "race_condition",
        "request_smuggling",
        "saml_xsw",
        "soapwn",
        "source_code_exposure",
        "tech_vulns",
        "web_cache_poisoning_dos",
        "xs_leak",
        "zip_slip",
    }

    def test_ref_only_set_matches_audit(self):
        from burpsuite_mcp.tools.scan._constants import _REFERENCE_ONLY
        # Allow superset so adding new ref-only KBs doesn't break the test —
        # but any REMOVAL from expected must be deliberate and documented.
        missing = self.EXPECTED_REF_ONLY - _REFERENCE_ONLY
        self.assertEqual(missing, set(),
            f"KBs were promoted out of ref-only without updating expected set: {missing}. "
            f"Update verdict-tools.md Ref-only KB table and this test.")


class VerdictToolsSkillW15Test(unittest.TestCase):

    def test_skill_documents_ref_only_policy(self):
        from pathlib import Path
        path = Path("../.claude/skills/verdict-tools.md")
        if not path.exists():
            path = Path(".claude/skills/verdict-tools.md")
        content = path.read_text(encoding="utf-8")
        for marker in ("Ref-only KB policy", "captcha_bypass", "h2_continuation_flood",
                       "saml_xsw", "Coverage as of W15", "43 testing tools"):
            self.assertIn(marker, content, f"missing W15 skill marker: {marker}")


if __name__ == "__main__":
    unittest.main()
