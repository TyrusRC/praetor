"""W12 verdict refactor batch 4 — 6 more testing tools.

Signature contracts + verdict_from_tally helper + KB promotion checks.
"""

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


class VerdictHelperTest(unittest.TestCase):

    def test_tally_three_levels(self):
        from burpsuite_mcp.tools.testing._verdict import verdict_from_tally
        self.assertEqual(verdict_from_tally(0)[0], "FAILED")
        self.assertEqual(verdict_from_tally(1)[0], "SUSPECTED")
        self.assertEqual(verdict_from_tally(2)[0], "CONFIRMED")
        self.assertEqual(verdict_from_tally(5)[0], "CONFIRMED")

    def test_tally_custom_threshold(self):
        from burpsuite_mcp.tools.testing._verdict import verdict_from_tally
        v, c = verdict_from_tally(2, confirmed_threshold=3,
                                  confirmed_confidence=0.9,
                                  suspected_confidence=0.6)
        self.assertEqual(v, "SUSPECTED")
        self.assertEqual(c, 0.6)
        v2, c2 = verdict_from_tally(3, confirmed_threshold=3,
                                    confirmed_confidence=0.9)
        self.assertEqual(v2, "CONFIRMED")
        self.assertEqual(c2, 0.9)


class WafBypassRefactorTest(unittest.TestCase):

    def test_probe_40x_bypass_returns_dict(self):
        from burpsuite_mcp.tools import waf_bypass
        stub, captured = _stub_mcp()
        waf_bypass.register(stub)
        sig = captured["probe_40x_bypass"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))


class TestingExtendedRefactorsTest(unittest.TestCase):

    def test_smuggling_returns_dict(self):
        from burpsuite_mcp.tools.testing_extended import smuggling
        stub, captured = _stub_mcp()
        smuggling.register(stub)
        sig = captured["test_request_smuggling"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_host_header_returns_dict(self):
        from burpsuite_mcp.tools.testing_extended import host_header
        stub, captured = _stub_mcp()
        host_header.register(stub)
        sig = captured["test_host_header"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_crlf_returns_dict(self):
        from burpsuite_mcp.tools.testing_extended import crlf
        stub, captured = _stub_mcp()
        crlf.register(stub)
        sig = captured["test_crlf_injection"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_idempotency_key_returns_dict(self):
        from burpsuite_mcp.tools.testing_extended import idempotency_key
        stub, captured = _stub_mcp()
        idempotency_key.register(stub)
        sig = captured["probe_idempotency_key"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_workflow_reorder_returns_dict(self):
        from burpsuite_mcp.tools.testing_extended import workflow_reorder
        stub, captured = _stub_mcp()
        workflow_reorder.register(stub)
        sig = captured["probe_workflow_reorder"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))


class KBPromotionsTest(unittest.TestCase):

    def test_csv_injection_active(self):
        from burpsuite_mcp.tools.scan._constants import _REFERENCE_ONLY
        self.assertNotIn("csv_injection", _REFERENCE_ONLY)

    def test_insecure_randomness_active(self):
        from burpsuite_mcp.tools.scan._constants import _REFERENCE_ONLY
        self.assertNotIn("insecure_randomness", _REFERENCE_ONLY)

    def test_csv_injection_has_w12_context(self):
        import json
        from pathlib import Path
        from burpsuite_mcp.tools.scan._constants import KNOWLEDGE_DIR
        data = json.loads(
            (Path(KNOWLEDGE_DIR) / "csv_injection.json").read_text(encoding="utf-8")
        )
        self.assertIn("csv_export_formula_reflection", data["contexts"])
        ctx = data["contexts"]["csv_export_formula_reflection"]
        self.assertGreater(len(ctx["probes"]), 0)
        # Probe should pair header + reflection matchers.
        types = {m["type"] for p in ctx["probes"] for m in p["matchers"]}
        self.assertIn("header", types)
        self.assertIn("reflection", types)

    def test_insecure_randomness_has_w12_contexts(self):
        import json
        from pathlib import Path
        from burpsuite_mcp.tools.scan._constants import KNOWLEDGE_DIR
        data = json.loads(
            (Path(KNOWLEDGE_DIR) / "insecure_randomness.json").read_text(encoding="utf-8")
        )
        for ctx in ("low_entropy_session_cookie", "reset_token_short_url"):
            self.assertIn(ctx, data["contexts"], f"W12 ctx missing: {ctx}")

    def test_uuid_v1_matcher_tightened(self):
        """W12 tightened uuid_v1_leak: was word:'-1' (FP), now full UUID regex."""
        import json
        from pathlib import Path
        from burpsuite_mcp.tools.scan._constants import KNOWLEDGE_DIR
        data = json.loads(
            (Path(KNOWLEDGE_DIR) / "insecure_randomness.json").read_text(encoding="utf-8")
        )
        ctx = data["contexts"]["uuid_v1_leak"]
        matchers = ctx["probes"][0]["matchers"]
        types = [m["type"] for m in matchers]
        self.assertIn("regex", types,
            "uuid_v1_leak should use regex matcher (post-W12); had word with literal '-1'")


if __name__ == "__main__":
    unittest.main()
