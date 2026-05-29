"""W13 verdict refactor batch 5 — 5 testing tools + web_cache_deception
promotion + verdict-tools skill.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    return _Stub(), captured


class W13TestingRefactorsTest(unittest.TestCase):

    def test_hpp_returns_dict(self):
        from burpsuite_mcp.tools.testing import hpp
        stub, captured = _stub_mcp()
        hpp.register(stub)
        sig = captured["test_parameter_pollution"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_rate_limit_returns_dict(self):
        from burpsuite_mcp.tools.testing import rate_limit
        stub, captured = _stub_mcp()
        rate_limit.register(stub)
        sig = captured["test_rate_limit"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_auth_compare_returns_dict(self):
        from burpsuite_mcp.tools.testing import auth_compare
        stub, captured = _stub_mcp()
        auth_compare.register(stub)
        sig = captured["compare_auth_states"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_id_monotonic_returns_dict(self):
        from burpsuite_mcp.tools.testing import id_monotonic
        stub, captured = _stub_mcp()
        id_monotonic.register(stub)
        sig = captured["probe_id_monotonic"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_cross_transport_returns_dict(self):
        from burpsuite_mcp.tools.testing import cross_transport
        stub, captured = _stub_mcp()
        cross_transport.register(stub)
        sig = captured["probe_cross_transport_idor"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))


class WebCacheDeceptionPromotionTest(unittest.TestCase):

    def test_now_active(self):
        from burpsuite_mcp.tools.scan._constants import _REFERENCE_ONLY
        self.assertNotIn("web_cache_deception", _REFERENCE_ONLY)

    def test_w13_context_added(self):
        from burpsuite_mcp.tools.scan._constants import KNOWLEDGE_DIR
        data = json.loads(
            (Path(KNOWLEDGE_DIR) / "web_cache_deception.json").read_text(encoding="utf-8")
        )
        self.assertIn("static_suffix_cache_poisoning", data["contexts"])
        ctx = data["contexts"]["static_suffix_cache_poisoning"]
        # Probes must pair status + word + cache header signal.
        types = {m["type"] for p in ctx["probes"] for m in p["matchers"]}
        self.assertIn("status", types)
        self.assertIn("word", types)
        self.assertIn("header", types)

    def test_path_confusion_schema_normalised(self):
        """W13 normalised plural `headers:[X]` to per-header `name:X` probes."""
        from burpsuite_mcp.tools.scan._constants import KNOWLEDGE_DIR
        data = json.loads(
            (Path(KNOWLEDGE_DIR) / "web_cache_deception.json").read_text(encoding="utf-8")
        )
        for ctx_name, ctx in data["contexts"].items():
            for probe in ctx.get("probes", []):
                for m in probe.get("matchers", []):
                    if m.get("type") == "header":
                        # Either has 'name' (post-W13 normalised) OR no 'headers' field.
                        if "name" not in m:
                            self.assertNotIn("headers", m,
                                f"{ctx_name}: header matcher still uses plural 'headers' field")


class VerdictToolsSkillTest(unittest.TestCase):

    def test_skill_present(self):
        path = Path("../.claude/skills/verdict-tools.md")
        if not path.exists():
            path = Path(".claude/skills/verdict-tools.md")
        self.assertTrue(path.exists(), f"verdict-tools skill missing at {path}")
        content = path.read_text(encoding="utf-8")
        for marker in ("VerdictResult", "CONFIRMED", "verdict_from_tally",
                       "make_verdict", "error_verdict", "is_actionable",
                       "to_assess_evidence"):
            self.assertIn(marker, content, f"missing marker: {marker}")


if __name__ == "__main__":
    unittest.main()
