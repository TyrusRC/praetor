"""W11 verdict refactor batch 3 — 8 more testing tools converted to dict.

Signature contracts for the 8 newly refactored tools.
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


class VulnRefactorsTest(unittest.TestCase):

    def test_websocket_returns_dict(self):
        from burpsuite_mcp.tools.vuln import test_websocket
        stub, captured = _stub_mcp()
        test_websocket.register(stub)
        sig = captured["test_websocket"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_prototype_pollution_returns_dict(self):
        from burpsuite_mcp.tools.vuln import test_prototype_pollution
        stub, captured = _stub_mcp()
        test_prototype_pollution.register(stub)
        sig = captured["test_prototype_pollution"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))


class EdgeRefactorsTest(unittest.TestCase):

    def test_cors_cloud_metadata_file_upload_return_dict(self):
        from burpsuite_mcp.tools import edge
        stub, captured = _stub_mcp()
        edge.register(stub)
        for name in ("test_cors", "test_cloud_metadata", "test_file_upload"):
            self.assertIn(name, captured, f"wrapper missing: {name}")
            sig = captured[name].__annotations__.get("return")
            self.assertIn(sig, (dict, "dict"),
                          f"{name}: return type wrong: {sig!r}")


class TestingExtendedRefactorsTest(unittest.TestCase):

    def test_business_logic_returns_dict(self):
        from burpsuite_mcp.tools.testing_extended import business_logic
        stub, captured = _stub_mcp()
        business_logic.register(stub)
        sig = captured["test_business_logic"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_mass_assignment_returns_dict(self):
        from burpsuite_mcp.tools.testing_extended import mass_assignment
        stub, captured = _stub_mcp()
        mass_assignment.register(stub)
        sig = captured["test_mass_assignment"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))

    def test_cache_poisoning_returns_dict(self):
        from burpsuite_mcp.tools.testing_extended import cache_poisoning
        stub, captured = _stub_mcp()
        cache_poisoning.register(stub)
        sig = captured["test_cache_poisoning"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))


class ClickjackingPromotionTest(unittest.TestCase):

    def test_clickjacking_no_longer_reference_only(self):
        from burpsuite_mcp.tools.scan._constants import _REFERENCE_ONLY
        self.assertNotIn("clickjacking", _REFERENCE_ONLY)

    def test_clickjacking_matchers_normalised(self):
        """W11 normalised not_header matchers: should use `name` (singular)
        instead of `headers` (array). Production MatcherEngine schema."""
        import json
        from pathlib import Path
        from burpsuite_mcp.tools.scan._constants import KNOWLEDGE_DIR
        data = json.loads(
            (Path(KNOWLEDGE_DIR) / "clickjacking.json").read_text(encoding="utf-8")
        )
        for ctx_name, ctx in data["contexts"].items():
            for probe in ctx.get("probes", []):
                for m in probe.get("matchers", []):
                    if m.get("type") == "not_header":
                        self.assertIn("name", m,
                            f"{ctx_name}: not_header missing 'name' field; got {m}")
                        self.assertNotIn("headers", m,
                            f"{ctx_name}: not_header still uses plural 'headers'")

    def test_missing_frameguard_has_state_change_positive(self):
        """W11 tightened missing_frameguard with word matcher (settings/account/...)."""
        import json
        from pathlib import Path
        from burpsuite_mcp.tools.scan._constants import KNOWLEDGE_DIR
        data = json.loads(
            (Path(KNOWLEDGE_DIR) / "clickjacking.json").read_text(encoding="utf-8")
        )
        probe = data["contexts"]["missing_frameguard"]["probes"][0]
        # First matcher should be the word positive (state-change kw).
        types = [m.get("type") for m in probe["matchers"]]
        self.assertIn("word", types,
            "missing_frameguard should include a positive 'word' matcher to suppress baseline FP")


class ReadmeTakeoverDocTest(unittest.TestCase):

    def test_readme_documents_dns_only(self):
        from pathlib import Path
        readme = Path("../README.md")
        if not readme.exists():
            readme = Path("README.md")
        content = readme.read_text(encoding="utf-8")
        # README uses "DNS-only" with caps; fingerprints.py uses dns_only literal.
        for marker in ("test_subdomain_takeover", "DNS-only", "ElasticBeanstalk", "129"):
            self.assertIn(marker, content,
                f"README missing W11 takeover doc marker: {marker}")


class MobileAgentWebViewHandoffTest(unittest.TestCase):

    def test_mobile_dynamic_agent_references_webview_kb(self):
        from pathlib import Path
        path = Path("../.claude/agents/mobile-dynamic-agent.md")
        if not path.exists():
            path = Path(".claude/agents/mobile-dynamic-agent.md")
        content = path.read_text(encoding="utf-8")
        for marker in ("webview_injection", "mobile_frida_snippet",
                       "mobile_adb_pack"):
            self.assertIn(marker, content,
                f"mobile-dynamic-agent missing W11 handoff marker: {marker}")


if __name__ == "__main__":
    unittest.main()
