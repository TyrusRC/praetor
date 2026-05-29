"""W10 verdict refactor batch 2 — 6 more testing tools converted to dict.

Verifies signature contracts. Functional tests deferred to live-target runs.
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


class SSRFRefactorTest(unittest.TestCase):

    def test_signature_returns_dict(self):
        from burpsuite_mcp.tools.vuln import test_ssrf
        stub, captured = _stub_mcp()
        test_ssrf.register(stub)
        sig = captured["test_ssrf"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))


class SSTIRefactorTest(unittest.TestCase):

    def test_signature_returns_dict(self):
        from burpsuite_mcp.tools.vuln import test_ssti
        stub, captured = _stub_mcp()
        test_ssti.register(stub)
        sig = captured["test_ssti"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))


class XXERefactorTest(unittest.TestCase):

    def test_signature_returns_dict(self):
        from burpsuite_mcp.tools.vuln import test_xxe
        stub, captured = _stub_mcp()
        test_xxe.register(stub)
        sig = captured["test_xxe"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))


class EdgeWrappersRefactorTest(unittest.TestCase):

    def test_all_three_edge_wrappers_return_dict(self):
        """test_open_redirect, test_lfi, test_graphql wrappers in edge/__init__."""
        from burpsuite_mcp.tools import edge
        stub, captured = _stub_mcp()
        edge.register(stub)
        for name in ("test_open_redirect", "test_lfi", "test_graphql"):
            self.assertIn(name, captured, f"wrapper missing: {name}")
            sig = captured[name].__annotations__.get("return")
            self.assertIn(sig, (dict, "dict"),
                          f"{name}: wrapper return type wrong: {sig!r}")


class WebViewPromotionTest(unittest.TestCase):

    def test_webview_no_longer_reference_only(self):
        from burpsuite_mcp.tools.scan._constants import _REFERENCE_ONLY
        self.assertNotIn("webview_injection", _REFERENCE_ONLY)

    def test_w10_http_observable_contexts_present(self):
        import json
        from pathlib import Path
        from burpsuite_mcp.tools.scan._constants import KNOWLEDGE_DIR
        data = json.loads(
            (Path(KNOWLEDGE_DIR) / "webview_injection.json").read_text(encoding="utf-8")
        )
        for ctx in ("webview_loaded_remote_url_backend_reach",
                    "webview_postmessage_cross_origin_reflection",
                    "webview_file_url_local_access"):
            self.assertIn(ctx, data["contexts"], f"W10 ctx missing: {ctx}")
            self.assertIn("probes", data["contexts"][ctx])

    def test_remote_url_context_uses_collaborator(self):
        import json
        from pathlib import Path
        from burpsuite_mcp.tools.scan._constants import KNOWLEDGE_DIR
        data = json.loads(
            (Path(KNOWLEDGE_DIR) / "webview_injection.json").read_text(encoding="utf-8")
        )
        ctx = data["contexts"]["webview_loaded_remote_url_backend_reach"]
        types = {m["type"] for p in ctx["probes"] for m in p["matchers"]}
        self.assertIn("collaborator", types)


class TakeoverSkillTest(unittest.TestCase):

    def test_recon_takeover_skill_present(self):
        from pathlib import Path
        skill_path = Path(".claude/skills/recon-takeover.md")
        # Tests run from mcp-server/; resolve up one level.
        if not skill_path.exists():
            skill_path = Path("..") / skill_path
        self.assertTrue(skill_path.exists(),
                        f"recon-takeover skill missing at {skill_path}")
        content = skill_path.read_text(encoding="utf-8")
        # Key concepts must be documented.
        for marker in ("dns_only", "Body-fingerprint match", "elasticbeanstalk",
                       "NEVER_SUBMIT"):
            self.assertIn(marker, content, f"missing dns_only doc marker: {marker}")


if __name__ == "__main__":
    unittest.main()
