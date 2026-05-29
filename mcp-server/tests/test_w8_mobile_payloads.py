"""Tests for W8 mobile payload delivery — mobile_frida_snippet + mobile_adb_pack."""

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


class MobileFridaSnippetTest(unittest.IsolatedAsyncioTestCase):

    async def test_list_without_args(self):
        from burpsuite_mcp.tools import mobile_payloads
        stub, captured = _stub_mcp()
        mobile_payloads.register(stub)
        out = await captured["mobile_frida_snippet"]()
        self.assertIn("available", out)
        self.assertGreater(out["count"], 0)
        # All 10 snippets from the mobile-mastg research must be present.
        expected = {
            "ssl_pin_universal_android", "ssl_pin_okhttp_specific",
            "ssl_pin_universal_ios", "root_jailbreak_bypass",
            "webview_debug_enable", "intent_url_enumerator",
            "crypto_dump", "keystore_hook", "biometric_bypass",
            "logcat_sensitive_tap", "clipboard_hook",
        }
        for name in expected:
            self.assertIn(name, out["available"], f"missing snippet: {name}")

    async def test_fetch_known_snippet_returns_js(self):
        from burpsuite_mcp.tools import mobile_payloads
        stub, captured = _stub_mcp()
        mobile_payloads.register(stub)
        out = await captured["mobile_frida_snippet"](name="ssl_pin_universal_android")
        self.assertIn("script", out)
        self.assertIn("Java.perform", out["script"])
        self.assertIn("run_cmd", out)

    async def test_unknown_snippet_errors(self):
        from burpsuite_mcp.tools import mobile_payloads
        stub, captured = _stub_mcp()
        mobile_payloads.register(stub)
        out = await captured["mobile_frida_snippet"](name="nonexistent_snippet")
        self.assertIn("error", out)
        self.assertIn("available", out)


class MobileAdbPackTest(unittest.IsolatedAsyncioTestCase):

    async def test_list_without_args(self):
        from burpsuite_mcp.tools import mobile_payloads
        stub, captured = _stub_mcp()
        mobile_payloads.register(stub)
        out = await captured["mobile_adb_pack"]()
        self.assertIn("available", out)
        self.assertGreater(out["count"], 5)

    async def test_substitution_works(self):
        from burpsuite_mcp.tools import mobile_payloads
        stub, captured = _stub_mcp()
        mobile_payloads.register(stub)
        out = await captured["mobile_adb_pack"](
            command_id="dumpsys_package", pkg="com.example.app",
        )
        self.assertIn("command", out)
        self.assertIn("com.example.app", out["command"])
        self.assertNotIn("{pkg}", out["command"])

    async def test_deep_link_substitution(self):
        from burpsuite_mcp.tools import mobile_payloads
        stub, captured = _stub_mcp()
        mobile_payloads.register(stub)
        out = await captured["mobile_adb_pack"](
            command_id="deep_link_probe",
            scheme="myapp", host="oauth", path="/callback?code=x",
            pkg="com.example.app",
        )
        self.assertIn("myapp://oauth/callback?code=x", out["command"])

    async def test_unknown_command_errors(self):
        from burpsuite_mcp.tools import mobile_payloads
        stub, captured = _stub_mcp()
        mobile_payloads.register(stub)
        out = await captured["mobile_adb_pack"](command_id="bogus_cmd")
        self.assertIn("error", out)


if __name__ == "__main__":
    unittest.main()
