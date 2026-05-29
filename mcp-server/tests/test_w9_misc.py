"""Tests for W9 misc additions — iOS Frida snippets, Tauri auto-update KB,
DNS-only takeover fingerprints, tech-specific common_files extensions."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from burpsuite_mcp.tools.scan._constants import KNOWLEDGE_DIR
from burpsuite_mcp.tools.recon_extended.fingerprints import TAKEOVER_FINGERPRINTS


class IOSFridaSnippetsTest(unittest.IsolatedAsyncioTestCase):

    async def test_all_ios_snippets_present(self):
        from burpsuite_mcp.tools import mobile_payloads
        captured: dict = {}

        class _Stub:
            def tool(self, *a, **kw):
                def deco(fn):
                    captured[fn.__name__] = fn
                    return fn
                return deco

        mobile_payloads.register(_Stub())
        out = await captured["mobile_frida_snippet"]()
        expected_ios = {
            "ios_nsurlsession_capture",
            "ios_nsuserdefaults_dump",
            "ios_keychain_enum",
            "ios_lacontext_bypass",
        }
        for name in expected_ios:
            self.assertIn(name, out["available"], f"missing W9 iOS snippet: {name}")

    async def test_ios_lacontext_returns_objc_code(self):
        from burpsuite_mcp.tools import mobile_payloads
        captured: dict = {}

        class _Stub:
            def tool(self, *a, **kw):
                def deco(fn):
                    captured[fn.__name__] = fn
                    return fn
                return deco

        mobile_payloads.register(_Stub())
        out = await captured["mobile_frida_snippet"](name="ios_lacontext_bypass")
        self.assertIn("script", out)
        self.assertIn("LAContext", out["script"])
        self.assertIn("ObjC.available", out["script"])


class TauriAutoUpdateKBTest(unittest.TestCase):

    def test_w9_tauri_contexts_present(self):
        path = Path(KNOWLEDGE_DIR) / "desktop_electron.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        for ctx in ("tauri_autoupdate_unsigned",
                    "tauri_autoupdate_tuf_metadata",
                    "cosign_signature_missing"):
            self.assertIn(ctx, data["contexts"], f"W9 ctx missing: {ctx}")
            self.assertIn("detect", data["contexts"][ctx])
            self.assertIn("severity_hint", data["contexts"][ctx])

    def test_tauri_unsigned_documents_cve(self):
        path = Path(KNOWLEDGE_DIR) / "desktop_electron.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        ctx = data["contexts"]["tauri_autoupdate_unsigned"]
        self.assertIn("GHSA", str(ctx.get("cve", "")))


class DNSOnlyTakeoverTest(unittest.TestCase):

    def test_dns_only_entries_added(self):
        # At least 8 ElasticBeanstalk regional + 3 Azure + 3 S3 regional.
        dns_only_count = sum(1 for e in TAKEOVER_FINGERPRINTS.values()
                             if e.get("dns_only"))
        self.assertGreaterEqual(dns_only_count, 11)

    def test_elasticbeanstalk_regional_present(self):
        for region in ("us-east-1", "eu-west-1", "ap-southeast-1"):
            key = f"elasticbeanstalk-{region}"
            self.assertIn(key, TAKEOVER_FINGERPRINTS, f"missing region: {key}")
            entry = TAKEOVER_FINGERPRINTS[key]
            self.assertTrue(entry.get("dns_only"))


class CommonFilesTechSpecificTest(unittest.IsolatedAsyncioTestCase):

    async def test_rails_paths_added(self):
        """W9 added Rails-specific paths: database.yml, secrets.yml, master.key."""
        # Read the source file directly (these are inline literals).
        path = Path("src/burpsuite_mcp/tools/edge/discover_common_files.py")
        # The tests run from mcp-server/; resolve relative.
        if not path.exists():
            path = Path("mcp-server") / path
        content = path.read_text(encoding="utf-8")
        for marker in ("/config/database.yml",
                       "/config/master.key",
                       "/db/schema.rb"):
            self.assertIn(marker, content, f"missing W9 Rails path: {marker}")

    async def test_go_pprof_paths_added(self):
        path = Path("src/burpsuite_mcp/tools/edge/discover_common_files.py")
        if not path.exists():
            path = Path("mcp-server") / path
        content = path.read_text(encoding="utf-8")
        for marker in ("/debug/pprof/", "/debug/vars"):
            self.assertIn(marker, content, f"missing W9 Go path: {marker}")


if __name__ == "__main__":
    unittest.main()
