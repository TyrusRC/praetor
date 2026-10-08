"""mobile_decompile_apk — jadx static APK analysis (manifest surface + secret leads)."""

import asyncio
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from praetor.tools.mobile import static as S

_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.acme.app">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.READ_SMS"/>
  <application android:debuggable="true" android:allowBackup="true">
    <activity android:name=".PublicActivity" android:exported="true"/>
    <service android:name=".SyncService">
      <intent-filter><action android:name="x"/></intent-filter>
    </service>
    <activity android:name=".PrivateActivity" android:exported="false"/>
  </application>
</manifest>
"""

_JAVA = (
    'class C { String k="AIza0123456789012345678901234567890123456"; '
    'String u="https://api.acme.com/v1/login"; }'
)


def _tools():
    holders: dict = {}

    class _Stub:
        def tool(self):
            def _wrap(fn):
                holders[fn.__name__] = fn
                return fn
            return _wrap

    S.register(_Stub())
    return holders


class ManifestParseTest(unittest.TestCase):

    def _write(self, text):
        d = Path(tempfile.mkdtemp(prefix="mf-"))
        p = d / "AndroidManifest.xml"
        p.write_text(text)
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return p

    def test_exported_and_flags(self):
        m = S._parse_manifest(self._write(_MANIFEST))
        self.assertEqual(m["package"], "com.acme.app")
        names = {c["name"]: c for c in m["exported"]}
        self.assertIn(".PublicActivity", names)          # explicit exported=true
        self.assertIn(".SyncService", names)              # implicit via intent-filter
        self.assertNotIn(".PrivateActivity", names)       # exported=false excluded
        self.assertEqual(m["flags"].get("debuggable"), "true")
        self.assertIn("android.permission.READ_SMS", m["permissions"])

    def test_bad_manifest_returns_error(self):
        self.assertIn("error", S._parse_manifest(self._write("<not-xml")))


class SourceScanTest(unittest.TestCase):

    def test_secret_and_endpoint_leads(self):
        d = Path(tempfile.mkdtemp(prefix="src-"))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        (d / "C.java").write_text(_JAVA)
        secrets, endpoints = S._scan_sources(d, cap=60)
        self.assertTrue(any("google_api_key" in s for s in secrets))
        self.assertIn("https://api.acme.com/v1/login", endpoints)


class ToolTest(unittest.TestCase):

    def test_registered(self):
        self.assertIn("mobile_decompile_apk", _tools())

    def test_not_installed_hint(self):
        fn = _tools()["mobile_decompile_apk"]
        with mock.patch.object(S, "_check_tool", return_value=False):
            out = asyncio.run(fn("/tmp/x.apk"))
        self.assertIn("jadx not installed", out)

    def test_end_to_end_with_fake_jadx(self):
        work = Path(tempfile.mkdtemp(prefix="apk-"))
        self.addCleanup(shutil.rmtree, work, ignore_errors=True)
        apk = work / "app.apk"
        apk.write_bytes(b"PK\x03\x04fake")
        out = work / "out"

        async def fake_run(cmd, timeout=600, bypass_proxy=False):
            d = Path(cmd[cmd.index("-d") + 1])
            (d / "sources").mkdir(parents=True, exist_ok=True)
            (d / "resources").mkdir(parents=True, exist_ok=True)
            (d / "sources" / "C.java").write_text(_JAVA)
            (d / "resources" / "AndroidManifest.xml").write_text(_MANIFEST)
            return ("", "", 0)

        fn = _tools()["mobile_decompile_apk"]
        with mock.patch.object(S, "_check_tool", return_value=True), \
             mock.patch.object(S, "_run_cmd", side_effect=fake_run):
            report = asyncio.run(fn(str(apk), out_dir=str(out)))
        self.assertIn("com.acme.app", report)
        self.assertIn("PublicActivity", report)          # exported surface
        self.assertIn("RISKY MANIFEST FLAGS", report)     # debuggable
        self.assertIn("google_api_key", report)           # secret lead
        self.assertIn("run_mantis", report)                # SAST handoff


class IpaAnalysisTest(unittest.TestCase):

    def test_analyze_ipa_surfaces_manifest_entitlements_secrets(self):
        import asyncio
        import plistlib
        import zipfile
        from praetor import server
        work = Path(tempfile.mkdtemp(prefix="ipa-"))
        self.addCleanup(shutil.rmtree, work, ignore_errors=True)
        info = {"CFBundleIdentifier": "com.acme.app", "CFBundleShortVersionString": "1.2",
                "CFBundleURLTypes": [{"CFBundleURLSchemes": ["acme", "acme-oauth"]}],
                "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}}
        ipa = work / "app.ipa"
        with zipfile.ZipFile(ipa, "w") as z:
            z.writestr("Payload/Acme.app/Info.plist", plistlib.dumps(info))
            z.writestr("Payload/Acme.app/Acme",
                       "k=AIza0123456789012345678901234567890123456 https://api.acme.com/v1")
        fn = server.mcp._tool_manager._tools["mobile_analyze_ipa"].fn
        out = asyncio.run(fn(str(ipa)))
        self.assertIn("com.acme.app", out)
        self.assertIn("acme-oauth", out)                # URL scheme surfaced
        self.assertIn("cleartext", out)                 # ATS risky flag
        self.assertIn("google_api_key", out)            # secret lead

    def test_bad_ipa_rejected(self):
        import asyncio
        from praetor import server
        work = Path(tempfile.mkdtemp(prefix="ipa-"))
        self.addCleanup(shutil.rmtree, work, ignore_errors=True)
        bad = work / "x.ipa"; bad.write_bytes(b"not a zip")
        fn = server.mcp._tool_manager._tools["mobile_analyze_ipa"].fn
        self.assertIn("Error", asyncio.run(fn(str(bad))))


if __name__ == "__main__":
    unittest.main()
