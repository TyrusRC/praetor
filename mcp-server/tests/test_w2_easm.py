"""Wave 2 — EASM + recorded_login + findings_diff + format_pr_comment."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from burpsuite_mcp.tools.easm import findings_diff as fd_mod
from burpsuite_mcp.tools.easm import format_pr_comment as pr_mod
from burpsuite_mcp.tools.easm import monitor_loop as ml_mod
from burpsuite_mcp.tools.easm import recorded_login as rl_mod
from burpsuite_mcp.tools.notes import _helpers as nh
from burpsuite_mcp.tools.recon_extended import TAKEOVER_FINGERPRINTS


class W2TakeoverFingerprintsTest(unittest.TestCase):

    def test_expanded_fingerprint_count(self):
        self.assertGreaterEqual(len(TAKEOVER_FINGERPRINTS), 60)

    def test_modern_hosts_present(self):
        for host in ("vercel-dns.com", "netlify.app", "pages.dev",
                     "fly.dev", "onrender.com", "supabase.co",
                     "firebaseapp.com", "azurestaticapps.net"):
            self.assertIn(host, TAKEOVER_FINGERPRINTS)

    def test_each_entry_has_cname_and_body(self):
        for host, entry in TAKEOVER_FINGERPRINTS.items():
            self.assertIn("cname", entry, host)
            self.assertIn("body", entry, host)
            self.assertTrue(entry["cname"])
            self.assertTrue(entry["body"])


class W2FindingsDiffTest(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="praetor-w2-"))
        self._intel_patch = mock.patch.object(nh, "_intel_dir",
            lambda: self.tmp)
        self._intel_patch.start()
        (self.tmp / "ex.com").mkdir()

    def tearDown(self):
        self._intel_patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name: str, items: list[dict]) -> Path:
        snaps = self.tmp / "ex.com" / "_snapshots"
        snaps.mkdir(parents=True, exist_ok=True)
        p = snaps / name
        p.write_text(json.dumps(items), encoding="utf-8")
        return p

    def test_index_dedup_key(self):
        f = [{"endpoint": "/a", "vuln_type": "xss", "parameter": "q", "title": "t"}]
        idx = fd_mod._index_by_dedup_key(f)
        self.assertEqual(list(idx.keys()), ["/a|xss|q|t"])

    def test_snapshot_archive_creates_file(self):
        live = self.tmp / "ex.com" / "findings.json"
        live.write_text(json.dumps({"findings": [{"id": "f-1"}]}), encoding="utf-8")
        with mock.patch.object(fd_mod, "_safe_findings_path", return_value=live):
            p = fd_mod._archive_current("ex.com")
        self.assertIsNotNone(p)
        self.assertTrue(p.exists())

    def test_findings_list_handles_dict_and_list_schemas(self):
        self.assertEqual(fd_mod._findings_list({"findings": [{"id": "x"}]}),
                         [{"id": "x"}])
        self.assertEqual(fd_mod._findings_list([{"id": "y"}]), [{"id": "y"}])
        self.assertEqual(fd_mod._findings_list(None), [])


class W2RecordedLoginExtractorsTest(unittest.TestCase):

    def test_defaults_cover_common_token_shapes(self):
        names = {e["name"] for e in rl_mod._TOKEN_EXTRACT_DEFAULTS}
        for n in ("auth_token", "session_cookie", "csrf_token", "jwt"):
            self.assertIn(n, names)

    def test_extractors_have_required_fields(self):
        for e in rl_mod._TOKEN_EXTRACT_DEFAULTS:
            for k in ("name", "from", "regex"):
                self.assertIn(k, e)


class W2PrCommentTest(unittest.TestCase):

    def test_severity_badges_cover_all_levels(self):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.assertIn(sev, pr_mod._SEVERITY_BADGE)

    def test_curl_repro_includes_burp_proxy(self):
        f = {"method": "POST", "endpoint": "https://x.test/a",
             "evidence": {"url": "https://x.test/a", "method": "POST"}}
        out = pr_mod._curl_repro(f)
        self.assertIn("127.0.0.1:8080", out)
        self.assertIn("-X POST", out)
        self.assertIn("https://x.test/a", out)


class W2MonitorLoopHelperTest(unittest.TestCase):

    def test_subfinder_returns_empty_when_missing(self):
        import asyncio
        with mock.patch.object(ml_mod, "_check_tool", return_value=False):
            out = asyncio.run(ml_mod._subfinder("ex.com", 5))
        self.assertEqual(out, [])

    def test_httpx_falls_back_when_tool_missing(self):
        import asyncio
        with mock.patch.object(ml_mod, "_check_tool", return_value=False):
            out = asyncio.run(ml_mod._httpx(["a.test", "b.test"], 5))
        self.assertEqual([r["alive"] for r in out], [None, None])


if __name__ == "__main__":
    unittest.main()
