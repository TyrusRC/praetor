"""Tests for capture-hygiene tooling: set_capture_hygiene (proxy config forward)
and snapshot_and_rotate (Burp-state snapshot to .burp-intel)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    return _Stub(), captured


class SetCaptureHygieneTest(unittest.IsolatedAsyncioTestCase):

    async def test_forwards_body_with_defaults(self):
        from praetor.tools.proxy_control import _config
        stub, captured = _stub_mcp()
        _config.register(stub)
        self.assertIn("set_capture_hygiene", captured)

        sent: dict = {}

        async def fake_post(path, json=None):
            sent["path"] = path
            sent["body"] = json
            return {"applied": ["ok"], "options_imported": True}

        with patch.object(_config.client, "post", side_effect=fake_post):
            out = await captured["set_capture_hygiene"]()

        self.assertEqual(sent["path"], "/api/proxy/capture-hygiene")
        self.assertTrue(sent["body"]["record_in_scope_only"])
        # defaults populated, not empty
        self.assertIn("js", sent["body"]["static_extensions"])
        self.assertTrue(any("analytics" in h for h in sent["body"]["noise_hosts"]))
        self.assertEqual(out["options_imported"], True)


class SnapshotAndRotateTest(unittest.IsolatedAsyncioTestCase):

    async def test_snapshots_burp_state_and_writes_manifest(self):
        from praetor.tools.evidence import tools

        async def fake_get(path, params=None):
            if "scanner" in path:
                return {"findings": [{"name": "info-leak"}]}
            if "sitemap" in path:
                return {"sitemap": [{"url": "/a"}, {"url": "/b"}]}
            if "count" in path:
                return {"count": 4200}
            return {}

        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            try:
                # a pre-existing on-disk intel file that must be reported as surviving
                intel = Path(td) / ".burp-intel" / "example.com"
                intel.mkdir(parents=True)
                (intel / "findings.json").write_text("[]")
                with patch.object(tools.client, "get", side_effect=fake_get):
                    out = await tools.snapshot_and_rotate("example.com")
                # assert while the tempdir still exists
                snap = Path(out["snapshot"])
                self.assertTrue((snap / "manifest.json").exists())
                self.assertTrue((snap / "scanner_findings.json").exists())
                self.assertEqual(json.loads((snap / "sitemap.json").read_text())[0]["url"], "/a")
            finally:
                os.chdir(cwd)

        self.assertEqual(out["domain"], "example.com")
        self.assertEqual(out["proxy_history_count"], 4200)
        self.assertEqual(out["burp_state_snapshotted"]["scanner_findings"], 1)
        self.assertEqual(out["burp_state_snapshotted"]["sitemap_entries"], 2)
        self.assertIn("findings.json", out["survives_rotation_on_disk"])

    async def test_requires_domain(self):
        from praetor.tools.evidence import tools
        out = await tools.snapshot_and_rotate("")
        self.assertIn("error", out)


def _hist(n_clean, n_static=0, n_oos=0, host="example.com"):
    e = [{"url": f"https://{host}/p{i}", "host": host} for i in range(n_clean)]
    e += [{"url": f"https://{host}/a{i}.js", "host": host} for i in range(n_static)]
    e += [{"url": f"https://cdn.other.com/x{i}.js", "host": "cdn.other.com"} for i in range(n_oos)]
    return {"history": e}


class VerifyCaptureHygieneTest(unittest.IsolatedAsyncioTestCase):

    async def _run(self, history, baseline=None):
        from praetor.tools.evidence import tools

        async def fake_get(path, params=None):
            return history

        with patch.object(tools.client, "get", side_effect=fake_get):
            return await tools.verify_capture_hygiene("example.com", baseline=baseline)

    async def test_baseline_then_working(self):
        base = await self._run(_hist(10, n_static=2, n_oos=1))
        self.assertEqual(base["current"]["proxy_count"], 13)
        self.assertIn("note", base)
        # +10 new entries, all clean
        after = await self._run(_hist(20, n_static=2, n_oos=1), baseline=base["current"])
        self.assertEqual(after["delta"]["new_entries"], 10)
        self.assertEqual(after["delta"]["new_static"], 0)
        self.assertIn("WORKING", after["verdict"])

    async def test_not_effective(self):
        base = await self._run(_hist(10))
        after = await self._run(_hist(10, n_static=10, n_oos=5), baseline=base["current"])
        self.assertGreater(after["delta"]["new_static"], 0)
        self.assertIn("NOT EFFECTIVE", after["verdict"])

    async def test_no_new_traffic(self):
        base = await self._run(_hist(10))
        after = await self._run(_hist(10), baseline=base["current"])
        self.assertIn("no new traffic", after["verdict"])


if __name__ == "__main__":
    unittest.main()
