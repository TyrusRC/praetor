"""Tests for propose_chains (W7, T3) — chain auto-proposer."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from burpsuite_mcp.tools.notes import chain_proposer


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    return _Stub(), captured


class ChainProposerTest(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cwd = os.getcwd()
        os.chdir(self.tmpdir)
        self.domain_dir = Path(self.tmpdir) / ".burp-intel" / "demo.example.com"
        self.domain_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        os.chdir(self.cwd)
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_findings(self, items: list[dict]):
        (self.domain_dir / "findings.json").write_text(
            json.dumps({"findings": items}), encoding="utf-8"
        )

    async def test_no_findings_returns_empty(self):
        stub, captured = _stub_mcp()
        chain_proposer.register(stub)
        propose = captured["propose_chains"]
        result = await propose(domain="demo.example.com")
        self.assertEqual(result["chains"], [])

    async def test_ssrf_to_cloud_chain_proposed(self):
        self._write_findings([
            {"id": "f1", "vuln_type": "ssrf", "status": "confirmed",
             "endpoint": "/api/fetch", "confidence": 0.9},
            {"id": "f2", "vuln_type": "cloud_metadata", "status": "confirmed",
             "endpoint": "/api/proxy", "confidence": 0.85},
        ])
        stub, captured = _stub_mcp()
        chain_proposer.register(stub)
        propose = captured["propose_chains"]
        result = await propose(domain="demo.example.com")
        names = [c["progression"] for c in result["chains"]]
        self.assertIn("ssrf_to_cloud_credentials", names)
        chain = next(c for c in result["chains"] if c["progression"] == "ssrf_to_cloud_credentials")
        self.assertEqual(chain["severity"], "critical")
        self.assertEqual(chain["score"], 95)

    async def test_excludes_stale_and_fp(self):
        self._write_findings([
            {"id": "f1", "vuln_type": "ssrf", "status": "stale", "endpoint": "/x"},
            {"id": "f2", "vuln_type": "cloud_metadata", "status": "likely_false_positive", "endpoint": "/y"},
        ])
        stub, captured = _stub_mcp()
        chain_proposer.register(stub)
        propose = captured["propose_chains"]
        result = await propose(domain="demo.example.com")
        self.assertEqual(result["total_findings_considered"], 0)
        self.assertEqual(result["chains"], [])

    async def test_includes_suspected_when_requested(self):
        self._write_findings([
            {"id": "f1", "vuln_type": "open_redirect", "status": "suspected",
             "endpoint": "/r", "confidence": 0.6},
            {"id": "f2", "vuln_type": "oauth", "status": "confirmed",
             "endpoint": "/oauth/callback", "confidence": 0.9},
        ])
        stub, captured = _stub_mcp()
        chain_proposer.register(stub)
        propose = captured["propose_chains"]
        r_yes = await propose(domain="demo.example.com", include_suspected=True)
        r_no = await propose(domain="demo.example.com", include_suspected=False)
        self.assertEqual(r_yes["total_findings_considered"], 2)
        self.assertEqual(r_no["total_findings_considered"], 1)

    async def test_chain_anchor_ordering_preserved(self):
        self._write_findings([
            {"id": "csrf-1", "vuln_type": "csrf", "status": "confirmed",
             "endpoint": "/email", "confidence": 0.85},
            {"id": "ma-1", "vuln_type": "account_email", "status": "confirmed",
             "endpoint": "/me", "confidence": 0.8},
        ])
        stub, captured = _stub_mcp()
        chain_proposer.register(stub)
        propose = captured["propose_chains"]
        result = await propose(domain="demo.example.com")
        chain = next((c for c in result["chains"] if c["progression"] == "csrf_email_change_ato"), None)
        self.assertIsNotNone(chain)
        self.assertEqual(chain["anchors"][0], "csrf-1")


if __name__ == "__main__":
    unittest.main()
