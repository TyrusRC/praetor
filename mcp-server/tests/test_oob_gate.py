"""OOB-mandatory gate for inherently out-of-band classes (2026-07-25 FP pass).

A claimed blind SSRF/XXE/XSS with only an in-band guess and no resolved
Collaborator/callback interaction is the classic blind false positive. The Q5
gate must require an OOB marker for these classes (Rule 9a).
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from praetor import server


class OobGate(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.assess = staticmethod(server.mcp._tool_manager._tools["assess_finding"].fn)
        cls.tmpdir = Path(tempfile.mkdtemp(prefix="burp-intel-oob-"))
        cls.original_cwd = Path.cwd()
        os.chdir(cls.tmpdir)

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.original_cwd)
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    async def _call(self, **kwargs) -> str:
        async def fake_post(path, json=None):
            return {"in_scope": True}
        async def fake_get(path, params=None):
            return {}
        with patch("praetor.client.post", fake_post), \
             patch("praetor.client.get", fake_get):
            return await self.assess(**kwargs)

    async def test_blind_ssrf_without_oob_flagged(self):
        out = await self._call(
            vuln_type="ssrf_blind",
            endpoint="/fetch",
            parameter="url",
            evidence="internal ip 169.254 reached, gopher:// filter bypass worked",
            domain="ex.com",
        )
        self.assertIn("Q5 OOB REQUIRED", out)

    async def test_blind_ssrf_with_collaborator_passes(self):
        out = await self._call(
            vuln_type="ssrf_blind",
            endpoint="/fetch",
            parameter="url",
            evidence="collaborator dns interaction received, oob callback confirmed from fetch of 169.254",
            domain="ex.com",
        )
        self.assertNotIn("Q5 OOB REQUIRED", out)

    async def test_inband_ssrf_not_oob_required(self):
        out = await self._call(
            vuln_type="ssrf",
            endpoint="/fetch",
            parameter="url",
            evidence="169.254 metadata AccessKeyId SecretAccessKey leaked in response body",
            domain="ex.com",
        )
        self.assertNotIn("Q5 OOB REQUIRED", out)

    async def test_human_verified_skips_oob(self):
        out = await self._call(
            vuln_type="blind xss",
            endpoint="/comment",
            parameter="body",
            evidence="stored payload fired in admin panel",
            domain="ex.com",
            human_verified=True,
        )
        self.assertNotIn("Q5 OOB REQUIRED", out)


if __name__ == "__main__":
    unittest.main()
