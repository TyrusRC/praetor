"""Regression tests for the codebase-audit gap sweep.

Each test reproduces one verified defect from the audit and locks the fix.
Grouped by wave; see the sweep branch commits for the corresponding change.
"""

from __future__ import annotations

import inspect
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from cryptography.fernet import Fernet

from praetor import server
from praetor.tools.testing_extended import quota_window, host_header, smuggling, line_item_mutation


def _tool(name: str):
    return server.mcp._tool_manager._tools[name].fn


# ── Wave 1: crashes & verdict type-safety ────────────────────────────────

class OastDecryptGracefulTest(unittest.IsolatedAsyncioTestCase):
    """_oast_tools.py:196 referenced base64.binascii.Error with no `import base64`,
    so the common wrong-key/corrupt-token path raised NameError instead of the
    graceful error message. The whole failure branch was dead."""

    async def test_bad_token_returns_graceful_error_not_nameerror(self):
        key = Fernet.generate_key()
        with patch("praetor.tools.collaborate._oast_tools._get_oast_fernet",
                   return_value=(Fernet(key), key.decode(), None)):
            fn = _tool("decrypt_oast_capture")
            out = await fn(ciphertext="!!!not-a-valid-token!!!")
        self.assertIsInstance(out, str)
        self.assertIn("decryption failed", out.lower())


class IdempotencyVerdictTest(unittest.IsolatedAsyncioTestCase):
    """idempotency_key.py: (a) canonical-send error returned a raw str from a
    `-> dict` tool; (b) critical_keywords never matched the emitted tokens, so a
    cross-principal / double-charge hit fell to SUSPECTED instead of CONFIRMED."""

    async def test_canonical_error_returns_verdict_dict(self):
        async def fake_post(path, json=None):
            return {"error": "session dead"}
        with patch("praetor.tools.testing_extended.idempotency_key.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_idempotency_key")
            out = await fn(session_primary="p", endpoint="/pay", body={"amount": 1})
        self.assertIsInstance(out, dict)
        self.assertEqual(out["verdict"], "ERROR")

    async def test_cross_principal_hit_is_confirmed(self):
        async def fake_post(path, json=None):
            return {"status": 200, "response_body": '{"ok":1}'}
        with patch("praetor.tools.testing_extended.idempotency_key.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_idempotency_key")
            out = await fn(session_primary="p", endpoint="/pay",
                           body={"amount": 1}, session_secondary="s")
        self.assertEqual(out["verdict"], "CONFIRMED")


class VerdictToolSourceGuardTest(unittest.TestCase):
    """Static guards against the exact regressions fixed this wave: a verdict
    tool must not return a raw string, and quota's off-by-one predicate must
    match the emitted DOUBLE_CONSUME token (underscore, not space)."""

    def test_quota_double_consume_token_matches_predicate(self):
        src = Path(quota_window.__file__).read_text(encoding="utf-8")
        self.assertIn('"DOUBLE_CONSUME"', src)          # predicate uses the real token
        self.assertNotIn('"DOUBLE CONSUME"', src)       # not the space-typo that never matched

    def test_no_raw_string_returns_from_dict_verdict_tools(self):
        for mod in (host_header, smuggling, line_item_mutation):
            src = inspect.getsource(mod)
            self.assertNotIn("return scope_err", src,
                             f"{mod.__name__} returns a raw scope str from a -> dict tool")
            self.assertNotIn('return "\\n".join(lines)', src,
                             f"{mod.__name__} returns a raw joined str from a -> dict tool")


if __name__ == "__main__":
    unittest.main()
