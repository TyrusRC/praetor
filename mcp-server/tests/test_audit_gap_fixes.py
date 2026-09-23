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


# ── Wave 2: exploit-confirm reflection / OOB coercion ────────────────────

class ConfirmReflectionGuardTest(unittest.IsolatedAsyncioTestCase):
    """The marker frame rides in the outbound payload, so pure input reflection
    used to yield a false CONFIRMED. Reflection must resolve to INCONCLUSIVE."""

    async def test_confirm_rce_reflection_is_inconclusive(self):
        async def fake_post(path, json=None):
            # App echoes the decoded payload verbatim (search box, error page):
            body = "you searched for: ; echo M-deadbeef-START; id; echo M-deadbeef-END — no results"
            return {"response_body": body, "status_code": 200, "proxy_index": 5}
        with patch("praetor.tools.exploit.confirm_rce.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("praetor.tools.exploit.confirm_rce.make_marker",
                   return_value="m-deadbeef"):
            fn = _tool("confirm_rce")
            out = await fn(endpoint="https://t/x", parameter="cmd",
                           command="id", os="linux", wrapper_index=0)
        self.assertEqual(out["verdict"], "INCONCLUSIVE")

    async def test_confirm_sqli_reflection_is_inconclusive(self):
        # App echoes the sent union payload verbatim (marker M-M-deadbeef included).
        async def fake_post(path, json=None):
            body = "results for '+UNION+SELECT+'M-M-deadbeef',VERSION()--+- : none found"
            return {"response_body": body, "status_code": 200, "proxy_index": 8}
        with patch("praetor.tools.exploit.confirm_sqli.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("praetor.tools.exploit.confirm_sqli.make_marker",
                   return_value="M-deadbeef"):
            fn = _tool("confirm_sqli")
            out = await fn(endpoint="https://t/x", parameter="id",
                           dbms="mysql", strategy="union")
        self.assertEqual(out["verdict"], "INCONCLUSIVE")


# ── Wave 3: network / probe validity gates ───────────────────────────────

class RateLimitValidityTest(unittest.IsolatedAsyncioTestCase):
    """All requests erroring (dead session) used to yield CONFIRMED 'no rate
    limiting'. Zero successful requests must be INCONCLUSIVE."""

    async def test_all_errored_is_inconclusive(self):
        async def fake_post(path, json=None):
            return {"error": "connection refused"}
        with patch("praetor.tools.testing.rate_limit.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("test_rate_limit")
            out = await fn(session="s", method="GET", path="/login", requests_count=5)
        self.assertEqual(out["verdict"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
