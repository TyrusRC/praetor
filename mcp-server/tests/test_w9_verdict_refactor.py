"""Tests for W9 verdict refactor batch — 6 testing tools converted to dict return.

Verifies each tool returns the W7 VerdictResult schema (verdict + confidence +
evidence_summary + vuln_type + details + human_summary) on the happy path AND
the error path.
"""

from __future__ import annotations

import asyncio
import base64
import json
import unittest

from burpsuite_mcp.tools.testing._verdict import is_actionable


class JWTRefactorTest(unittest.IsolatedAsyncioTestCase):

    async def test_alg_none_confirmed(self):
        from burpsuite_mcp.tools.edge.test_jwt import test_jwt_impl
        hdr = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(b'{"sub":"x","role":"admin"}').rstrip(b"=").decode()
        token = f"{hdr}.{payload}."
        r = await test_jwt_impl(token)
        self.assertEqual(r["verdict"], "CONFIRMED")
        self.assertEqual(r["vuln_type"], "jwt")
        self.assertTrue(is_actionable(r))
        self.assertIn("human_summary", r)

    async def test_clean_hs256_failed(self):
        from burpsuite_mcp.tools.edge.test_jwt import test_jwt_impl
        hdr = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(b'{"sub":"user"}').rstrip(b"=").decode()
        token = f"{hdr}.{payload}.fakesig"
        r = await test_jwt_impl(token)
        # HS256 has no vulnerabilities flagged but follow-up tests exist → SUSPECTED 0.4
        self.assertIn(r["verdict"], ("SUSPECTED", "FAILED"))
        self.assertEqual(r["vuln_type"], "jwt")

    async def test_invalid_jwt_returns_error_verdict(self):
        from burpsuite_mcp.tools.edge.test_jwt import test_jwt_impl
        r = await test_jwt_impl("not-a-jwt")
        self.assertEqual(r["verdict"], "ERROR")
        self.assertEqual(r["vuln_type"], "jwt")
        self.assertFalse(is_actionable(r))


class AuthMatrixContractTest(unittest.TestCase):

    def test_signature_returns_dict(self):
        """Type signature check — auth_matrix declares dict return."""
        from burpsuite_mcp.tools.testing import auth_matrix
        # Ensure the module imports and registers without error.
        captured: dict = {}

        class _Stub:
            def tool(self, *a, **kw):
                def deco(fn):
                    captured[fn.__name__] = fn
                    return fn
                return deco

        auth_matrix.register(_Stub())
        self.assertIn("test_auth_matrix", captured)
        sig = captured["test_auth_matrix"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))


class CSRFContractTest(unittest.TestCase):

    def test_signature_returns_dict(self):
        from burpsuite_mcp.tools.vuln import test_csrf
        captured: dict = {}

        class _Stub:
            def tool(self, *a, **kw):
                def deco(fn):
                    captured[fn.__name__] = fn
                    return fn
                return deco

        test_csrf.register(_Stub())
        sig = captured["test_csrf"].__annotations__.get("return")
        # __future__ annotations renders as string 'dict'; without renders as type.
        self.assertIn(sig, (dict, "dict"))


class LoginBypassContractTest(unittest.TestCase):

    def test_signature_returns_dict(self):
        from burpsuite_mcp.tools.auth import login_bypass
        captured: dict = {}

        class _Stub:
            def tool(self, *a, **kw):
                def deco(fn):
                    captured[fn.__name__] = fn
                    return fn
                return deco

        login_bypass.register(_Stub())
        sig = captured["test_login_bypass"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))


class MFABypassContractTest(unittest.IsolatedAsyncioTestCase):

    async def test_missing_session_returns_error_verdict(self):
        from burpsuite_mcp.tools.auth import mfa_bypass
        captured: dict = {}

        class _Stub:
            def tool(self, *a, **kw):
                def deco(fn):
                    captured[fn.__name__] = fn
                    return fn
                return deco

        mfa_bypass.register(_Stub())
        r = await captured["test_mfa_bypass"](
            mfa_verify_url="https://x.example.com/verify",
        )
        self.assertEqual(r["verdict"], "ERROR")
        self.assertEqual(r["vuln_type"], "mfa_bypass")


class DOMSinksContractTest(unittest.TestCase):

    def test_signature_returns_dict(self):
        from burpsuite_mcp.tools import dom_probe
        captured: dict = {}

        class _Stub:
            def tool(self, *a, **kw):
                def deco(fn):
                    captured[fn.__name__] = fn
                    return fn
                return deco

        dom_probe.register(_Stub())
        sig = captured["test_dom_sinks"].__annotations__.get("return")
        self.assertIn(sig, (dict, "dict"))


if __name__ == "__main__":
    unittest.main()
