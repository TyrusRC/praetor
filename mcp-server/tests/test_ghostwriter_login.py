"""Ghostwriter username/password login fallback + auth precedence.

Covers the first-setup path: with no static token/admin-secret, Praetor logs
in with GHOSTWRITER_USERNAME/PASSWORD (default praetor/praetor) to mint a JWT,
bears it on GraphQL calls, and re-mints once on an expired-token error.
"""
import asyncio
import unittest
from unittest.mock import patch

from praetor import config
from praetor.tools.redteam import _ghostwriter as gw
from praetor.tools.redteam import _gw_auth  # login state lives here after the split


class _Resp:
    def __init__(self, status=200, body=None, text=""):
        self.status_code = status
        self._body = body or {}
        self.text = text

    def json(self):
        return self._body


class _FakeClient:
    """Async-context httpx.AsyncClient stub returning queued responses in order
    and recording the Authorization header of each POST."""
    calls: list = []          # (url, headers) per post, across instances
    queue: list = []          # _Resp objects, popped left-to-right

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, headers=None, json=None):
        _FakeClient.calls.append((url, headers or {}, json or {}))
        return _FakeClient.queue.pop(0)


def _patch_client():
    return patch.object(gw.httpx, "AsyncClient", _FakeClient)


class GhostwriterAuth(unittest.TestCase):
    def setUp(self):
        _FakeClient.calls = []
        _FakeClient.queue = []
        _gw_auth._LOGIN_JWT = ""
        # Baseline config: URL + oplog set, no static auth, default creds.
        self._saved = {k: getattr(config, k) for k in (
            "GHOSTWRITER_URL", "GHOSTWRITER_OPLOG_ID", "GHOSTWRITER_API_TOKEN",
            "GHOSTWRITER_ADMIN_SECRET", "GHOSTWRITER_USERNAME",
            "GHOSTWRITER_PASSWORD", "GHOSTWRITER_INSECURE_TLS")}
        config.GHOSTWRITER_URL = "https://gw.local"
        config.GHOSTWRITER_OPLOG_ID = 1
        config.GHOSTWRITER_API_TOKEN = ""
        config.GHOSTWRITER_ADMIN_SECRET = ""
        config.GHOSTWRITER_USERNAME = "praetor"
        config.GHOSTWRITER_PASSWORD = "praetor"
        config.GHOSTWRITER_INSECURE_TLS = True

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(config, k, v)
        _gw_auth._LOGIN_JWT = ""

    # ── config / precedence ────────────────────────────────────────────────
    def test_configured_with_only_url_oplog_and_default_creds(self):
        self.assertTrue(gw.is_configured())
        self.assertEqual(gw.config_hint(), "configured")

    def test_not_configured_without_any_auth(self):
        config.GHOSTWRITER_USERNAME = ""
        config.GHOSTWRITER_PASSWORD = ""
        self.assertFalse(gw.is_configured())
        self.assertIn("USERNAME", gw.config_hint())

    def test_header_precedence(self):
        config.GHOSTWRITER_ADMIN_SECRET = "sekret"
        config.GHOSTWRITER_API_TOKEN = "tok"
        self.assertEqual(gw._headers("bear")["X-Hasura-Admin-Secret"], "sekret")
        self.assertNotIn("Authorization", gw._headers("bear"))
        config.GHOSTWRITER_ADMIN_SECRET = ""
        self.assertEqual(gw._headers("bear")["Authorization"], "Bearer tok")
        config.GHOSTWRITER_API_TOKEN = ""
        self.assertEqual(gw._headers("bear")["Authorization"], "Bearer bear")

    def test_auth_mode_reports_login_without_leaking_password(self):
        mode = gw.auth_mode()
        self.assertIn("login", mode)
        self.assertIn("praetor", mode)       # username ok to show
        self.assertNotIn("password", mode.lower())

    def test_ensure_token_empty_when_static_auth(self):
        config.GHOSTWRITER_ADMIN_SECRET = "sekret"
        self.assertEqual(asyncio.run(gw._ensure_login_token()), "")

    # ── login + gql ────────────────────────────────────────────────────────
    def test_login_parses_token(self):
        _FakeClient.queue = [_Resp(body={"data": {"login": {"token": "JWT1"}}})]
        with _patch_client():
            self.assertEqual(asyncio.run(gw._login()), {"token": "JWT1"})

    def test_gql_logs_in_then_bears_jwt(self):
        _FakeClient.queue = [
            _Resp(body={"data": {"login": {"token": "JWT1"}}}),   # login
            _Resp(body={"data": {"ok": True}}),                   # gql
        ]
        with _patch_client():
            out = asyncio.run(gw._gql("query{ok}", {}))
        self.assertEqual(out, {"data": {"ok": True}})
        # second call (the gql op) must bear the minted JWT
        self.assertEqual(_FakeClient.calls[1][1].get("Authorization"), "Bearer JWT1")

    def test_gql_relogins_once_on_expired_jwt(self):
        _gw_auth._LOGIN_JWT = "STALE"                                   # cached, expired
        _FakeClient.queue = [
            _Resp(body={"errors": [{"message": "Could not verify JWT: expired"}]}),  # 1st gql
            _Resp(body={"data": {"login": {"token": "FRESH"}}}),  # re-login
            _Resp(body={"data": {"ok": True}}),                   # retried gql
        ]
        with _patch_client():
            out = asyncio.run(gw._gql("query{ok}", {}))
        self.assertEqual(out, {"data": {"ok": True}})
        self.assertEqual(_FakeClient.calls[-1][1].get("Authorization"), "Bearer FRESH")

    def test_map_finding_to_oplog_mirror(self):
        f = {"id": "f001", "title": "SQLi", "vuln_type": "sqli_time",
             "severity": "critical", "endpoint": "http://x/showthread.asp",
             "poc_request": "GET /showthread.asp?id=0;WAITFOR...", "impact": "db read",
             "evidence": {"logger_index": 22}}
        o = gw.map_finding_to_oplog(f)
        self.assertEqual(o["oplog"], config.GHOSTWRITER_OPLOG_ID)
        self.assertEqual(o["destIp"], "http://x/showthread.asp")
        self.assertIn("severity:CRITICAL", o["comments"])
        self.assertIn("vuln:sqli_time", o["comments"])
        self.assertIn("Burp logger_index=22", o["comments"])
        self.assertIn("finding", o["extraFields"]["tags"])
        self.assertIn("severity:CRITICAL", o["extraFields"]["tags"])
        self.assertEqual(o["extraFields"]["praetor_finding_id"], "f001")
        self.assertEqual(o["entryIdentifier"], "finding:f001")

    def test_gql_reports_login_failure(self):
        _FakeClient.queue = [_Resp(status=401, text="bad creds")]  # login fails
        with _patch_client():
            out = asyncio.run(gw._gql("query{ok}", {}))
        self.assertIn("login failed", out.get("error", ""))


if __name__ == "__main__":
    unittest.main()
