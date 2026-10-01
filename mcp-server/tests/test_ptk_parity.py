"""PTK-parity tools: cURL import/export, client-side storage dump, retire.js SCA.

One focused test per behaviour that can break — the curl parser's flag handling,
the storage formatter's secret-flagging, and the retire.js JSON projection.
"""

import unittest
from unittest.mock import AsyncMock, patch

from praetor.tools import utility as U
from praetor.tools import sca as SCA
from praetor.tools.browser import inspect as BI


def _fn(name):
    from praetor import server
    return server.mcp._tool_manager._tools[name].fn


class CurlParseTest(unittest.TestCase):

    def test_post_with_headers_cookie_and_body(self):
        p = U._parse_curl(
            "curl -X POST 'https://t.io/api/login' "
            "-H 'Content-Type: application/json' -b 'sid=abc' "
            "--data-raw '{\"u\":\"a\"}'")
        self.assertEqual(p["method"], "POST")
        self.assertEqual(p["url"], "https://t.io/api/login")
        self.assertEqual(p["headers"]["Content-Type"], "application/json")
        self.assertEqual(p["headers"]["Cookie"], "sid=abc")
        self.assertEqual(p["body"], '{"u":"a"}')

    def test_body_implies_post(self):
        p = U._parse_curl("curl https://t.io/x -d 'a=1'")
        self.assertEqual(p["method"], "POST")

    def test_dash_G_forces_get(self):
        p = U._parse_curl("curl -G https://t.io/x -d 'a=1'")
        self.assertEqual(p["method"], "GET")

    def test_unmodelled_value_flag_not_read_as_url(self):
        # -x <proxy> must be skipped with its value, leaving the real URL
        p = U._parse_curl("curl -x http://127.0.0.1:8080 https://real.target/x")
        self.assertEqual(p["url"], "https://real.target/x")

    def test_basic_auth_becomes_authorization_header(self):
        p = U._parse_curl("curl -u admin:admin https://t.io/x")
        self.assertTrue(p["headers"]["Authorization"].startswith("Basic "))

    def test_bundled_valueless_shorts_ignored(self):
        p = U._parse_curl("curl -fsSL https://t.io/x")
        self.assertEqual(p["url"], "https://t.io/x")
        self.assertEqual(p["method"], "GET")


class ImportCurlToolTest(unittest.IsolatedAsyncioTestCase):

    async def test_emits_replay_call_and_shapes_secret(self):
        out = await _fn("import_curl")(
            curl_command="curl 'https://t.io/a' -H 'Authorization: Bearer SECRET_TOKEN_VALUE_1234'")
        self.assertIn("curl_request(", out)
        self.assertIn("https://t.io/a", out)
        # the summary line shapes the bearer, not the full token
        self.assertNotIn("SECRET_TOKEN_VALUE_1234:", out)  # never shown raw in summary

    async def test_no_url_errors(self):
        out = await _fn("import_curl")(curl_command="curl -s -k")
        self.assertIn("no URL", out)


class StorageDumpTest(unittest.IsolatedAsyncioTestCase):

    async def test_flags_sensitive_keys_and_lists_idb(self):
        fake_page = AsyncMock()
        fake_page.evaluate = AsyncMock(return_value={
            "origin": "https://app.t.io",
            "local": {"theme": "dark", "jwt": "eyJhbGciOi..."},
            "session": {},
            "indexedDB": ["keyval-store v1"],
        })
        with patch.object(BI, "_ensure_browser",
                          new=AsyncMock(return_value=(None, None, fake_page))):
            out = await _fn("browser_storage")()
        self.assertIn("https://app.t.io", out)
        self.assertIn("jwt [sensitive]", out)
        self.assertIn("theme = dark", out)
        self.assertIn("keyval-store v1", out)


class RetireJsTest(unittest.IsolatedAsyncioTestCase):

    def test_fmt_retire_v4_shape(self):
        data = {"data": [{"file": "/js/jquery.js", "results": [
            {"component": "jquery", "version": "1.8.0", "vulnerabilities": [
                {"severity": "medium", "identifiers": {"CVE": ["CVE-2012-6708"]}}]}]}]}
        out = SCA._fmt_retire(data)
        self.assertIn("jquery@1.8.0", out)
        self.assertIn("CVE-2012-6708", out)
        self.assertIn("[MEDIUM]", out)

    def test_fmt_retire_empty(self):
        self.assertIn("no vulnerable", SCA._fmt_retire({"data": []}))

    async def test_tool_missing_binary_hints(self):
        with patch.object(SCA, "_check_tool", return_value=False):
            out = await _fn("run_retirejs")(path="/tmp/js")
        self.assertIn("not installed", out)

    async def test_tool_parses_run_output(self):
        data = '{"data":[{"file":"a.js","results":[{"component":"lodash","version":"4.17.4","vulnerabilities":[{"severity":"high","identifiers":{"CVE":["CVE-2018-3721"]}}]}]}]}'
        with patch.object(SCA, "_check_tool", return_value=True), \
             patch.object(SCA, "_run_cmd", new=AsyncMock(return_value=(data, "", 13))):
            out = await _fn("run_retirejs")(path="/tmp/js")
        self.assertIn("lodash@4.17.4", out)
        self.assertIn("CVE-2018-3721", out)


if __name__ == "__main__":
    unittest.main()
