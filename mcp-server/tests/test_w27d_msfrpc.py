"""W27-d — msfrpc thin client tests.

Two layers:
  1. Pure msgpack round-trip — exercises _pack/_unpack with the value types
     msfrpcd actually returns (nil/bool/int/str/bin/array/map).
  2. Tool-layer auth + search behaviour with mocked HTTP."""

from __future__ import annotations

import base64
import unittest
from unittest.mock import AsyncMock, patch

from burpsuite_mcp import server
from burpsuite_mcp.tools.exploit.msfrpc import _pack, _TOKEN_CACHE, unpackb


def _tool(name: str):
    return server.mcp._tool_manager._tools[name].fn


def _msgpack_b64(obj) -> str:
    """Helper: pack obj and base64-encode (matches the on-wire shape the
    Java extension returns via response_body_b64)."""
    return base64.b64encode(_pack(obj)).decode("ascii")


class MsgpackRoundtripTest(unittest.TestCase):

    def test_nil_bool(self):
        for v in (None, True, False):
            self.assertEqual(unpackb(_pack(v)), v)

    def test_small_ints(self):
        for v in (0, 1, 127, -1, -32, -33, 128, 255, 65535, 16777216):
            self.assertEqual(unpackb(_pack(v)), v)

    def test_neg_ints(self):
        for v in (-128, -32768, -2**31, -2**63):
            self.assertEqual(unpackb(_pack(v)), v)

    def test_strings(self):
        for v in ("", "a", "hello", "x" * 100, "y" * 70000):
            self.assertEqual(unpackb(_pack(v)), v)

    def test_bytes(self):
        for v in (b"", b"abc", b"x" * 300):
            self.assertEqual(unpackb(_pack(v)), v)

    def test_lists(self):
        for v in ([], [1, 2, 3], ["a", "b"], list(range(50))):
            self.assertEqual(unpackb(_pack(v)), v)

    def test_maps(self):
        for v in ({}, {"a": 1}, {"version": "6.4", "ruby": "3.2"}):
            self.assertEqual(unpackb(_pack(v)), v)

    def test_nested(self):
        v = {"result": "success", "token": "abc123",
             "modules": ["exploit/multi/http/x", "exploit/multi/http/y"],
             "count": 2, "ok": True, "meta": None}
        self.assertEqual(unpackb(_pack(v)), v)


class MsfrpcLoginTest(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        _TOKEN_CACHE.clear()

    async def test_non_loopback_refused(self):
        fn = _tool("msfrpc_login")
        out = await fn(password="x", host="8.8.8.8")
        self.assertEqual(out["verdict"], "ERROR")
        self.assertIn("loopback", out["evidence_summary"])

    async def test_successful_login_caches_token(self):
        body_b64 = _msgpack_b64({"result": "success",
                                  "token": "abcdef1234567890"})

        async def fake_post(path, json=None):
            return {"status_code": 200, "response_body_b64": body_b64,
                    "proxy_index": 1}

        with patch("burpsuite_mcp.tools.exploit.msfrpc.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("msfrpc_login")
            out = await fn(password="pw")
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertEqual(_TOKEN_CACHE.get("127.0.0.1:55553"),
                         "abcdef1234567890")

    async def test_rpc_error_returned(self):
        body_b64 = _msgpack_b64({"error": True,
                                  "error_message": "Invalid User ID or Password"})

        async def fake_post(path, json=None):
            return {"status_code": 200, "response_body_b64": body_b64,
                    "proxy_index": 1}

        with patch("burpsuite_mcp.tools.exploit.msfrpc.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("msfrpc_login")
            out = await fn(password="wrong")
        self.assertEqual(out["verdict"], "ERROR")
        self.assertIn("Invalid User ID", out["evidence_summary"])

    async def test_http_non_200_error(self):
        async def fake_post(path, json=None):
            return {"status_code": 401, "response_body_b64": "",
                    "proxy_index": 1}
        with patch("burpsuite_mcp.tools.exploit.msfrpc.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("msfrpc_login")
            out = await fn(password="x")
        self.assertEqual(out["verdict"], "ERROR")


class MsfrpcVersionTest(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        _TOKEN_CACHE.clear()

    async def test_no_token_returns_error(self):
        fn = _tool("msfrpc_version")
        out = await fn()
        self.assertEqual(out["verdict"], "ERROR")
        self.assertIn("call msfrpc_login first", out["evidence_summary"])

    async def test_version_returned(self):
        _TOKEN_CACHE["127.0.0.1:55553"] = "tok"
        body_b64 = _msgpack_b64({"version": "6.4.10-dev",
                                  "ruby": "3.2.2", "api": "1.2"})

        async def fake_post(path, json=None):
            return {"status_code": 200, "response_body_b64": body_b64,
                    "proxy_index": 2}

        with patch("burpsuite_mcp.tools.exploit.msfrpc.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("msfrpc_version")
            out = await fn()
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertEqual(out["details"]["version"], "6.4.10-dev")


class MsfrpcModuleSearchTest(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        _TOKEN_CACHE.clear()

    async def test_no_token_returns_error(self):
        fn = _tool("msfrpc_module_search")
        out = await fn(query="log4shell")
        self.assertEqual(out["verdict"], "ERROR")

    async def test_search_returns_modules(self):
        _TOKEN_CACHE["127.0.0.1:55553"] = "tok"
        body_b64 = _msgpack_b64({"modules": [
            "exploit/multi/http/log4shell_header_injection",
            "auxiliary/scanner/http/log4shell_scanner",
        ]})

        async def fake_post(path, json=None):
            return {"status_code": 200, "response_body_b64": body_b64,
                    "proxy_index": 3}

        with patch("burpsuite_mcp.tools.exploit.msfrpc.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("msfrpc_module_search")
            out = await fn(query="log4shell")
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertEqual(out["details"]["count"], 2)

    async def test_cve_query_rewritten(self):
        """CVE-YYYY-NNNN gets rewritten to cve:YYYY-NNNN (parity with W23-b)."""
        _TOKEN_CACHE["127.0.0.1:55553"] = "tok"
        body_b64 = _msgpack_b64({"modules": ["exploit/x"]})
        sent_params = []

        async def fake_post(path, json=None):
            sent_params.append(json)
            return {"status_code": 200, "response_body_b64": body_b64,
                    "proxy_index": 4}

        with patch("burpsuite_mcp.tools.exploit.msfrpc.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("msfrpc_module_search")
            out = await fn(query="CVE-2024-12345")
        self.assertEqual(out["verdict"], "CONFIRMED")
        # The packed RPC body should contain the rewritten query
        body_b64_sent = sent_params[0]["data_b64"]
        body_bytes = base64.b64decode(body_b64_sent)
        decoded = unpackb(body_bytes)
        # Decoded should be ["module.search", "tok", "cve:2024-12345"]
        self.assertEqual(decoded[0], "module.search")
        self.assertEqual(decoded[2], "cve:2024-12345")

    async def test_empty_results_failed(self):
        _TOKEN_CACHE["127.0.0.1:55553"] = "tok"
        body_b64 = _msgpack_b64({"modules": []})

        async def fake_post(path, json=None):
            return {"status_code": 200, "response_body_b64": body_b64,
                    "proxy_index": 5}

        with patch("burpsuite_mcp.tools.exploit.msfrpc.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("msfrpc_module_search")
            out = await fn(query="nothing")
        self.assertEqual(out["verdict"], "FAILED")


class MsfrpcRegistrationTest(unittest.TestCase):

    def test_all_three_tools_registered(self):
        names = set(server.mcp._tool_manager._tools.keys())
        for required in ("msfrpc_login", "msfrpc_version", "msfrpc_module_search"):
            self.assertIn(required, names)


if __name__ == "__main__":
    unittest.main()
