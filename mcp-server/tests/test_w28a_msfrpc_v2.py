"""W28-a — msfrpc v2 tests (module_info / module_check / module_execute)."""

from __future__ import annotations

import base64
import unittest
from unittest.mock import AsyncMock, patch

from burpsuite_mcp import server
from burpsuite_mcp.tools.exploit.msfrpc import (
    _module_type_for,
    _pack,
    _TOKEN_CACHE,
)


def _tool(name: str):
    return server.mcp._tool_manager._tools[name].fn


def _msgpack_b64(obj) -> str:
    return base64.b64encode(_pack(obj)).decode("ascii")


class ModuleTypeInferTest(unittest.TestCase):

    def test_exploit_prefix(self):
        self.assertEqual(_module_type_for(
            "exploit/multi/http/log4shell_header_injection"), "exploit")

    def test_auxiliary_prefix(self):
        self.assertEqual(_module_type_for("auxiliary/scanner/http/x"),
                         "auxiliary")

    def test_post_prefix(self):
        self.assertEqual(_module_type_for("post/multi/manage/x"), "post")

    def test_payload_prefix(self):
        self.assertEqual(_module_type_for("payload/linux/x64/shell"),
                         "payload")

    def test_unknown_prefix(self):
        self.assertIsNone(_module_type_for("notathing/x/y"))


class MsfrpcModuleInfoTest(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        _TOKEN_CACHE.clear()

    async def test_no_token_error(self):
        fn = _tool("msfrpc_module_info")
        out = await fn(module_name="exploit/multi/http/x")
        self.assertEqual(out["verdict"], "ERROR")

    async def test_unknown_prefix_error(self):
        _TOKEN_CACHE["127.0.0.1:55553"] = "tok"
        fn = _tool("msfrpc_module_info")
        out = await fn(module_name="garbage/x/y")
        self.assertEqual(out["verdict"], "ERROR")

    async def test_module_info_returned(self):
        _TOKEN_CACHE["127.0.0.1:55553"] = "tok"
        body_b64 = _msgpack_b64({
            "name": "Log4Shell HTTP Header Injection",
            "rank": "excellent",
            "disclosure_date": "2021-12-09",
            "references": ["CVE-2021-44228", "URL https://logging.apache.org/"],
            "options": {"RHOSTS": "required", "RPORT": "optional"},
        })
        sent = []

        async def fake_post(path, json=None):
            sent.append(json)
            return {"status_code": 200, "response_body_b64": body_b64,
                    "proxy_index": 1}

        with patch("burpsuite_mcp.tools.exploit.msfrpc.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("msfrpc_module_info")
            out = await fn(module_name="exploit/multi/http/log4shell_header_injection")
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertEqual(out["details"]["rank"], "excellent")

        # RPC body must contain module.info + type='exploit' + short name
        from burpsuite_mcp.tools.exploit.msfrpc import unpackb
        body = unpackb(base64.b64decode(sent[0]["data_b64"]))
        self.assertEqual(body[0], "module.info")
        self.assertEqual(body[2], "exploit")
        # short name = full path minus type prefix
        self.assertEqual(body[3], "multi/http/log4shell_header_injection")


class MsfrpcModuleCheckTest(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        _TOKEN_CACHE.clear()

    async def test_no_token_error(self):
        fn = _tool("msfrpc_module_check")
        out = await fn(module_name="exploit/x", options={"RHOSTS": "127.0.0.1"})
        self.assertEqual(out["verdict"], "ERROR")

    async def test_denylisted_dos_refused(self):
        _TOKEN_CACHE["127.0.0.1:55553"] = "tok"
        fn = _tool("msfrpc_module_check")
        out = await fn(module_name="auxiliary/dos/http/some_dos",
                       options={"RHOSTS": "127.0.0.1"})
        self.assertEqual(out["verdict"], "ERROR")
        self.assertIn("hard-deny", out["evidence_summary"])

    async def test_vulnerable_confirmed(self):
        _TOKEN_CACHE["127.0.0.1:55553"] = "tok"
        body_b64 = _msgpack_b64({
            "code": "vulnerable",
            "message": "The target is vulnerable. JNDI-Reference reached.",
        })

        async def fake_post(path, json=None):
            return {"status_code": 200, "response_body_b64": body_b64,
                    "proxy_index": 5}

        with patch("burpsuite_mcp.tools.exploit.msfrpc.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("burpsuite_mcp.tools.exploit.metasploit.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})):
            fn = _tool("msfrpc_module_check")
            out = await fn(
                module_name="exploit/multi/http/log4shell_header_injection",
                options={"RHOSTS": "10.0.0.5", "TARGETURI": "/"})
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertGreaterEqual(out["confidence"], 0.90)

    async def test_safe_failed(self):
        _TOKEN_CACHE["127.0.0.1:55553"] = "tok"
        body_b64 = _msgpack_b64({
            "code": "safe",
            "message": "The target is not vulnerable. Java version too new.",
        })

        async def fake_post(path, json=None):
            return {"status_code": 200, "response_body_b64": body_b64,
                    "proxy_index": 6}

        with patch("burpsuite_mcp.tools.exploit.msfrpc.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("burpsuite_mcp.tools.exploit.metasploit.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})):
            fn = _tool("msfrpc_module_check")
            out = await fn(
                module_name="exploit/multi/http/log4shell_header_injection",
                options={"RHOSTS": "10.0.0.5"})
        self.assertEqual(out["verdict"], "FAILED")

    async def test_detected_suspected(self):
        _TOKEN_CACHE["127.0.0.1:55553"] = "tok"
        body_b64 = _msgpack_b64({
            "code": "detected",
            "message": "Service identified but exploitability not confirmed.",
        })

        async def fake_post(path, json=None):
            return {"status_code": 200, "response_body_b64": body_b64,
                    "proxy_index": 7}

        with patch("burpsuite_mcp.tools.exploit.msfrpc.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("burpsuite_mcp.tools.exploit.metasploit.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})):
            fn = _tool("msfrpc_module_check")
            out = await fn(module_name="exploit/multi/http/x",
                           options={"RHOSTS": "10.0.0.5"})
        self.assertEqual(out["verdict"], "SUSPECTED")


class MsfrpcModuleExecuteTest(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        _TOKEN_CACHE.clear()

    async def test_no_token_error(self):
        fn = _tool("msfrpc_module_execute")
        out = await fn(module_name="exploit/x", options={"RHOSTS": "10.0.0.5"})
        self.assertEqual(out["verdict"], "ERROR")

    async def test_denylisted_persistence_refused(self):
        _TOKEN_CACHE["127.0.0.1:55553"] = "tok"
        fn = _tool("msfrpc_module_execute")
        out = await fn(module_name="post/multi/manage/persistence_meterpreter",
                       options={"RHOSTS": "127.0.0.1"})
        self.assertEqual(out["verdict"], "ERROR")
        self.assertIn("hard-deny", out["evidence_summary"])

    async def test_job_started_confirmed(self):
        _TOKEN_CACHE["127.0.0.1:55553"] = "tok"
        body_b64 = _msgpack_b64({
            "job_id": 42, "uuid": "abc-123-uuid",
        })

        async def fake_post(path, json=None):
            return {"status_code": 200, "response_body_b64": body_b64,
                    "proxy_index": 10}

        with patch("burpsuite_mcp.tools.exploit.msfrpc.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("burpsuite_mcp.tools.exploit.metasploit.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})):
            fn = _tool("msfrpc_module_execute")
            out = await fn(
                module_name="exploit/multi/http/log4shell_header_injection",
                options={"RHOSTS": "10.0.0.5", "LHOST": "10.0.0.99",
                         "LPORT": 4444})
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertEqual(out["details"]["job_id"], 42)

    async def test_no_job_started_failed(self):
        """RPC returns no job_id and no uuid — module failed to start →
        FAILED. The msgpack body may carry an error_message but the _rpc_call
        layer only branches on the literal 'error' key being truthy."""
        _TOKEN_CACHE["127.0.0.1:55553"] = "tok"
        body_b64 = _msgpack_b64({"error_message": "missing option"})

        async def fake_post(path, json=None):
            return {"status_code": 200, "response_body_b64": body_b64,
                    "proxy_index": 11}

        with patch("burpsuite_mcp.tools.exploit.msfrpc.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("burpsuite_mcp.tools.exploit.metasploit.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})):
            fn = _tool("msfrpc_module_execute")
            out = await fn(module_name="exploit/multi/http/x",
                           options={"RHOSTS": "10.0.0.5"})
        self.assertEqual(out["verdict"], "FAILED")
        self.assertIsNone(out["details"]["job_id"])


class MsfrpcV2RegistrationTest(unittest.TestCase):

    def test_three_new_tools_registered(self):
        names = set(server.mcp._tool_manager._tools.keys())
        for required in ("msfrpc_module_info", "msfrpc_module_check",
                         "msfrpc_module_execute"):
            self.assertIn(required, names)


if __name__ == "__main__":
    unittest.main()
