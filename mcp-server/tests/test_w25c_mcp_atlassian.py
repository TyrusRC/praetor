"""W25-c — probe_mcp_server_attacks (CVE-2026-27825 path traversal +
CVE-2026-27826 header SSRF)."""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from burpsuite_mcp import server


def _tool(name: str):
    return server.mcp._tool_manager._tools[name].fn


class McpServerAttacksErrorPathsTest(unittest.IsolatedAsyncioTestCase):

    async def test_no_base_url_returns_error(self):
        fn = _tool("probe_mcp_server_attacks")
        out = await fn(base_url="")
        self.assertEqual(out["verdict"], "ERROR")

    async def test_scope_reject_returns_error(self):
        with patch("burpsuite_mcp.tools.exploit.mcp_atlassian.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": False})):
            fn = _tool("probe_mcp_server_attacks")
            out = await fn(base_url="https://oos/")
        self.assertEqual(out["verdict"], "ERROR")
        self.assertIn("not in scope", out["evidence_summary"])


class McpServerAttacksVerdictTest(unittest.IsolatedAsyncioTestCase):

    async def test_lfi_linux_extract_confirmed(self):
        """LFI canary returning /etc/passwd content → CONFIRMED (critical)."""
        call_idx = [0]

        async def fake_post(path, json=None):
            i = call_idx[0]
            call_idx[0] += 1
            # First LFI probe returns /etc/passwd — second+ return generic 404
            if i == 0:
                return {
                    "status_code": 200,
                    "response_body": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                    "proxy_index": 100 + i,
                }
            return {"status_code": 404, "response_body": "not found",
                    "proxy_index": 100 + i}

        with patch("burpsuite_mcp.tools.exploit.mcp_atlassian.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})), \
             patch("burpsuite_mcp.tools.exploit.mcp_atlassian.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("burpsuite_mcp.tools.exploit.mcp_atlassian.client.get",
                   new=AsyncMock(return_value={"interactions": []})):
            fn = _tool("probe_mcp_server_attacks")
            out = await fn(base_url="https://t.example/",
                           path_traversal_only=True)
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertEqual(out["vuln_type"], "mcp_server_attacks")
        self.assertGreaterEqual(out["details"]["lfi_hits"], 1)

    async def test_lfi_windows_extract_confirmed(self):
        """Windows LFI canary returning win.ini content → CONFIRMED."""
        call_idx = [0]

        async def fake_post(path, json=None):
            i = call_idx[0]
            call_idx[0] += 1
            # Path with 'windows' in it returns win.ini
            url = json.get("url", "") if isinstance(json, dict) else ""
            if "windows" in url.lower() or "win.ini" in url.lower():
                return {
                    "status_code": 200,
                    "response_body": "[fonts]\n[extensions]\nfor 16-bit app support",
                    "proxy_index": 200 + i,
                }
            return {"status_code": 404, "response_body": "not found",
                    "proxy_index": 200 + i}

        with patch("burpsuite_mcp.tools.exploit.mcp_atlassian.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})), \
             patch("burpsuite_mcp.tools.exploit.mcp_atlassian.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("burpsuite_mcp.tools.exploit.mcp_atlassian.client.get",
                   new=AsyncMock(return_value={"interactions": []})):
            fn = _tool("probe_mcp_server_attacks")
            out = await fn(base_url="https://t.example/",
                           path_traversal_only=True)
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertGreaterEqual(out["details"]["lfi_hits"], 1)

    async def test_header_ssrf_imds_extract_confirmed(self):
        """Header-SSRF hits IMDS, body contains AccessKeyId → CONFIRMED."""
        call_idx = [0]

        async def fake_post(path, json=None):
            i = call_idx[0]
            call_idx[0] += 1
            # Return IMDS markers on first header-SSRF attempt
            if i == 0:
                return {
                    "status_code": 200,
                    "response_body": '{"AccessKeyId":"ASIA...", "ami-id":"ami-xyz"}',
                    "proxy_index": 300 + i,
                }
            return {"status_code": 200, "response_body": "ok",
                    "proxy_index": 300 + i}

        with patch("burpsuite_mcp.tools.exploit.mcp_atlassian.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})), \
             patch("burpsuite_mcp.tools.exploit.mcp_atlassian.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("burpsuite_mcp.tools.exploit.mcp_atlassian.client.get",
                   new=AsyncMock(return_value={"interactions": []})):
            fn = _tool("probe_mcp_server_attacks")
            out = await fn(base_url="https://t.example/",
                           header_ssrf_only=True)
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertGreaterEqual(out["details"]["ssrf_hits"], 1)

    async def test_collaborator_callback_confirmed(self):
        """Blind header-SSRF via Collaborator callback → CONFIRMED."""

        async def fake_post(path, json=None):
            return {"status_code": 200, "response_body": "ok", "proxy_index": 50}

        async def fake_get(path):
            return {"interactions": [
                {"type": "HTTP", "payload_id": "abc123",
                 "raw": "mcp-ssrf-canary received"}
            ]}

        with patch("burpsuite_mcp.tools.exploit.mcp_atlassian.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})), \
             patch("burpsuite_mcp.tools.exploit.mcp_atlassian.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("burpsuite_mcp.tools.exploit.mcp_atlassian.client.get",
                   new=AsyncMock(side_effect=fake_get)):
            fn = _tool("probe_mcp_server_attacks")
            out = await fn(base_url="https://t.example/",
                           header_ssrf_only=True,
                           collaborator_url="xyz.oastify.com")
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertIn("abc123", out["collaborator_interactions"])

    async def test_clean_target_failed(self):
        """Patched target returns no LFI extracts and no IMDS markers → FAILED."""

        async def fake_post(path, json=None):
            return {"status_code": 404, "response_body": "Not Found",
                    "proxy_index": 1}

        with patch("burpsuite_mcp.tools.exploit.mcp_atlassian.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})), \
             patch("burpsuite_mcp.tools.exploit.mcp_atlassian.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("burpsuite_mcp.tools.exploit.mcp_atlassian.client.get",
                   new=AsyncMock(return_value={"interactions": []})):
            fn = _tool("probe_mcp_server_attacks")
            out = await fn(base_url="https://t.example/")
        self.assertEqual(out["verdict"], "FAILED")
        self.assertEqual(out["details"]["lfi_hits"], 0)
        self.assertEqual(out["details"]["ssrf_hits"], 0)


class McpServerAttacksRegistrationTest(unittest.TestCase):

    def test_tool_registered(self):
        names = set(server.mcp._tool_manager._tools.keys())
        self.assertIn("probe_mcp_server_attacks", names)


if __name__ == "__main__":
    unittest.main()
