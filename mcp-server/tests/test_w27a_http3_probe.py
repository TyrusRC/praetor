"""W27-a — probe_http3_downgrade tests."""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from burpsuite_mcp import server


def _tool(name: str):
    return server.mcp._tool_manager._tools[name].fn


class Http3ProbeErrorPathsTest(unittest.IsolatedAsyncioTestCase):

    async def test_no_url_returns_error(self):
        fn = _tool("probe_http3_downgrade")
        out = await fn(url="")
        self.assertEqual(out["verdict"], "ERROR")

    async def test_scope_reject_returns_error(self):
        with patch("burpsuite_mcp.tools.http3_probe.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": False})):
            fn = _tool("probe_http3_downgrade")
            out = await fn(url="https://oos/")
        self.assertEqual(out["verdict"], "ERROR")


class Http3ProbeVerdictTest(unittest.IsolatedAsyncioTestCase):

    async def test_no_alt_svc_advertisement_failed(self):
        """Server doesn't advertise H3 and no operator override → FAILED."""

        async def fake_post(path, json=None):
            return {"status_code": 200, "response_body": "ok",
                    "response_headers": [{"name": "Server", "value": "nginx"}],
                    "proxy_index": 1}

        with patch("burpsuite_mcp.tools.http3_probe.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})), \
             patch("burpsuite_mcp.tools.http3_probe.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_http3_downgrade")
            out = await fn(url="https://t.example.com/")
        self.assertEqual(out["verdict"], "FAILED")
        self.assertIn("no Alt-Svc", out["evidence_summary"])

    async def test_alt_svc_advertised_no_diff_failed(self):
        """H3 advertised, but H2 baseline and Alt-Used path return identical
        fingerprints → no downgrade differential → FAILED."""
        body = "<html>same content</html>"
        call_idx = [0]

        async def fake_post(path, json=None):
            i = call_idx[0]
            call_idx[0] += 1
            return {
                "status_code": 200, "response_body": body,
                "response_headers": [
                    {"name": "Alt-Svc", "value": 'h3=":443"; ma=86400'},
                    {"name": "Content-Type", "value": "text/html"},
                ],
                "proxy_index": 10 + i,
            }

        with patch("burpsuite_mcp.tools.http3_probe.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})), \
             patch("burpsuite_mcp.tools.http3_probe.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_http3_downgrade")
            out = await fn(url="https://t.example.com/")
        self.assertEqual(out["verdict"], "FAILED")
        self.assertEqual(out["details"]["h3_targets_advertised"], [":443"])

    async def test_status_divergence_confirmed(self):
        """Baseline 200 vs Alt-Used 403 → CONFIRMED downgrade differential."""
        call_idx = [0]

        async def fake_post(path, json=None):
            i = call_idx[0]
            call_idx[0] += 1
            if i == 0:
                return {
                    "status_code": 200,
                    "response_body": "<html>baseline</html>",
                    "response_headers": [
                        {"name": "Alt-Svc", "value": 'h3="h3.target.com:443"'},
                    ],
                    "proxy_index": 20,
                }
            return {
                "status_code": 403,
                "response_body": "Forbidden",
                "response_headers": [{"name": "X-Cache", "value": "MISS"}],
                "proxy_index": 21,
            }

        with patch("burpsuite_mcp.tools.http3_probe.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})), \
             patch("burpsuite_mcp.tools.http3_probe.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_http3_downgrade")
            out = await fn(url="https://t.example.com/")
        self.assertEqual(out["verdict"], "CONFIRMED")
        self.assertEqual(out["details"]["diff"]["status"], [200, 403])

    async def test_body_hash_diff_suspected(self):
        """Different body content but same status → SUSPECTED (not CONFIRMED;
        status mismatch is the CONFIRMED-bar marker)."""
        call_idx = [0]

        async def fake_post(path, json=None):
            i = call_idx[0]
            call_idx[0] += 1
            if i == 0:
                return {
                    "status_code": 200,
                    "response_body": "<html>baseline content here</html>" + "X" * 500,
                    "response_headers": [
                        {"name": "Alt-Svc", "value": 'h3=":443"'},
                    ],
                    "proxy_index": 30,
                }
            # Different body — but same status
            return {
                "status_code": 200,
                "response_body": "<html>different content body</html>" + "Y" * 500,
                "response_headers": [],
                "proxy_index": 31,
            }

        with patch("burpsuite_mcp.tools.http3_probe.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})), \
             patch("burpsuite_mcp.tools.http3_probe.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_http3_downgrade")
            out = await fn(url="https://t.example.com/")
        self.assertEqual(out["verdict"], "SUSPECTED")
        self.assertTrue(out["details"]["diff"]["body_hash_differs"])

    async def test_force_alt_used_override(self):
        """Operator-supplied force_alt_used bypasses Alt-Svc detection."""
        call_idx = [0]

        async def fake_post(path, json=None):
            i = call_idx[0]
            call_idx[0] += 1
            return {"status_code": 200, "response_body": "same",
                    "response_headers": [],  # no Alt-Svc advertisement
                    "proxy_index": 40 + i}

        with patch("burpsuite_mcp.tools.http3_probe.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})), \
             patch("burpsuite_mcp.tools.http3_probe.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_http3_downgrade")
            out = await fn(url="https://t.example.com/",
                           force_alt_used="h3.target.com:443")
        # No advertisement but force_alt_used → still probes H3 path
        self.assertEqual(out["verdict"], "FAILED")
        self.assertEqual(out["details"]["alt_used"], "h3.target.com:443")


class Http3ProbeRegistrationTest(unittest.TestCase):

    def test_tool_registered(self):
        names = set(server.mcp._tool_manager._tools.keys())
        self.assertIn("probe_http3_downgrade", names)


if __name__ == "__main__":
    unittest.main()
