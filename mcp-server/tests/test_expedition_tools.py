"""MCP tools for the burp-expedition TCP/UDP proxy lane (:8112) — wiring only."""

import unittest
from unittest.mock import AsyncMock, patch

from praetor.tools.expedition import _client


def _fn(name):
    from praetor import server
    return server.mcp._tool_manager._tools[name].fn


class ExpeditionToolsTest(unittest.IsolatedAsyncioTestCase):

    async def test_add_listener_posts_config(self):
        captured = {}

        async def fake_post(path, json=None):
            captured["path"] = path
            captured["json"] = json
            return {"ok": True, "name": json["name"]}

        with patch.object(_client, "post", new=AsyncMock(side_effect=fake_post)):
            out = await _fn("tcp_proxy_add_listener")(
                name="redis", upstream_host="10.0.0.5", upstream_port=6379,
                bind_port=16379, protocol="tcp", tls="mitm")
        self.assertEqual(captured["path"], "/listeners")
        self.assertEqual(captured["json"]["upstream_port"], 6379)
        self.assertEqual(captured["json"]["tls"], "mitm")
        self.assertIn("redis", out)
        self.assertIn("TLS MITM", out)

    async def test_socks5_listener_needs_no_upstream(self):
        captured = {}

        async def fake_post(path, json=None):
            captured["json"] = json
            return {"ok": True, "name": json["name"]}

        with patch.object(_client, "post", new=AsyncMock(side_effect=fake_post)):
            out = await _fn("tcp_proxy_add_listener")(
                name="dyn", bind_port=11080, protocol="socks5",
                upstream_proxy="10.0.0.9:9050")
        # socks5 payload omits the fixed upstream, forwards the chain proxy
        self.assertNotIn("upstream_host", captured["json"])
        self.assertEqual(captured["json"]["upstream_proxy"], "10.0.0.9:9050")
        self.assertIn("SOCKS5", out)

    async def test_tcp_listener_requires_upstream(self):
        out = await _fn("tcp_proxy_add_listener")(
            name="bad", bind_port=1234, protocol="tcp")
        self.assertIn("upstream_host and upstream_port are required", out)

    async def test_repeat_requires_payload(self):
        out = await _fn("tcp_repeat")(host="10.0.0.5", port=6379)
        self.assertIn("supply a payload", out)

    async def test_repeat_sends_hex_and_formats_response(self):
        async def fake_post(path, json=None):
            self.assertEqual(path, "/repeat")
            self.assertEqual(json["hex"], "2a31")
            return {"sent_len": 2, "response_len": 5, "response_text": "+PONG",
                    "response_hex": "2b504f4e47"}

        with patch.object(_client, "post", new=AsyncMock(side_effect=fake_post)):
            out = await _fn("tcp_repeat")(host="10.0.0.5", port=6379, hex="2a31")
        self.assertIn("received 5B", out)
        self.assertIn("PONG", out)

    async def test_connections_formats_rows(self):
        rows = [{"id": 1, "protocol": "TCP", "client": "1.2.3.4:5",
                 "upstream": "10.0.0.5:6379", "listener": "redis", "closed_at": None}]
        with patch.object(_client, "get_list", new=AsyncMock(return_value=rows)):
            out = await _fn("tcp_proxy_connections")()
        self.assertIn("#1", out)
        self.assertIn("redis", out)
        self.assertIn("open", out)

    async def test_unreachable_surfaces_clear_error(self):
        with patch.object(_client, "get", new=AsyncMock(return_value={"error": "Cannot reach burp-expedition"})):
            out = await _fn("tcp_proxy_status")()
        self.assertIn("Cannot reach", out)


if __name__ == "__main__":
    unittest.main()
