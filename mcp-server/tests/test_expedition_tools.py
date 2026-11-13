"""MCP tools for the burp-expedition TCP/UDP proxy lane (:18112) — wiring only."""

import tempfile
import unittest
from pathlib import Path
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

    async def test_add_listener_framing_and_socks_auth_and_tls_passthrough(self):
        """The control API's /listeners now also takes tls_passthrough, SOCKS5
        username/password, and length/delimiter framing — added reviewing the
        current burp-expedition Control API, which had these fields with no
        tool exposing them."""
        captured = {}

        async def fake_post(path, json=None):
            captured["json"] = json
            return {"ok": True}

        with patch.object(_client, "post", new=AsyncMock(side_effect=fake_post)):
            await _fn("tcp_proxy_add_listener")(
                name="modbus", bind_port=15020, upstream_host="10.0.0.5",
                upstream_port=502, protocol="tcp", framing="length",
                length_offset=0, length_size=2, length_endian="big",
                length_adjust=1, max_frame_bytes=2048,
            )
        self.assertEqual(captured["json"]["framing"], "length")
        self.assertEqual(captured["json"]["length_size"], 2)
        self.assertEqual(captured["json"]["length_adjust"], 1)
        self.assertEqual(captured["json"]["max_frame_bytes"], 2048)

        with patch.object(_client, "post", new=AsyncMock(side_effect=fake_post)):
            await _fn("tcp_proxy_add_listener")(
                name="dyn2", bind_port=11081, protocol="socks5",
                socks_username="op", socks_password="pw",
                tls_passthrough="internal.corp,*.svc.local",
            )
        self.assertEqual(captured["json"]["username"], "op")
        self.assertEqual(captured["json"]["password"], "pw")
        self.assertEqual(captured["json"]["tls_passthrough"], ["internal.corp", "*.svc.local"])

    async def test_delimiter_framing_needs_a_delimiter(self):
        out = await _fn("tcp_proxy_add_listener")(
            name="bad", bind_port=1235, upstream_host="h", upstream_port=1,
            protocol="tcp", framing="delimiter")
        self.assertIn("needs delimiter", out)

    async def test_broken_duplicate_tag_tool_was_removed(self):
        """tcp_tag_connection sent {"tag": ...} but the current extension's
        /connections/{id}/tag handler only reads color/comment — it would
        always 400. tcp_search_messages was an exact duplicate of tcp_search
        (same endpoint, same params). Both removed; tcp_get_tags added for
        the previously-unwired GET /connections/{id}/tags."""
        from praetor import server
        names = server.mcp._tool_manager._tools
        self.assertNotIn("tcp_tag_connection", names)
        self.assertNotIn("tcp_search_messages", names)
        self.assertIn("tcp_get_tags", names)
        self.assertIn("tcp_annotate", names)
        self.assertIn("tcp_search", names)

    async def test_get_tags_reads_back(self):
        with patch.object(_client, "get", new=AsyncMock(return_value={"connection_id": 7, "tags": ["RED|evidence"]})):
            out = await _fn("tcp_get_tags")(connection_id=7)
        self.assertIn("RED|evidence", out)


class ExpeditionScriptDnsToolsTest(unittest.IsolatedAsyncioTestCase):
    """tcp_script_* / tcp_dns_* — added wiring the Control API's /script and
    /dns endpoints, which existed in burp-expedition with no tool calling them."""

    async def test_script_set_requires_source(self):
        out = await _fn("tcp_script_set")(source="")
        self.assertIn("source required", out)

    async def test_script_set_posts_source(self):
        captured = {}

        async def fake_post(path, json=None):
            captured.update(path=path, json=json)
            return {"ok": True, "installed": True}

        with patch.object(_client, "post", new=AsyncMock(side_effect=fake_post)):
            out = await _fn("tcp_script_set")(source="function onMessage(m) { return m; }")
        self.assertEqual(captured["path"], "/script")
        self.assertIn("function onMessage", captured["json"]["source"])
        self.assertIn("installed", out.lower())

    async def test_dns_start_parses_rules_and_requires_one(self):
        out = await _fn("tcp_dns_start")()
        self.assertIn("at least one rule or default_ip", out)

        captured = {}

        async def fake_post(path, json=None):
            captured.update(path=path, json=json)
            return {"ok": True, "host": json["host"], "port": json["port"]}

        with patch.object(_client, "post", new=AsyncMock(side_effect=fake_post)):
            out2 = await _fn("tcp_dns_start")(
                rules="api.target.com=127.0.0.1,db.target.com=127.0.0.1",
                default_ip="10.0.0.9")
        self.assertEqual(captured["path"], "/dns/start")
        self.assertEqual(
            captured["json"]["rules"],
            [{"host": "api.target.com", "ip": "127.0.0.1"}, {"host": "db.target.com", "ip": "127.0.0.1"}],
        )
        self.assertEqual(captured["json"]["default_ip"], "10.0.0.9")
        self.assertIn("2 rule(s)", out2)

    async def test_dns_stop(self):
        with patch.object(_client, "post", new=AsyncMock(return_value={"ok": True})):
            out = await _fn("tcp_dns_stop")()
        self.assertIn("stopped", out)


class ExpeditionTokenResolutionTest(unittest.TestCase):
    """The control API made auth mandatory on every request (no loopback
    bypass) in a recent burp-expedition update; the Python client previously
    only sent a token when the operator set EXPEDITION_API_TOKEN by hand,
    so every tcp_*/probe_*_unauth call would 401 against the new default
    (a random token auto-written to ~/.expedition/api-token)."""

    def test_explicit_env_token_wins(self):
        with patch.dict("os.environ", {"EXPEDITION_API_TOKEN": "explicit"}, clear=False):
            self.assertEqual(_client._headers(), {"Authorization": "Bearer explicit"})

    def test_falls_back_to_token_file(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "api-token").write_text("file-token-abc\n")
            with patch.dict("os.environ", {"EXPEDITION_CA_DIR": td}, clear=False):
                with patch.dict("os.environ", {}, clear=False):
                    import os as _os
                    _os.environ.pop("EXPEDITION_API_TOKEN", None)
                    self.assertEqual(_client._headers(), {"Authorization": "Bearer file-token-abc"})

    def test_no_token_no_file_sends_no_auth_header(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.dict("os.environ", {"EXPEDITION_CA_DIR": td}, clear=False):
                import os as _os
                _os.environ.pop("EXPEDITION_API_TOKEN", None)
                self.assertEqual(_client._headers(), {})

    def test_token_resolved_per_call_not_cached_at_import(self):
        """A long-running MCP server can start before the extension has ever
        written its token file; caching an empty token at import time would
        401 forever even after the file later appears."""
        with tempfile.TemporaryDirectory() as td:
            with patch.dict("os.environ", {"EXPEDITION_CA_DIR": td}, clear=False):
                import os as _os
                _os.environ.pop("EXPEDITION_API_TOKEN", None)
                self.assertEqual(_client._headers(), {})
                (Path(td) / "api-token").write_text("late-token\n")
                self.assertEqual(_client._headers(), {"Authorization": "Bearer late-token"})


if __name__ == "__main__":
    unittest.main()
