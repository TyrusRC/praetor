"""burp_settings dispatcher — settable actions hit the exact existing REST endpoints;
unsettable actions return a manual dict without calling the extension."""
import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from mcp.server.fastmcp import FastMCP

from praetor.tools import burp_settings as bs_mod


def _get_tool():
    mcp = FastMCP("test")
    bs_mod.register(mcp)
    return mcp._tool_manager.get_tool("burp_settings").fn


class BurpSettingsDispatchTest(unittest.TestCase):
    def test_scope_add_posts_configure_with_include(self):
        burp_settings = _get_tool()
        with patch.object(bs_mod.client, "post", new=AsyncMock(return_value={"included": 1})) as p:
            result = asyncio.run(burp_settings(action="scope_add", urls=["https://x.com"]))
            p.assert_awaited_once()
            args, kwargs = p.call_args
            self.assertEqual(args[0], "/api/scope/configure")
            self.assertEqual(kwargs["json"]["include"], ["https://x.com"])
            self.assertEqual(kwargs["json"]["exclude"], [])
            self.assertEqual(result, {"included": 1})

    def test_scope_exclude_posts_configure_with_exclude(self):
        burp_settings = _get_tool()
        with patch.object(bs_mod.client, "post", new=AsyncMock(return_value={"excluded": 1})) as p:
            asyncio.run(burp_settings(action="scope_exclude", urls=["https://x.com"]))
            args, kwargs = p.call_args
            self.assertEqual(args[0], "/api/scope/configure")
            self.assertEqual(kwargs["json"]["include"], [])
            self.assertEqual(kwargs["json"]["exclude"], ["https://x.com"])

    def test_scope_get_calls_get_scope_endpoint(self):
        burp_settings = _get_tool()
        with patch.object(bs_mod.client, "get", new=AsyncMock(return_value={"in_scope_hosts": []})) as g:
            asyncio.run(burp_settings(action="scope_get"))
            g.assert_awaited_once_with("/api/scope")

    def test_scope_check_posts_url(self):
        burp_settings = _get_tool()
        with patch.object(bs_mod.client, "post", new=AsyncMock(return_value={"in_scope": True})) as p:
            asyncio.run(burp_settings(action="scope_check", url="https://x.com/a"))
            p.assert_awaited_once_with("/api/scope/check", json={"url": "https://x.com/a"})

    def test_intercept_on_posts_enable(self):
        burp_settings = _get_tool()
        with patch.object(bs_mod.client, "post", new=AsyncMock(return_value={"intercept_enabled": True})) as p:
            asyncio.run(burp_settings(action="intercept_on"))
            p.assert_awaited_once_with("/api/intercept/enable")

    def test_intercept_off_posts_disable(self):
        burp_settings = _get_tool()
        with patch.object(bs_mod.client, "post", new=AsyncMock(return_value={"intercept_enabled": False})) as p:
            asyncio.run(burp_settings(action="intercept_off"))
            p.assert_awaited_once_with("/api/intercept/disable")

    def test_intercept_status_gets_status(self):
        burp_settings = _get_tool()
        with patch.object(bs_mod.client, "get", new=AsyncMock(return_value={"intercept_enabled": False})) as g:
            asyncio.run(burp_settings(action="intercept_status"))
            g.assert_awaited_once_with("/api/intercept/status")

    def test_match_replace_list_gets_match_replace(self):
        burp_settings = _get_tool()
        with patch.object(bs_mod.client, "get", new=AsyncMock(return_value={"rules": []})) as g:
            asyncio.run(burp_settings(action="match_replace_list"))
            g.assert_awaited_once_with("/api/match-replace")

    def test_match_replace_delete_without_rule_id_errors(self):
        burp_settings = _get_tool()
        with patch.object(bs_mod.client, "delete", new=AsyncMock()) as d:
            result = asyncio.run(burp_settings(action="match_replace_delete"))
            self.assertIn("error", result)
            d.assert_not_awaited()

    def test_match_replace_delete_with_rule_id_calls_delete(self):
        burp_settings = _get_tool()
        with patch.object(bs_mod.client, "delete", new=AsyncMock(return_value={"removed": True})) as d:
            asyncio.run(burp_settings(action="match_replace_delete", rule_id="3"))
            d.assert_awaited_once_with("/api/match-replace/3")

    def test_match_replace_clear_posts_clear(self):
        burp_settings = _get_tool()
        with patch.object(bs_mod.client, "post", new=AsyncMock(return_value={"cleared": True})) as p:
            asyncio.run(burp_settings(action="match_replace_clear"))
            p.assert_awaited_once_with("/api/match-replace/clear")

    def test_match_replace_add_dangerous_host_rule_refused_without_force(self):
        burp_settings = _get_tool()
        dangerous_rules = [{"type": "request_header", "match": "Host: .*", "replace": "evil.com"}]
        with patch.object(bs_mod.client, "post", new=AsyncMock()) as p:
            result = asyncio.run(burp_settings(action="match_replace_add", rules=dangerous_rules, force=False))
            self.assertIn("error", result)
            p.assert_not_awaited()

    def test_match_replace_add_dangerous_host_rule_allowed_with_force(self):
        burp_settings = _get_tool()
        dangerous_rules = [{"type": "request_header", "match": "Host: .*", "replace": "evil.com"}]
        with patch.object(bs_mod.client, "post", new=AsyncMock(return_value={"rules": dangerous_rules})) as p:
            result = asyncio.run(burp_settings(action="match_replace_add", rules=dangerous_rules, force=True))
            p.assert_awaited_once_with("/api/match-replace/add", json={"rules": dangerous_rules})
            self.assertEqual(result, {"rules": dangerous_rules})

    def test_match_replace_add_without_rules_errors(self):
        burp_settings = _get_tool()
        with patch.object(bs_mod.client, "post", new=AsyncMock()) as p:
            result = asyncio.run(burp_settings(action="match_replace_add", rules=None))
            self.assertIn("error", result)
            p.assert_not_awaited()

    def test_proxy_listener_returns_manual_without_client_call(self):
        burp_settings = _get_tool()
        with patch.object(bs_mod.client, "get", new=AsyncMock()) as g, \
             patch.object(bs_mod.client, "post", new=AsyncMock()) as p:
            result = asyncio.run(burp_settings(action="proxy_listener"))
            self.assertIn("manual", result)
            self.assertEqual(result["montoya"], False)
            g.assert_not_awaited()
            p.assert_not_awaited()

    def test_all_manual_actions_return_manual_dict(self):
        burp_settings = _get_tool()
        for action in ("proxy_listener", "upstream_proxy", "tls", "native_match_replace", "intercept_state_read"):
            with patch.object(bs_mod.client, "get", new=AsyncMock()) as g, \
                 patch.object(bs_mod.client, "post", new=AsyncMock()) as p:
                result = asyncio.run(burp_settings(action=action))
                self.assertIn("manual", result, f"action={action}")
                self.assertFalse(result["montoya"], f"action={action}")
                g.assert_not_awaited()
                p.assert_not_awaited()

    def test_unknown_action_errors(self):
        burp_settings = _get_tool()
        result = asyncio.run(burp_settings(action="not_a_real_action"))
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
