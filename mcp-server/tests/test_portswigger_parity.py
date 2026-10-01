"""PortSwigger-MCP parity: burp_settings options/task-engine, organizer read,
random string, and the honest active_editor 'manual' path.

The Burp-side endpoints are exercised in a live Burp; these cover the Python
dispatch — argument validation, the right REST call, and formatting.
"""

import unittest
from unittest.mock import AsyncMock, patch

from praetor.tools import burp_settings as BS
from praetor.tools import burp_tools as BT
from praetor.tools import utility as U


def _fn(name):
    from praetor import server
    return server.mcp._tool_manager._tools[name].fn


class BurpSettingsOptionsTest(unittest.IsolatedAsyncioTestCase):

    async def test_options_get_routes_with_level(self):
        captured = {}

        async def fake_get(path, params=None):
            captured["path"] = path
            captured["params"] = params
            return {"level": "user", "json": "{...}"}

        with patch.object(BS, "client") as c:
            c.get = AsyncMock(side_effect=fake_get)
            out = await _fn("burp_settings")(action="options_get", level="user")
        self.assertEqual(captured["path"], "/api/burp-control/options")
        self.assertEqual(captured["params"], {"level": "user"})
        self.assertEqual(out["json"], "{...}")

    async def test_options_set_requires_json(self):
        out = await _fn("burp_settings")(action="options_set", level="project")
        self.assertIn("requires options_json", out["error"])

    async def test_options_bad_level_rejected(self):
        out = await _fn("burp_settings")(action="options_get", level="global")
        self.assertIn("project", out["error"])

    async def test_task_engine_set_validates_state(self):
        out = await _fn("burp_settings")(action="task_engine_set", state="halt")
        self.assertIn("RUNNING", out["error"])

    async def test_task_engine_set_posts_state(self):
        captured = {}

        async def fake_post(path, json=None):
            captured["path"] = path
            captured["json"] = json
            return {"state": "PAUSED"}

        with patch.object(BS, "client") as c:
            c.post = AsyncMock(side_effect=fake_post)
            out = await _fn("burp_settings")(action="task_engine_set", state="paused")
        self.assertEqual(captured["path"], "/api/burp-control/task-engine")
        self.assertEqual(captured["json"], {"state": "PAUSED"})
        self.assertEqual(out["state"], "PAUSED")

    async def test_active_editor_is_honest_manual(self):
        out = await _fn("burp_settings")(action="active_editor")
        self.assertFalse(out["montoya"])
        self.assertIn("no getter", out["manual"])


class OrganizerReadTest(unittest.IsolatedAsyncioTestCase):

    async def test_lists_items(self):
        rows = {"count": 1, "items": [
            {"id": 3, "status": "NONE", "method": "GET", "url": "https://t.io/a",
             "status_code": 200, "response_length": 512}]}
        with patch.object(BT, "client") as c:
            c.get = AsyncMock(return_value=rows)
            out = await _fn("get_organizer_items")()
        self.assertIn("#3", out)
        self.assertIn("https://t.io/a", out)
        self.assertIn("200", out)

    async def test_empty(self):
        with patch.object(BT, "client") as c:
            c.get = AsyncMock(return_value={"count": 0, "items": []})
            out = await _fn("get_organizer_items")()
        self.assertIn("empty", out)

    async def test_regex_passed_through(self):
        captured = {}

        async def fake_get(path, params=None):
            captured["params"] = params
            return {"count": 0, "items": []}

        with patch.object(BT, "client") as c:
            c.get = AsyncMock(side_effect=fake_get)
            await _fn("get_organizer_items")(regex="login")
        self.assertEqual(captured["params"], {"regex": "login"})


class RandomStringTest(unittest.IsolatedAsyncioTestCase):

    async def test_length_and_hex_charset(self):
        out = await _fn("generate_random_string")(length=20, charset="hex")
        self.assertEqual(len(out), 20)
        self.assertTrue(all(ch in "0123456789abcdef" for ch in out))

    async def test_bad_charset(self):
        out = await _fn("generate_random_string")(length=8, charset="klingon")
        self.assertIn("unknown charset", out)

    async def test_length_clamped(self):
        out = await _fn("generate_random_string")(length=99999)
        self.assertEqual(len(out), 4096)


if __name__ == "__main__":
    unittest.main()
