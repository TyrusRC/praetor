"""mobile_locate (label/tree) + mobile_run_flow (scripted verified UI journey)."""

import asyncio
import unittest

from praetor.tools.mobile import flow as F


class _FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self, *a, **k):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


class _Dev:
    id = "emulator-5554"
    platform = "android"


class _Backend:
    def __init__(self):
        self.calls = []

    async def ui_dump_raw(self, dev):
        return "<xml/>"

    async def tap(self, dev, x, y):
        self.calls.append(("tap", x, y))

    async def input_text(self, dev, text):
        self.calls.append(("input", text))

    async def swipe(self, dev, x1, y1, x2, y2, d):
        self.calls.append(("swipe", x1, y1, x2, y2))

    async def key(self, dev, key):
        self.calls.append(("key", key))

    async def deeplink(self, dev, uri, package):
        self.calls.append(("deeplink", uri))

    async def screenshot(self, dev, out):
        self.calls.append(("screenshot", str(out)))


class MobileFlowTest(unittest.TestCase):
    def setUp(self):
        self.mcp = _FakeMCP()
        F.register(self.mcp)
        self.be = _Backend()
        self.dev = _Dev()
        self._orig = (F.resolve_device, F.backend_for, F.parse_ui, F.log_action, F.artifact_dir)
        # the on-screen tree: a Login button + a Welcome label
        self._tree = [
            {"index": 0, "text": "Log in", "resource_id": "btn_login", "class": "Button",
             "center": [100, 200], "clickable": True},
            {"index": 1, "text": "Welcome back", "resource_id": "", "class": "TextView",
             "center": [50, 50], "clickable": False},
        ]
        F.resolve_device = self._resolve
        F.backend_for = lambda dev: self.be
        F.parse_ui = lambda raw, platform: self._tree
        F.log_action = lambda *a, **k: "op-1"
        F.artifact_dir = lambda domain: __import__("pathlib").Path("/tmp")

    def tearDown(self):
        F.resolve_device, F.backend_for, F.parse_ui, F.log_action, F.artifact_dir = self._orig

    async def _resolve(self, device, **kw):
        return self.dev

    def _call(self, name, **kw):
        return asyncio.run(self.mcp.tools[name](**kw))

    def test_locate_by_label_tree(self):
        out = self._call("mobile_locate", text="login", tap=True)
        self.assertTrue(out["found"])
        self.assertEqual(out["method"], "tree")
        self.assertEqual(out["center"], [100, 200])
        self.assertIn(("tap", 100, 200), self.be.calls)

    def test_flow_happy_path(self):
        steps = [
            {"action": "tap", "text": "Log in"},
            {"action": "input", "text": "wiener"},
            {"action": "key", "key": "KEYCODE_ENTER"},
            {"action": "assert_text", "text": "Welcome"},
        ]
        out = self._call("mobile_run_flow", steps=steps)
        self.assertTrue(out["ok"])
        self.assertEqual(out["steps_run"], 4)
        self.assertTrue(all(s["ok"] for s in out["trace"]))
        self.assertIn(("input", "wiener"), self.be.calls)

    def test_flow_assert_fail_stops(self):
        steps = [
            {"action": "tap", "x": 10, "y": 20},
            {"action": "assert_text", "text": "NoSuchText"},
            {"action": "input", "text": "never reached"},
        ]
        out = self._call("mobile_run_flow", steps=steps)
        self.assertFalse(out["ok"])
        self.assertEqual(out["steps_run"], 2)            # stopped at the failed assert
        self.assertFalse(out["trace"][1]["ok"])
        self.assertNotIn(("input", "never reached"), self.be.calls)

    def test_flow_unknown_action(self):
        out = self._call("mobile_run_flow", steps=[{"action": "teleport"}])
        self.assertFalse(out["ok"])
        self.assertIn("unknown action", out["trace"][0]["error"])

    def test_flow_rejects_empty(self):
        out = self._call("mobile_run_flow", steps=[])
        self.assertIn("non-empty list", out["error"])


if __name__ == "__main__":
    unittest.main()
