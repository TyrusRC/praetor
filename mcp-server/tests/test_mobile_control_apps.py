# tests/test_mobile_control_apps.py
from __future__ import annotations

import unittest
from unittest import mock

from praetor.tools.mobile import control, _device


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco
    return _Stub(), captured


class AppToolTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.stub, self.cap = _stub_mcp()
        control.register(self.stub)
        self.dev = _device.Device(id="ABC123", platform="android", authorized=True)

    async def test_devices_lists(self):
        with mock.patch.object(control, "list_devices",
                               return_value=[self.dev]):
            out = await self.cap["mobile_devices"]()
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["devices"][0]["id"], "ABC123")

    async def test_app_list_parses(self):
        with mock.patch.object(control, "resolve_device", return_value=self.dev), \
             mock.patch.object(_device.AndroidBackend, "app_list",
                               return_value=["com.x.app", "com.y.app"]), \
             mock.patch.object(control, "log_action", return_value="op1"):
            out = await self.cap["mobile_app_list"](domain="ex.com")
        self.assertIn("com.x.app", out["packages"])

    async def test_app_control_clear_nontarget_refused(self):
        # pm clear of a package is destructive per guards
        with mock.patch.object(control, "resolve_device", return_value=self.dev):
            out = await self.cap["mobile_app_control"](action="clear", package="com.other",
                                                       domain="ex.com")
        self.assertIn("error", out)

    async def test_app_control_start_ok(self):
        with mock.patch.object(control, "resolve_device", return_value=self.dev), \
             mock.patch.object(_device.AndroidBackend, "app_control", return_value="started"), \
             mock.patch.object(control, "log_action", return_value="op1"):
            out = await self.cap["mobile_app_control"](action="start", package="com.x.app",
                                                       domain="ex.com")
        self.assertNotIn("error", out)

    async def test_deeplink_ok(self):
        with mock.patch.object(control, "resolve_device", return_value=self.dev), \
             mock.patch.object(_device.AndroidBackend, "deeplink", return_value="ok"), \
             mock.patch.object(control, "log_action", return_value="op1"):
            out = await self.cap["mobile_deeplink"](uri="myapp://oauth/cb?code=x",
                                                    domain="ex.com")
        self.assertNotIn("error", out)


if __name__ == "__main__":
    unittest.main()
