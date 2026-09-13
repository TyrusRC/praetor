# tests/test_mobile_setting.py
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


class MobileSettingTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.stub, self.cap = _stub_mcp()
        control.register(self.stub)
        self.android = _device.Device(id="ABC123", platform="android", authorized=True)
        self.ios = _device.Device(id="UDID1", platform="ios", authorized=True)

    async def test_get_calls_backend_and_returns_value(self):
        with mock.patch.object(control, "resolve_device", return_value=self.android), \
             mock.patch.object(_device.AndroidBackend, "setting_get",
                               return_value="120") as sg, \
             mock.patch.object(control, "log_action", return_value="op1"):
            out = await self.cap["mobile_setting"](
                action="get", namespace="system", key="screen_brightness", domain="ex.com")
        sg.assert_awaited_once_with(self.android, "system", "screen_brightness")
        self.assertEqual(out["value"], "120")
        self.assertEqual(out["oplog_id"], "op1")

    async def test_put_benign_writes_and_oplogs(self):
        with mock.patch.object(control, "resolve_device", return_value=self.android), \
             mock.patch.object(_device.AndroidBackend, "setting_put",
                               return_value=None) as sp, \
             mock.patch.object(control, "log_action", return_value="op2"):
            out = await self.cap["mobile_setting"](
                action="put", namespace="system", key="screen_brightness",
                value="120", domain="ex.com")
        sp.assert_awaited_once_with(self.android, "system", "screen_brightness", "120")
        self.assertTrue(out["written"])
        self.assertEqual(out["oplog_id"], "op2")

    async def test_put_destructive_refused_before_device_write(self):
        with mock.patch.object(control, "resolve_device", return_value=self.android), \
             mock.patch.object(_device.AndroidBackend, "setting_put",
                               return_value=None) as sp:
            out = await self.cap["mobile_setting"](
                action="put", namespace="secure", key="lockscreen.disabled",
                value="1", domain="ex.com")
        self.assertIn("error", out)
        sp.assert_not_awaited()

    async def test_ios_get_not_cli_writable(self):
        with mock.patch.object(control, "resolve_device", return_value=self.ios):
            out = await self.cap["mobile_setting"](
                action="get", namespace="system", key="foo", domain="ex.com")
        self.assertIn("error", out)

    async def test_ios_put_not_cli_writable(self):
        with mock.patch.object(control, "resolve_device", return_value=self.ios):
            out = await self.cap["mobile_setting"](
                action="put", namespace="system", key="foo", value="1", domain="ex.com")
        self.assertIn("error", out)

    async def test_bad_namespace(self):
        out = await self.cap["mobile_setting"](
            action="get", namespace="bogus", key="foo", domain="ex.com")
        self.assertIn("error", out)

    async def test_bad_action(self):
        out = await self.cap["mobile_setting"](
            action="delete", namespace="system", key="foo", domain="ex.com")
        self.assertIn("error", out)


if __name__ == "__main__":
    unittest.main()
