# tests/test_mobile_control_ui.py
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


_UIXML = (
    '<?xml version="1.0"?>'
    '<hierarchy>'
    '<node index="0" text="" resource-id="" class="android.widget.FrameLayout" '
    'bounds="[0,0][1080,2400]" clickable="false">'
    '<node index="0" text="Log in" resource-id="com.x:id/login" '
    'class="android.widget.Button" bounds="[40,100][200,180]" clickable="true"/>'
    '</node></hierarchy>'
)


class ParseUiTest(unittest.TestCase):
    def test_android_parse(self):
        els = control.parse_ui(_UIXML, "android")
        btn = next(e for e in els if e["text"] == "Log in")
        self.assertEqual(btn["resource_id"], "com.x:id/login")
        self.assertTrue(btn["clickable"])
        self.assertEqual(btn["bounds"], [40, 100, 200, 180])
        self.assertEqual(btn["center"], [120, 140])


class ControlToolTest(unittest.IsolatedAsyncioTestCase):
    async def _dev(self):
        return _device.Device(id="ABC123", platform="android", authorized=True)

    async def test_tap_by_coord_logs_action(self):
        stub, cap = _stub_mcp()
        control.register(stub)
        dev = await self._dev()
        with mock.patch.object(control, "resolve_device", return_value=dev), \
             mock.patch.object(_device.AndroidBackend, "tap", return_value=None) as tap, \
             mock.patch.object(control, "log_action", return_value="op1") as la:
            out = await cap["mobile_tap"](x=100, y=200, domain="ex.com")
        self.assertNotIn("error", out)
        self.assertEqual(out["oplog_id"], "op1")
        tap.assert_awaited_once()
        la.assert_called_once()

    async def test_tap_by_element_index(self):
        stub, cap = _stub_mcp()
        control.register(stub)
        dev = await self._dev()
        with mock.patch.object(control, "resolve_device", return_value=dev), \
             mock.patch.object(_device.AndroidBackend, "ui_dump_raw", return_value=_UIXML), \
             mock.patch.object(_device.AndroidBackend, "tap", return_value=None) as tap, \
             mock.patch.object(control, "log_action", return_value="op1"):
            out = await cap["mobile_tap"](element_index=1, domain="ex.com")
        self.assertNotIn("error", out)
        # element 1 is the button; center [120,140]
        tap.assert_awaited_once()
        args = tap.await_args.args
        self.assertEqual(args[-2:], (120, 140))

    async def test_unknown_device_returns_error(self):
        stub, cap = _stub_mcp()
        control.register(stub)
        with mock.patch.object(control, "resolve_device",
                               side_effect=_device.DeviceError("no device")):
            out = await cap["mobile_tap"](x=1, y=1, domain="ex.com")
        self.assertIn("error", out)

    async def test_ui_dump_returns_elements(self):
        stub, cap = _stub_mcp()
        control.register(stub)
        dev = await self._dev()
        with mock.patch.object(control, "resolve_device", return_value=dev), \
             mock.patch.object(_device.AndroidBackend, "ui_dump_raw", return_value=_UIXML), \
             mock.patch.object(control, "log_action", return_value="op1"):
            out = await cap["mobile_ui_dump"](domain="ex.com")
        self.assertGreaterEqual(len(out["elements"]), 1)


if __name__ == "__main__":
    unittest.main()
