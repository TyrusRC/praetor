from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from praetor.tools.mobile import frida as mfrida, _device


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco
    return _Stub(), captured


class FakeProc:
    def __init__(self, lines):
        self.pid = 4242
        self._lines = [l.encode() for l in lines]
        self.stdout = self
        self.returncode = None

    async def readline(self):
        return self._lines.pop(0) if self._lines else b""

    def kill(self):
        self.returncode = -9


class FridaRunTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.stub, self.cap = _stub_mcp()
        mfrida.register(self.stub)
        self.dev = _device.Device(id="ABC123", platform="android", authorized=True)

    async def test_unknown_script_errors(self):
        with mock.patch.object(mfrida, "resolve_device", return_value=self.dev):
            out = await self.cap["mobile_frida_run"](script="nope", package="com.x", domain="ex.com")
        self.assertIn("error", out)

    async def test_run_launches_and_captures(self):
        fake = FakeProc(["[*] pinning bypassed\n", "hooked okhttp\n"])
        with mock.patch.object(mfrida, "resolve_device", return_value=self.dev), \
             mock.patch.object(mfrida, "_snippet_path", return_value="/tmp/ssl.js"), \
             mock.patch.object(mfrida, "_check_tool", lambda n: True), \
             mock.patch("asyncio.create_subprocess_exec", return_value=fake), \
             mock.patch.object(mfrida, "log_action", return_value="op1"):
            out = await self.cap["mobile_frida_run"](script="ssl_pin_universal_android",
                                                     package="com.x", capture_secs=0, domain="ex.com")
        self.assertTrue(out["running"])
        self.assertIn("pinning bypassed", out["console_head"])
        self.assertIn(out["session_id"], mfrida._SESSIONS)

    async def test_stop_kills_session(self):
        fake = FakeProc([])
        mfrida._SESSIONS["s1"] = fake
        with mock.patch.object(mfrida, "log_action", return_value="op1"):
            out = await self.cap["mobile_frida_stop"](session_id="s1", domain="ex.com")
        self.assertTrue(out["stopped"])
        self.assertNotIn("s1", mfrida._SESSIONS)


if __name__ == "__main__":
    unittest.main()
