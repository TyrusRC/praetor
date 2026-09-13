"""Tests for the WebDriverAgent HTTP client + go-ios session management
(Task 5) and the IOSBackend UI methods that route through it. No real device
or WDA server -- http.client.HTTPConnection and the go-ios subprocesses are
mocked throughout."""
from __future__ import annotations

import json
import unittest
from unittest import mock

from praetor.tools.mobile import _wda, control
from praetor.tools.mobile._device import Device, DeviceError, IOSBackend


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco
    return _Stub(), captured


class FakeResponse:
    def __init__(self, status=200, body=b""):
        self.status = status
        self._body = body

    def read(self):
        return self._body


class FakeHTTPConnection:
    """Records every request() call; returns a canned FakeResponse."""
    instances: list["FakeHTTPConnection"] = []

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.requests: list[tuple] = []
        self.response = FakeResponse(200, b"{}")
        self.closed = False
        FakeHTTPConnection.instances.append(self)

    def request(self, method, path, body=None, headers=None):
        self.requests.append((method, path, body, headers))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


# --- WdaClient HTTP request building ------------------------------------

class WdaClientRequestTest(unittest.TestCase):
    def setUp(self):
        FakeHTTPConnection.instances.clear()
        self.patcher = mock.patch("http.client.HTTPConnection", FakeHTTPConnection)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_session_posts_capabilities_and_stores_session_id(self):
        conn = FakeHTTPConnection
        client = _wda.WdaClient(port=9100)
        # Pre-seed the response the (not-yet-created) connection will return.
        orig_init = conn.__init__

        def init_with_body(self, host, port, timeout=None):
            orig_init(self, host, port, timeout)
            self.response = FakeResponse(200, json.dumps({"sessionId": "sess-1"}).encode())
        with mock.patch.object(conn, "__init__", init_with_body):
            sid = client.session(bundle_id="com.example.app")
        self.assertEqual(sid, "sess-1")
        self.assertEqual(client.session_id, "sess-1")
        method, path, body, headers = FakeHTTPConnection.instances[0].requests[0]
        self.assertEqual(method, "POST")
        self.assertEqual(path, "/session")
        sent = json.loads(body)
        self.assertEqual(sent["capabilities"]["alwaysMatch"]["bundleId"], "com.example.app")
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_session_missing_id_raises(self):
        client = _wda.WdaClient(port=9100)
        FakeHTTPConnection.instances = []
        with mock.patch("http.client.HTTPConnection") as cls:
            inst = FakeHTTPConnection("127.0.0.1", 9100)
            inst.response = FakeResponse(200, b"{}")
            cls.return_value = inst
            with self.assertRaises(DeviceError):
                client.session()

    def test_tap_posts_coordinates_to_session_scoped_path(self):
        client = _wda.WdaClient(port=9100)
        client.session_id = "sess-1"
        with mock.patch("http.client.HTTPConnection") as cls:
            inst = FakeHTTPConnection("127.0.0.1", 9100)
            cls.return_value = inst
            client.tap(10, 20)
        method, path, body, _ = inst.requests[0]
        self.assertEqual(method, "POST")
        self.assertIn("/session/sess-1/wda/tap", path)
        self.assertEqual(json.loads(body), {"x": 10, "y": 20})

    def test_swipe_posts_from_to_duration(self):
        client = _wda.WdaClient(port=9100)
        client.session_id = "sess-1"
        with mock.patch("http.client.HTTPConnection") as cls:
            inst = FakeHTTPConnection("127.0.0.1", 9100)
            cls.return_value = inst
            client.swipe(1, 2, 3, 4, duration=0.5)
        _, path, body, _ = inst.requests[0]
        self.assertIn("dragfromtoforduration", path)
        sent = json.loads(body)
        self.assertEqual(sent, {"fromX": 1, "fromY": 2, "toX": 3, "toY": 4, "duration": 0.5})

    def test_type_text_sends_char_array(self):
        client = _wda.WdaClient(port=9100)
        client.session_id = "sess-1"
        with mock.patch("http.client.HTTPConnection") as cls:
            inst = FakeHTTPConnection("127.0.0.1", 9100)
            cls.return_value = inst
            client.type_text("hi")
        _, path, body, _ = inst.requests[0]
        self.assertIn("/wda/keys", path)
        self.assertEqual(json.loads(body), {"value": ["h", "i"]})

    def test_screenshot_decodes_base64_value(self):
        import base64
        client = _wda.WdaClient(port=9100)
        png_bytes = b"\x89PNGfake"
        with mock.patch("http.client.HTTPConnection") as cls:
            inst = FakeHTTPConnection("127.0.0.1", 9100)
            inst.response = FakeResponse(200, json.dumps(
                {"value": base64.b64encode(png_bytes).decode()}).encode())
            cls.return_value = inst
            data = client.screenshot()
        self.assertEqual(data, png_bytes)

    def test_open_url_posts_url(self):
        client = _wda.WdaClient(port=9100)
        client.session_id = "sess-1"
        with mock.patch("http.client.HTTPConnection") as cls:
            inst = FakeHTTPConnection("127.0.0.1", 9100)
            cls.return_value = inst
            client.open_url("https://example.com")
        _, path, body, _ = inst.requests[0]
        self.assertIn("/session/sess-1/url", path)
        self.assertEqual(json.loads(body), {"url": "https://example.com"})

    def test_home_posts_homescreen_no_session_needed(self):
        client = _wda.WdaClient(port=9100)
        with mock.patch("http.client.HTTPConnection") as cls:
            inst = FakeHTTPConnection("127.0.0.1", 9100)
            cls.return_value = inst
            client.home()
        method, path, _, _ = inst.requests[0]
        self.assertEqual(path, "/wda/homescreen")

    def test_actions_without_session_raise(self):
        client = _wda.WdaClient(port=9100)
        with self.assertRaises(DeviceError):
            client.tap(1, 1)

    def test_http_error_status_raises_device_error(self):
        client = _wda.WdaClient(port=9100)
        client.session_id = "sess-1"
        with mock.patch("http.client.HTTPConnection") as cls:
            inst = FakeHTTPConnection("127.0.0.1", 9100)
            inst.response = FakeResponse(500, b"boom")
            cls.return_value = inst
            with self.assertRaises(DeviceError):
                client.tap(1, 1)


# --- parse_wda_source ----------------------------------------------------

_WDA_TREE = json.dumps({
    "value": {
        "type": "Application",
        "label": "MyApp",
        "rect": {"x": 0, "y": 0, "width": 390, "height": 844},
        "enabled": True,
        "children": [
            {
                "type": "Button",
                "label": "Log in",
                "name": "loginBtn",
                "rect": {"x": 40, "y": 100, "width": 160, "height": 80},
                "enabled": True,
                "children": [],
            },
            {
                "type": "TextField",
                "value": "user@example.com",
                "name": "emailField",
                "rect": {"x": 40, "y": 200, "width": 300, "height": 44},
                "enabled": False,
                "children": [],
            },
        ],
    }
})


class ParseWdaSourceTest(unittest.TestCase):
    def test_flattens_tree_with_same_shape_as_control_parse_ui(self):
        els = _wda.parse_wda_source(_WDA_TREE)
        self.assertEqual(len(els), 3)  # root + 2 children
        for e in els:
            self.assertEqual(set(e.keys()),
                             {"index", "text", "resource_id", "class", "bounds", "center", "clickable"})

    def test_button_fields(self):
        els = _wda.parse_wda_source(_WDA_TREE)
        btn = next(e for e in els if e["text"] == "Log in")
        self.assertEqual(btn["resource_id"], "loginBtn")
        self.assertEqual(btn["class"], "Button")
        self.assertEqual(btn["bounds"], [40, 100, 200, 180])
        self.assertEqual(btn["center"], [120, 140])
        self.assertTrue(btn["clickable"])

    def test_disabled_field_not_clickable(self):
        els = _wda.parse_wda_source(_WDA_TREE)
        field = next(e for e in els if e["resource_id"] == "emailField")
        self.assertFalse(field["clickable"])
        self.assertEqual(field["text"], "user@example.com")

    def test_frame_key_also_supported(self):
        raw = json.dumps({"value": {"type": "Button", "label": "X",
                                    "frame": {"x": 1, "y": 2, "width": 10, "height": 20},
                                    "children": []}})
        els = _wda.parse_wda_source(raw)
        self.assertEqual(els[0]["bounds"], [1, 2, 11, 22])

    def test_invalid_json_returns_empty(self):
        self.assertEqual(_wda.parse_wda_source("not json"), [])

    def test_control_parse_ui_dispatches_to_wda_parser(self):
        els = control.parse_ui(_WDA_TREE, "ios")
        self.assertEqual(len(els), 3)


# --- Session lifecycle (mock go-ios subprocs) -----------------------------

class FakeProc:
    def __init__(self):
        self.pid = 4242
        self.killed = False

    def kill(self):
        self.killed = True


class EnsureSessionTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        _wda._WDA_SESSIONS.clear()
        self.dev = Device(id="UDID-1", platform="ios")

    async def test_no_ios_tool_raises(self):
        with mock.patch.object(_wda, "_check_tool", lambda n: False):
            with self.assertRaises(DeviceError):
                await _wda.ensure_session(self.dev)

    async def test_starts_runwda_and_forward_then_opens_session(self):
        spawned = []

        async def fake_spawn(cmd):
            spawned.append(cmd)
            return FakeProc()

        with mock.patch.object(_wda, "_check_tool", lambda n: True), \
             mock.patch.object(_wda, "_find_tool", lambda n: "ios"), \
             mock.patch.object(_wda, "_spawn", fake_spawn), \
             mock.patch.object(_wda.WdaClient, "session", return_value="sess-1"):
            client = await _wda.ensure_session(self.dev)
        self.assertEqual(client.session_id, None)  # session() mocked, never really set it
        self.assertIn("UDID-1", _wda._WDA_SESSIONS)
        self.assertEqual(spawned[0][:2], ["ios", "runwda"])
        self.assertEqual(spawned[1][:2], ["ios", "forward"])

    async def test_reuses_cached_session(self):
        cached_client = _wda.WdaClient(port=1234)
        _wda._WDA_SESSIONS["UDID-1"] = {"port": 1234, "client": cached_client,
                                        "runwda_proc": FakeProc(), "forward_proc": FakeProc()}
        with mock.patch.object(_wda, "_check_tool", lambda n: False):  # would raise if not cached
            client = await _wda.ensure_session(self.dev)
        self.assertIs(client, cached_client)

    async def test_wda_never_responds_raises_and_kills_procs(self):
        procs = []

        async def fake_spawn(cmd):
            p = FakeProc()
            procs.append(p)
            return p

        with mock.patch.object(_wda, "_check_tool", lambda n: True), \
             mock.patch.object(_wda, "_find_tool", lambda n: "ios"), \
             mock.patch.object(_wda, "_spawn", fake_spawn), \
             mock.patch.object(_wda, "_WDA_START_TIMEOUT", 0.01), \
             mock.patch.object(_wda, "_WDA_POLL_INTERVAL", 0.001), \
             mock.patch.object(_wda.WdaClient, "session",
                               side_effect=ConnectionRefusedError("refused")):
            with self.assertRaises(DeviceError):
                await _wda.ensure_session(self.dev)
        self.assertTrue(all(p.killed for p in procs))
        self.assertNotIn("UDID-1", _wda._WDA_SESSIONS)

    async def test_stop_session_kills_procs_and_drops_entry(self):
        p1, p2 = FakeProc(), FakeProc()
        _wda._WDA_SESSIONS["UDID-1"] = {"port": 1234, "client": _wda.WdaClient(),
                                        "runwda_proc": p1, "forward_proc": p2}
        stopped = await _wda.stop_session("UDID-1")
        self.assertTrue(stopped)
        self.assertTrue(p1.killed)
        self.assertTrue(p2.killed)
        self.assertNotIn("UDID-1", _wda._WDA_SESSIONS)

    async def test_stop_session_no_entry_returns_false(self):
        self.assertFalse(await _wda.stop_session("nope"))


# --- IOSBackend UI dispatch -----------------------------------------------

class IosBackendUiDispatchTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        _wda._WDA_SESSIONS.clear()
        self.dev = Device(id="UDID-1", platform="ios")
        self.backend = IOSBackend()

    async def test_ui_dump_raw_routes_to_wda_source(self):
        fake_client = mock.Mock()
        fake_client.source.return_value = _WDA_TREE
        with mock.patch("praetor.tools.mobile._wda.ensure_session", return_value=fake_client):
            out = await self.backend.ui_dump_raw(self.dev)
        self.assertEqual(out, _WDA_TREE)
        fake_client.source.assert_called_once()

    async def test_tap_routes_to_wda_tap(self):
        fake_client = mock.Mock()
        with mock.patch("praetor.tools.mobile._wda.ensure_session", return_value=fake_client):
            await self.backend.tap(self.dev, 5, 6)
        fake_client.tap.assert_called_once_with(5, 6)

    async def test_swipe_converts_ms_to_seconds(self):
        fake_client = mock.Mock()
        with mock.patch("praetor.tools.mobile._wda.ensure_session", return_value=fake_client):
            await self.backend.swipe(self.dev, 1, 2, 3, 4, 500)
        fake_client.swipe.assert_called_once_with(1, 2, 3, 4, 0.5)

    async def test_input_text_routes_to_wda(self):
        fake_client = mock.Mock()
        with mock.patch("praetor.tools.mobile._wda.ensure_session", return_value=fake_client):
            await self.backend.input_text(self.dev, "hello")
        fake_client.type_text.assert_called_once_with("hello")

    async def test_key_home_routes_to_wda_home(self):
        fake_client = mock.Mock()
        with mock.patch("praetor.tools.mobile._wda.ensure_session", return_value=fake_client):
            await self.backend.key(self.dev, "home")
        fake_client.home.assert_called_once()

    async def test_key_unmapped_raises_without_touching_wda(self):
        with mock.patch("praetor.tools.mobile._wda.ensure_session") as ensure:
            with self.assertRaises(DeviceError):
                await self.backend.key(self.dev, "VOLUME_UP")
        ensure.assert_not_called()

    async def test_ui_dump_raw_no_go_ios_raises_device_error(self):
        # ensure_session() itself raises when go-ios is absent. FINDING 5: mock
        # the tool-presence check directly rather than relying on the ambient
        # environment lacking it -- on a box WITH go-ios installed, an unmocked
        # check would let ensure_session spawn real runwda/forward and block ~15s.
        with mock.patch.object(_wda, "_check_tool", lambda n: False):
            with self.assertRaises(DeviceError):
                await self.backend.ui_dump_raw(self.dev)


# --- mobile_wda_start / mobile_wda_stop tools ------------------------------

class WdaToolsTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        _wda._WDA_SESSIONS.clear()
        self.stub, self.cap = _stub_mcp()
        control.register(self.stub)
        self.dev = Device(id="UDID-1", platform="ios", authorized=True)

    async def test_start_success(self):
        fake_client = mock.Mock()
        fake_client.session_id = "sess-1"

        async def fake_ensure(dev):
            _wda._WDA_SESSIONS[dev.id] = {"port": 9100, "client": fake_client,
                                          "runwda_proc": FakeProc(), "forward_proc": FakeProc()}
            return fake_client

        with mock.patch.object(control, "resolve_device", return_value=self.dev), \
             mock.patch.object(_wda, "ensure_session", fake_ensure), \
             mock.patch.object(control, "log_action", return_value="op1"):
            out = await self.cap["mobile_wda_start"](domain="ex.com")
        self.assertTrue(out["started"])
        self.assertEqual(out["port"], 9100)
        self.assertEqual(out["session_id"], "sess-1")

    async def test_start_propagates_device_error(self):
        with mock.patch.object(control, "resolve_device",
                               side_effect=DeviceError("go-ios not installed")):
            out = await self.cap["mobile_wda_start"](domain="ex.com")
        self.assertIn("error", out)

    async def test_stop_kills_and_reports(self):
        with mock.patch.object(control, "resolve_device", return_value=self.dev), \
             mock.patch.object(_wda, "stop_session", return_value=True) as stop, \
             mock.patch.object(control, "log_action", return_value="op1"):
            out = await self.cap["mobile_wda_stop"](domain="ex.com")
        self.assertTrue(out["stopped"])
        stop.assert_called_once_with("UDID-1")

    async def test_stop_no_session_reports_false(self):
        with mock.patch.object(control, "resolve_device", return_value=self.dev), \
             mock.patch.object(_wda, "stop_session", return_value=False), \
             mock.patch.object(control, "log_action", return_value="op1"):
            out = await self.cap["mobile_wda_stop"](domain="ex.com")
        self.assertFalse(out["stopped"])


if __name__ == "__main__":
    unittest.main()
