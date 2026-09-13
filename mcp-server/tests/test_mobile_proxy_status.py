from __future__ import annotations
import unittest
from unittest import mock
from praetor.tools.mobile import proxy, _device

def _stub_mcp():
    captured = {}
    class _S:
        def tool(self,*a,**k):
            def d(f): captured[f.__name__]=f; return f
            return d
    return _S(), captured

class ProxyStatusConfigTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.stub, self.cap = _stub_mcp()
        proxy.register(self.stub)
        self.dev = _device.Device(id="ABC123", platform="android", authorized=True)

    async def test_routing_ok_when_device_proxy_matches_reachable_burp(self):
        with mock.patch.object(proxy, "resolve_device", return_value=self.dev), \
             mock.patch.object(_device.AndroidBackend, "get_proxy", return_value="192.168.1.163:8080"), \
             mock.patch.object(proxy, "host_lan_ip", return_value="192.168.1.163"), \
             mock.patch.object(proxy, "burp_listener_scope", return_value={"listening": True, "loopback_only": False, "addrs": ["0.0.0.0:8080"]}), \
             mock.patch.object(proxy, "log_action", return_value="op1"):
            out = await self.cap["mobile_proxy_status"](domain="ex.com")
        self.assertIs(out["routing_ok"], True)
        self.assertEqual(out["warnings"], [])
        self.assertTrue(out["ca_note"])

    async def test_warn_when_proxy_unset(self):
        with mock.patch.object(proxy, "resolve_device", return_value=self.dev), \
             mock.patch.object(_device.AndroidBackend, "get_proxy", return_value=""), \
             mock.patch.object(proxy, "host_lan_ip", return_value="192.168.1.163"), \
             mock.patch.object(proxy, "burp_listener_scope", return_value={"listening": True, "loopback_only": False, "addrs": ["0.0.0.0:8080"]}), \
             mock.patch.object(proxy, "log_action", return_value="op1"):
            out = await self.cap["mobile_proxy_status"](domain="ex.com")
        self.assertFalse(out["routing_ok"])
        self.assertTrue(any("not set" in w or "unset" in w for w in out["warnings"]))

    async def test_warn_when_burp_loopback_only(self):
        with mock.patch.object(proxy, "resolve_device", return_value=self.dev), \
             mock.patch.object(_device.AndroidBackend, "get_proxy", return_value="192.168.1.163:8080"), \
             mock.patch.object(proxy, "host_lan_ip", return_value="192.168.1.163"), \
             mock.patch.object(proxy, "burp_listener_scope", return_value={"listening": True, "loopback_only": True, "addrs": ["127.0.0.1:8080"]}), \
             mock.patch.object(proxy, "log_action", return_value="op1"):
            out = await self.cap["mobile_proxy_status"](domain="ex.com")
        self.assertFalse(out["routing_ok"])
        self.assertTrue(any("loopback" in w.lower() for w in out["warnings"]))

    def test_burp_listener_scope_parses_ss(self):
        sample = 'LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:*\nLISTEN 0 4096 0.0.0.0:8080 0.0.0.0:*\n'
        with mock.patch.object(proxy, "_run_text", return_value=sample):
            sc = proxy.burp_listener_scope()
        self.assertTrue(sc["listening"])
        self.assertFalse(sc["loopback_only"])  # 0.0.0.0 present

class ProxyStatusIosTest(unittest.IsolatedAsyncioTestCase):
    async def test_ios_device_proxy_unreadable_does_not_crash(self):
        """FINDING 1 regression: get_proxy() on iOS used to raise a bare
        AttributeError (no override on IOSBackend) outside the except DeviceError
        guard, crashing the tool. The _Backend base fallback now raises
        DeviceError, so this must return a clean dict + warning instead."""
        stub, cap = _stub_mcp(); proxy.register(stub)
        dev = _device.Device(id="UDID-1", platform="ios", authorized=True)
        with mock.patch.object(proxy, "resolve_device", return_value=dev), \
             mock.patch.object(proxy, "host_lan_ip", return_value="192.168.1.163"), \
             mock.patch.object(proxy, "burp_listener_scope", return_value={"listening": True, "loopback_only": False, "addrs": ["0.0.0.0:8080"]}), \
             mock.patch.object(proxy, "log_action", return_value="op1"):
            out = await cap["mobile_proxy_status"](domain="ex.com")
        self.assertIsInstance(out, dict)
        self.assertNotIn("error", out)
        self.assertEqual(out["device_proxy"], "")
        self.assertTrue(any("ios" in w.lower() for w in out["warnings"]))


class ProxyStatusIosCanaryTest(unittest.IsolatedAsyncioTestCase):
    async def test_ios_canary_no_wda_does_not_crash(self):
        """Task 1 regression: IOSBackend had no open_url override, so
        _run_canary's backend_for(dev).open_url(dev, url) raised a bare
        AttributeError (not caught by `except DeviceError`), crashing
        mobile_proxy_status(canary=True) for iOS devices. IOSBackend.open_url
        now drives WDA and degrades to DeviceError when go-ios/WDA is absent,
        which _run_canary already catches cleanly."""
        stub, cap = _stub_mcp(); proxy.register(stub)
        dev = _device.Device(id="UDID-1", platform="ios", authorized=True)
        with mock.patch.object(proxy, "resolve_device", return_value=dev), \
             mock.patch.object(proxy, "host_lan_ip", return_value="192.168.1.163"), \
             mock.patch.object(proxy, "burp_listener_scope", return_value={"listening": True, "loopback_only": False, "addrs": ["0.0.0.0:8080"]}), \
             mock.patch.object(_device, "_wda_ensure",
                               side_effect=_device.DeviceError("go-ios (`ios`) not installed")), \
             mock.patch.object(proxy, "log_action", return_value="op1"):
            out = await cap["mobile_proxy_status"](domain="ex.com", canary=True)
        self.assertIsInstance(out, dict)
        self.assertNotIn("error", out)
        self.assertIs(out["canary_landed"], False)
        self.assertIn("warnings", out)
        self.assertTrue(any("canary" in w.lower() for w in out["warnings"]))


class ProxyStatusCanaryTest(unittest.IsolatedAsyncioTestCase):
    async def test_canary_landed(self):
        stub, cap = _stub_mcp(); proxy.register(stub)
        dev = _device.Device(id="ABC123", platform="android", authorized=True)
        with mock.patch.object(proxy, "resolve_device", return_value=dev), \
             mock.patch.object(_device.AndroidBackend, "get_proxy", return_value="192.168.1.163:8080"), \
             mock.patch.object(proxy, "host_lan_ip", return_value="192.168.1.163"), \
             mock.patch.object(proxy, "burp_listener_scope", return_value={"listening": True, "loopback_only": False, "addrs": ["0.0.0.0:8080"]}), \
             mock.patch.object(_device.AndroidBackend, "open_url", return_value=None), \
             mock.patch.object(proxy, "_poll_history_for", return_value=4242), \
             mock.patch.object(proxy, "log_action", return_value="op1"):
            out = await cap["mobile_proxy_status"](domain="ex.com", canary=True)
        self.assertTrue(out["canary_landed"])
        self.assertEqual(out["logger_index"], 4242)

    async def test_canary_lost(self):
        stub, cap = _stub_mcp(); proxy.register(stub)
        dev = _device.Device(id="ABC123", platform="android", authorized=True)
        with mock.patch.object(proxy, "resolve_device", return_value=dev), \
             mock.patch.object(_device.AndroidBackend, "get_proxy", return_value="192.168.1.163:8080"), \
             mock.patch.object(proxy, "host_lan_ip", return_value="192.168.1.163"), \
             mock.patch.object(proxy, "burp_listener_scope", return_value={"listening": True, "loopback_only": False, "addrs": ["0.0.0.0:8080"]}), \
             mock.patch.object(_device.AndroidBackend, "open_url", return_value=None), \
             mock.patch.object(proxy, "_poll_history_for", return_value=None), \
             mock.patch.object(proxy, "log_action", return_value="op1"):
            out = await cap["mobile_proxy_status"](domain="ex.com", canary=True)
        self.assertFalse(out["canary_landed"])
        self.assertTrue(any("canary" in w.lower() for w in out["warnings"]))


class SetProxyTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.stub, self.cap = _stub_mcp()
        proxy.register(self.stub)
        self.dev = _device.Device(id="ABC123", platform="android", authorized=True)

    async def test_reverse_mode_reverses_port_then_sets_loopback_proxy(self):
        with mock.patch.object(proxy, "resolve_device", return_value=self.dev), \
             mock.patch.object(_device.AndroidBackend, "reverse_port", return_value=None) as m_rev, \
             mock.patch.object(_device.AndroidBackend, "set_proxy", return_value=None) as m_set, \
             mock.patch.object(proxy, "log_action", return_value="op1"):
            out = await self.cap["mobile_set_proxy"](domain="ex.com", mode="reverse")
        m_rev.assert_awaited_once_with(self.dev, proxy.BURP_PROXY_PORT)
        m_set.assert_awaited_once_with(self.dev, f"127.0.0.1:{proxy.BURP_PROXY_PORT}")
        self.assertEqual(out["applied"], "reverse")
        self.assertEqual(out["device_proxy"], f"127.0.0.1:{proxy.BURP_PROXY_PORT}")
        self.assertEqual(out["oplog_id"], "op1")

    async def test_lan_mode_uses_host_lan_ip(self):
        with mock.patch.object(proxy, "resolve_device", return_value=self.dev), \
             mock.patch.object(proxy, "host_lan_ip", return_value="192.168.1.50"), \
             mock.patch.object(_device.AndroidBackend, "set_proxy", return_value=None) as m_set, \
             mock.patch.object(proxy, "log_action", return_value="op1"):
            out = await self.cap["mobile_set_proxy"](domain="ex.com", mode="lan")
        m_set.assert_awaited_once_with(self.dev, f"192.168.1.50:{proxy.BURP_PROXY_PORT}")
        self.assertEqual(out["device_proxy"], f"192.168.1.50:{proxy.BURP_PROXY_PORT}")

    async def test_lan_mode_errors_when_no_lan_ip(self):
        with mock.patch.object(proxy, "resolve_device", return_value=self.dev), \
             mock.patch.object(proxy, "host_lan_ip", return_value=""):
            out = await self.cap["mobile_set_proxy"](domain="ex.com", mode="lan")
        self.assertIn("error", out)

    async def test_tailscale_mode_uses_host_tailscale_ip(self):
        with mock.patch.object(proxy, "resolve_device", return_value=self.dev), \
             mock.patch.object(proxy, "host_tailscale_ip", return_value="100.64.1.2"), \
             mock.patch.object(_device.AndroidBackend, "set_proxy", return_value=None) as m_set, \
             mock.patch.object(proxy, "log_action", return_value="op1"):
            out = await self.cap["mobile_set_proxy"](domain="ex.com", mode="tailscale")
        m_set.assert_awaited_once_with(self.dev, f"100.64.1.2:{proxy.BURP_PROXY_PORT}")
        self.assertEqual(out["device_proxy"], f"100.64.1.2:{proxy.BURP_PROXY_PORT}")

    async def test_tailscale_mode_errors_when_no_tailnet_ip(self):
        with mock.patch.object(proxy, "resolve_device", return_value=self.dev), \
             mock.patch.object(proxy, "host_tailscale_ip", return_value=""):
            out = await self.cap["mobile_set_proxy"](domain="ex.com", mode="tailscale")
        self.assertIn("error", out)

    async def test_off_mode_clears_proxy(self):
        with mock.patch.object(proxy, "resolve_device", return_value=self.dev), \
             mock.patch.object(_device.AndroidBackend, "clear_proxy", return_value=None) as m_clear, \
             mock.patch.object(proxy, "log_action", return_value="op1"):
            out = await self.cap["mobile_set_proxy"](domain="ex.com", mode="off")
        m_clear.assert_awaited_once_with(self.dev)
        self.assertEqual(out["applied"], "off")
        self.assertEqual(out["device_proxy"], "")

    async def test_ios_device_returns_error_no_adb_reverse(self):
        ios_dev = _device.Device(id="UDID1", platform="ios", authorized=True)
        with mock.patch.object(proxy, "resolve_device", return_value=ios_dev), \
             mock.patch.object(_device.AndroidBackend, "reverse_port", return_value=None) as m_rev:
            out = await self.cap["mobile_set_proxy"](domain="ex.com", mode="reverse")
        m_rev.assert_not_awaited()
        self.assertIn("error", out)

    async def test_unknown_mode_returns_error(self):
        with mock.patch.object(proxy, "resolve_device", return_value=self.dev):
            out = await self.cap["mobile_set_proxy"](domain="ex.com", mode="bogus")
        self.assertIn("error", out)


class ProxyStatusDriftTest(unittest.IsolatedAsyncioTestCase):
    async def test_drift_warning_when_device_proxy_ip_stale(self):
        stub, cap = _stub_mcp(); proxy.register(stub)
        dev = _device.Device(id="ABC123", platform="android", authorized=True)
        with mock.patch.object(proxy, "resolve_device", return_value=dev), \
             mock.patch.object(_device.AndroidBackend, "get_proxy", return_value="192.168.1.163:8080"), \
             mock.patch.object(proxy, "host_lan_ip", return_value="192.168.1.200"), \
             mock.patch.object(proxy, "host_tailscale_ip", return_value=""), \
             mock.patch.object(proxy, "burp_listener_scope", return_value={"listening": True, "loopback_only": False, "addrs": ["0.0.0.0:8080"]}), \
             mock.patch.object(proxy, "log_action", return_value="op1"):
            out = await cap["mobile_proxy_status"](domain="ex.com")
        self.assertTrue(any("mobile_set_proxy" in w for w in out["warnings"]))
        drift_warnings = [w for w in out["warnings"] if "drift" in w.lower() or "stale" in w.lower()]
        self.assertEqual(len(drift_warnings), 1)  # FINDING 2: collapsed, not a double warning
        self.assertFalse(out["routing_ok"])

    async def test_routing_ok_when_device_proxy_is_tailscale_ip(self):
        """FINDING 2: mode='tailscale' points the device at the tailnet IP, which
        differs from host_lan_ip() — that must NOT trip the mismatch/drift warning,
        and routing_ok must be reachable for this recommended wireless mode."""
        stub, cap = _stub_mcp(); proxy.register(stub)
        dev = _device.Device(id="ABC123", platform="android", authorized=True)
        with mock.patch.object(proxy, "resolve_device", return_value=dev), \
             mock.patch.object(_device.AndroidBackend, "get_proxy", return_value="100.64.1.2:8080"), \
             mock.patch.object(proxy, "host_lan_ip", return_value="192.168.1.163"), \
             mock.patch.object(proxy, "host_tailscale_ip", return_value="100.64.1.2"), \
             mock.patch.object(proxy, "burp_listener_scope", return_value={"listening": True, "loopback_only": False, "addrs": ["0.0.0.0:8080"]}), \
             mock.patch.object(proxy, "log_action", return_value="op1"):
            out = await cap["mobile_proxy_status"](domain="ex.com")
        self.assertIs(out["routing_ok"], True)
        self.assertEqual(out["warnings"], [])

    async def test_no_drift_warning_when_device_proxy_is_loopback(self):
        stub, cap = _stub_mcp(); proxy.register(stub)
        dev = _device.Device(id="ABC123", platform="android", authorized=True)
        with mock.patch.object(proxy, "resolve_device", return_value=dev), \
             mock.patch.object(_device.AndroidBackend, "get_proxy", return_value="127.0.0.1:8080"), \
             mock.patch.object(proxy, "host_lan_ip", return_value="192.168.1.200"), \
             mock.patch.object(proxy, "burp_listener_scope", return_value={"listening": True, "loopback_only": False, "addrs": ["0.0.0.0:8080"]}), \
             mock.patch.object(proxy, "log_action", return_value="op1"):
            out = await cap["mobile_proxy_status"](domain="ex.com")
        self.assertFalse(any("mobile_set_proxy" in w for w in out["warnings"]))
        self.assertIs(out["routing_ok"], True)
        self.assertEqual(out["warnings"], [])

    async def test_adb_reverse_loopback_proxy_with_loopback_listener_is_routing_ok(self):
        """FACET 1+2: reverse mode's device_proxy=127.0.0.1:<port> + a loopback-only
        Burp listener is the CORRECT adb-reverse config — no mismatch warning, no
        loopback-listener warning, routing_ok True, even though the host LAN IP
        differs (irrelevant to a reverse tunnel)."""
        stub, cap = _stub_mcp(); proxy.register(stub)
        dev = _device.Device(id="ABC123", platform="android", authorized=True)
        with mock.patch.object(proxy, "resolve_device", return_value=dev), \
             mock.patch.object(_device.AndroidBackend, "get_proxy", return_value="127.0.0.1:8080"), \
             mock.patch.object(proxy, "host_lan_ip", return_value="192.168.1.200"), \
             mock.patch.object(proxy, "burp_listener_scope", return_value={"listening": True, "loopback_only": True, "addrs": ["127.0.0.1:8080"]}), \
             mock.patch.object(proxy, "log_action", return_value="op1"):
            out = await cap["mobile_proxy_status"](domain="ex.com")
        self.assertIs(out["routing_ok"], True)
        self.assertEqual(out["warnings"], [])
        self.assertTrue(out["ca_note"])
        self.assertFalse(any("mismatch" in w.lower() or "!= expected" in w or "loopback" in w.lower()
                             for w in out["warnings"]))

    async def test_loopback_only_listener_still_warns_for_non_reverse_proxy(self):
        """Regression guard: the loopback-listener warning must still fire for a
        LAN-configured device_proxy (Task 2/3 behavior unchanged)."""
        stub, cap = _stub_mcp(); proxy.register(stub)
        dev = _device.Device(id="ABC123", platform="android", authorized=True)
        with mock.patch.object(proxy, "resolve_device", return_value=dev), \
             mock.patch.object(_device.AndroidBackend, "get_proxy", return_value="192.168.1.163:8080"), \
             mock.patch.object(proxy, "host_lan_ip", return_value="192.168.1.163"), \
             mock.patch.object(proxy, "burp_listener_scope", return_value={"listening": True, "loopback_only": True, "addrs": ["127.0.0.1:8080"]}), \
             mock.patch.object(proxy, "log_action", return_value="op1"):
            out = await cap["mobile_proxy_status"](domain="ex.com")
        self.assertFalse(out["routing_ok"])
        self.assertTrue(any("loopback" in w.lower() for w in out["warnings"]))

    async def test_canary_lost_includes_remediation(self):
        stub, cap = _stub_mcp(); proxy.register(stub)
        dev = _device.Device(id="ABC123", platform="android", authorized=True)
        with mock.patch.object(proxy, "resolve_device", return_value=dev), \
             mock.patch.object(_device.AndroidBackend, "get_proxy", return_value="192.168.1.163:8080"), \
             mock.patch.object(proxy, "host_lan_ip", return_value="192.168.1.163"), \
             mock.patch.object(proxy, "burp_listener_scope", return_value={"listening": True, "loopback_only": False, "addrs": ["0.0.0.0:8080"]}), \
             mock.patch.object(_device.AndroidBackend, "open_url", return_value=None), \
             mock.patch.object(proxy, "_poll_history_for", return_value=None), \
             mock.patch.object(proxy, "log_action", return_value="op1"):
            out = await cap["mobile_proxy_status"](domain="ex.com", canary=True)
        self.assertTrue(any("mobile_set_proxy" in w for w in out["warnings"]))


if __name__ == "__main__":
    unittest.main()
