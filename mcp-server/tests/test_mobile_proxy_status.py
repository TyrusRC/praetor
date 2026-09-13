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


if __name__ == "__main__":
    unittest.main()
