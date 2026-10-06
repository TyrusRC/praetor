"""Threat-intel / OSINT enrichers — correct endpoints, keyless paths, key hints.

Proves a key put in the config drives the right API call, and that the keyless
tools (shodan InternetDB, urlscan search) work with no key.
"""

import os
import unittest
from unittest.mock import AsyncMock, patch

from praetor.tools import threat_intel as TI

_KEYS = ("VT_API_KEY", "SHODAN_API_KEY", "OTX_API_KEY", "GREYNOISE_API_KEY",
         "ABUSEIPDB_API_KEY", "URLSCAN_API_KEY")


def _fn(name):
    from praetor import server
    return server.mcp._tool_manager._tools[name].fn


def _no_keys() -> dict:
    return {k: v for k, v in os.environ.items() if k not in _KEYS}


class KeyGuardTest(unittest.IsolatedAsyncioTestCase):

    async def test_keyed_tools_hint_when_unset(self):
        with patch.dict(os.environ, _no_keys(), clear=True):
            for tool, arg in [("vt_lookup", {"target": "x.io"}),
                              ("otx_lookup", {"target": "x.io"}),
                              ("greynoise_lookup", {"ip": "1.2.3.4"}),
                              ("abuseipdb_lookup", {"ip": "1.2.3.4"})]:
                out = await _fn(tool)(**arg)
                self.assertIn("not set", out["error"], tool)


class EndpointTest(unittest.IsolatedAsyncioTestCase):

    async def _capture(self, tool, env, **kw):
        cap = {}

        async def fake_get(url, headers=None, params=None, timeout=20):
            cap.update(url=url, headers=headers or {}, params=params or {})
            return {"_ok": 1}, ""        # truthy so success paths don't fall back

        with patch.dict(os.environ, _no_keys(), clear=True), patch.dict(os.environ, env), \
             patch.object(TI, "_get", new=AsyncMock(side_effect=fake_get)):
            out = await _fn(tool)(**kw)
        return cap, out

    async def test_virustotal_domain(self):
        cap, _ = await self._capture("vt_lookup", {"VT_API_KEY": "K"}, target="example.com")
        self.assertIn("/api/v3/domains/example.com", cap["url"])
        self.assertEqual(cap["headers"]["x-apikey"], "K")

    async def test_virustotal_ip_autodetect(self):
        cap, _ = await self._capture("vt_lookup", {"VT_API_KEY": "K"}, target="8.8.8.8")
        self.assertIn("/api/v3/ip_addresses/8.8.8.8", cap["url"])

    async def test_shodan_keyless_internetdb(self):
        cap, out = await self._capture("shodan_host", {}, ip="1.2.3.4")
        self.assertIn("internetdb.shodan.io/1.2.3.4", cap["url"])
        self.assertEqual(out["source"], "internetdb (keyless)")

    async def test_shodan_keyed_full_api(self):
        cap, out = await self._capture("shodan_host", {"SHODAN_API_KEY": "K"}, ip="1.2.3.4")
        self.assertIn("api.shodan.io/shodan/host/1.2.3.4", cap["url"])
        self.assertEqual(cap["params"]["key"], "K")

    async def test_urlscan_keyless_bare_domain(self):
        cap, out = await self._capture("urlscan_search", {}, query="example.com")
        self.assertIn("urlscan.io/api/v1/search", cap["url"])
        self.assertEqual(cap["params"]["q"], "domain:example.com")   # bare host -> domain:
        self.assertEqual(out["source"], "urlscan (keyless)")

    async def test_greynoise_header_key(self):
        cap, _ = await self._capture("greynoise_lookup", {"GREYNOISE_API_KEY": "K"}, ip="1.2.3.4")
        self.assertIn("api.greynoise.io/v3/community/1.2.3.4", cap["url"])
        self.assertEqual(cap["headers"]["key"], "K")

    async def test_abuseipdb_params(self):
        cap, _ = await self._capture("abuseipdb_lookup", {"ABUSEIPDB_API_KEY": "K"}, ip="1.2.3.4")
        self.assertIn("abuseipdb.com/api/v2/check", cap["url"])
        self.assertEqual(cap["params"]["ipAddress"], "1.2.3.4")
        self.assertEqual(cap["headers"]["Key"], "K")


if __name__ == "__main__":
    unittest.main()
