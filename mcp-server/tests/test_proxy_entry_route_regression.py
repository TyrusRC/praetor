"""Regression: proxy-entry fetches must target the real detail route.

Six call sites fetched `GET /api/proxy/{idx}`, which the Burp extension's
ProxyHandler does not serve (only /api/proxy/history/{n}, /api/proxy/history,
/api/proxy/count) — every such call returned 404 "Not found", so
export_poc_bundle / export_proof_capsule / repro_script / shadow_repeater /
opengrep_audit / recorded_login never worked on a real index.

Assert the bare route is gone from source, and that the shared normalizer maps
the handleDetail shape (list headers, flat body) into the {headers: dict, body,
response: {...}} shape the capsule/repro renderers consume.
"""

import re
import unittest
from pathlib import Path

from praetor.tools.notes._proxy_entry import _normalize_entry

SRC = Path(__file__).resolve().parents[1] / "src" / "praetor"

CALLERS = [
    "tools/easm/recorded_login.py",
    "tools/analysis/opengrep_audit.py",
    "tools/shadow_repeater.py",
    "tools/notes/repro_script.py",
    "tools/notes/poc_bundle/__init__.py",
]


class ProxyRouteRegressionTest(unittest.TestCase):
    def test_no_bare_proxy_route(self):
        # The bare `/api/proxy/{...}` route 404s; only `/api/proxy/history/{...}`
        # is served. `/api/proxy/history/{` must NOT trip this check.
        bare = re.compile(r"/api/proxy/\{")
        for rel in CALLERS:
            src = (SRC / rel).read_text()
            self.assertIsNone(
                bare.search(src),
                f"{rel} still fetches the bare /api/proxy/{{idx}} route (404s); "
                f"use /api/proxy/history/{{idx}}",
            )

    def test_normalize_entry_shape(self):
        detail = {
            "index": 5,
            "method": "POST",
            "url": "https://t/graphql",
            "request_headers": [{"name": "Content-Type", "value": "application/json"}],
            "request_body": '{"query":"x"}',
            "status_code": 200,
            "response_headers": [{"name": "Server", "value": "nginx"}],
            "response_body": '{"data":1}',
            "response_length": 10,
        }
        out = _normalize_entry(detail)
        self.assertEqual(out["method"], "POST")
        self.assertEqual(out["url"], "https://t/graphql")
        self.assertEqual(out["headers"], {"Content-Type": "application/json"})
        self.assertEqual(out["body"], '{"query":"x"}')
        self.assertEqual(out["response"]["status"], 200)
        self.assertEqual(out["response"]["headers"], {"Server": "nginx"})
        self.assertEqual(out["response"]["body"], '{"data":1}')

    def test_normalize_entry_tolerates_missing_fields(self):
        out = _normalize_entry({"method": "GET", "url": "https://t/"})
        self.assertEqual(out["headers"], {})
        self.assertEqual(out["body"], "")
        self.assertEqual(out["response"]["headers"], {})


if __name__ == "__main__":
    unittest.main()
