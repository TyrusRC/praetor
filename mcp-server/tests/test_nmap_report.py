"""nmap XML -> HTML report (network-lane deliverable). Pure render coverage."""

import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

_INV = {
    "hosts": [
        {"ip": "10.0.0.5", "hostnames": ["web01"], "ports": [
            {"port": 443, "proto": "tcp", "state": "open", "service": "https",
             "product": "nginx", "version": "1.18", "tunnel": "ssl"},
            {"port": 8081, "proto": "tcp", "state": "open", "service": "http",
             "product": "Jetty", "version": "9.4", "tunnel": ""},
        ]},
        {"ip": "10.0.0.6", "hostnames": [], "ports": [
            {"port": 22, "proto": "tcp", "state": "open", "service": "ssh",
             "product": "OpenSSH", "version": "7.4", "tunnel": ""},
        ]},
    ]
}


class TestNmapReport(unittest.TestCase):
    def setUp(self):
        from praetor.tools.nmap_report import render_nmap_html
        self.render = render_nmap_html

    def test_row_per_open_port(self):
        html = self.render(_INV)
        # 3 open ports total -> 3 data rows (count <tr with a port number)
        self.assertEqual(html.count("<td class=\"port\">"), 3)

    def test_hosts_and_ips_present(self):
        html = self.render(_INV)
        self.assertIn("10.0.0.5", html)
        self.assertIn("web01", html)
        self.assertIn("nginx", html)

    def test_non_standard_port_flagged(self):
        # 8081 is not a common web port -> flagged for attention
        html = self.render(_INV)
        self.assertIn("8081", html)
        self.assertIn("non-standard", html.lower())

    def test_self_contained_no_external_refs(self):
        html = self.render(_INV)
        low = html.lower()
        self.assertIn("<html", low)
        self.assertNotIn("http://", low)
        self.assertNotIn("src=", low)

    def test_empty_inventory_placeholder(self):
        html = self.render({"hosts": []})
        self.assertIn("no hosts", html.lower())

    def test_service_html_escaped(self):
        inv = {"hosts": [{"ip": "1.1.1.1", "hostnames": [], "ports": [
            {"port": 80, "proto": "tcp", "state": "open",
             "service": "<x>", "product": "<script>", "version": "", "tunnel": ""}]}]}
        html = self.render(inv)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)


if __name__ == "__main__":
    unittest.main()
