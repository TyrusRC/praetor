"""Vuln-tool helpers: CSRF token discovery, SSTI payloads, SameSite parsing.

Pure stdlib — no Burp, no async. Run with:
    uv run python -m unittest tests.test_vuln_tools -v
"""

import unittest

from praetor.tools.vuln._csrf_helpers import _find_token_in_request, _samesite_status
from praetor.tools.vuln._ssti_payloads import (
    _POLYGLOT,
    _POLYGLOT_HINTS,
    _DISTINGUISHERS,
    _CAPABILITIES,
)


class CsrfTokenDiscovery(unittest.TestCase):

    def test_finds_header_token(self):
        headers = {"X-CSRF-Token": "abc123", "Content-Type": "application/json"}
        loc, val = _find_token_in_request(headers, "")
        self.assertTrue(loc.startswith("header:"))
        self.assertEqual(val, "abc123")

    def test_finds_xsrf_header(self):
        headers = {"X-XSRF-Token": "tok456"}
        loc, val = _find_token_in_request(headers, "")
        self.assertIn("xsrf", loc.lower())
        self.assertEqual(val, "tok456")

    def test_finds_body_form_param(self):
        loc, val = _find_token_in_request({}, "action=login&csrf_token=DEADBEEF&user=a")
        self.assertTrue(loc.startswith("body:"))
        self.assertEqual(val, "DEADBEEF")

    def test_finds_body_json_param(self):
        body = '{"csrf_token": "json-tok-99", "data": "x"}'
        loc, val = _find_token_in_request({}, body)
        self.assertTrue(loc.startswith("body:"))
        self.assertEqual(val, "json-tok-99")

    def test_finds_cookie_double_submit(self):
        headers = {"Cookie": "session=abc; csrf_token=COOK_TOK; other=1"}
        loc, val = _find_token_in_request(headers, "")
        self.assertTrue(loc.startswith("cookie:"))
        self.assertEqual(val, "COOK_TOK")

    def test_returns_none_when_absent(self):
        loc, val = _find_token_in_request({"Accept": "text/html"}, "username=bob")
        self.assertEqual(loc, "none")
        self.assertEqual(val, "")

    def test_empty_inputs(self):
        loc, val = _find_token_in_request({}, "")
        self.assertEqual(loc, "none")

    def test_header_takes_priority_over_body(self):
        headers = {"X-CSRF-Token": "from-header"}
        body = "csrf_token=from-body"
        loc, _ = _find_token_in_request(headers, body)
        self.assertTrue(loc.startswith("header:"),
                        "header token should take priority over body")


class SameSiteStatus(unittest.TestCase):

    def test_strict(self):
        verdict, _ = _samesite_status(["session=abc; SameSite=Strict; Secure"])
        self.assertEqual(verdict, "strict")

    def test_lax(self):
        verdict, _ = _samesite_status(["JSESSIONID=x; SameSite=Lax; Path=/"])
        self.assertEqual(verdict, "lax")

    def test_none_with_secure(self):
        verdict, _ = _samesite_status(["session=x; SameSite=None; Secure"])
        self.assertEqual(verdict, "none-secure")

    def test_absent_when_no_cookies(self):
        verdict, _ = _samesite_status([])
        self.assertEqual(verdict, "absent")

    def test_missing_attribute(self):
        verdict, _ = _samesite_status(["session=x; Path=/; HttpOnly"])
        self.assertEqual(verdict, "missing-attribute")


class SstiPayloadTables(unittest.TestCase):

    def test_polyglot_nonempty(self):
        self.assertGreater(len(_POLYGLOT), 0)

    def test_polyglot_hints_cover_major_engines(self):
        engines = {name for name, _ in _POLYGLOT_HINTS}
        for expected in ("jinja2", "twig", "freemarker", "erb", "mako"):
            self.assertIn(expected, engines, f"{expected} missing from hints")

    def test_distinguishers_have_valid_structure(self):
        for payload, marker, engine_list in _DISTINGUISHERS:
            self.assertIsInstance(payload, str)
            self.assertIsInstance(marker, str)
            self.assertIsInstance(engine_list, list)
            self.assertGreater(len(engine_list), 0)

    def test_capabilities_cover_major_engines(self):
        for engine in ("jinja2", "twig", "freemarker"):
            self.assertIn(engine, _CAPABILITIES,
                          f"{engine} missing from capability probes")
            self.assertGreater(len(_CAPABILITIES[engine]), 0)

    def test_capability_tuples_are_triples(self):
        for engine, probes in _CAPABILITIES.items():
            for probe in probes:
                self.assertEqual(len(probe), 3,
                                 f"{engine} probe {probe[0] if probe else '?'} "
                                 f"is not a (name, payload, marker) triple")


if __name__ == "__main__":
    unittest.main()
