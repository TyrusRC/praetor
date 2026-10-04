"""resend_with_csrf_refresh — the generic anti-CSRF "Sprinkle".

Covers token detection (form/JSON/header), fresh-token extraction (hidden input,
meta tag, Set-Cookie), substitution, and the end-to-end resend wiring including
the fail-closed path (never resend a stale token).
"""

import unittest
from unittest.mock import AsyncMock, patch

from praetor.tools import session as S


def _fn(name):
    from praetor import server
    return server.mcp._tool_manager._tools[name].fn


class DetectFieldTest(unittest.TestCase):

    def test_form_body(self):
        f, v, loc = S._detect_csrf_field("a=1&csrfmiddlewaretoken=TOK&b=2", {})
        self.assertEqual((f, v, loc), ("csrfmiddlewaretoken", "TOK", "body"))

    def test_json_body(self):
        f, v, loc = S._detect_csrf_field('{"_token":"ABC","x":1}', {})
        self.assertEqual((f, v, loc), ("_token", "ABC", "body"))

    def test_header(self):
        f, v, loc = S._detect_csrf_field("", {"X-CSRF-Token": "HDR"})
        self.assertEqual((f, v, loc), ("X-CSRF-Token", "HDR", "header"))

    def test_none(self):
        self.assertEqual(S._detect_csrf_field("amount=100&to=bob", {}), (None, None, None))


class ExtractFreshTest(unittest.TestCase):

    def test_hidden_input_both_orders(self):
        html_a = '<input type="hidden" name="csrfmiddlewaretoken" value="FRESH1">'
        html_b = '<input value="FRESH2" name="csrfmiddlewaretoken">'
        self.assertEqual(S._extract_fresh_token("csrfmiddlewaretoken", html_a, []), "FRESH1")
        self.assertEqual(S._extract_fresh_token("csrfmiddlewaretoken", html_b, []), "FRESH2")

    def test_rails_meta_tag(self):
        html = '<meta name="csrf-token" content="METATOK">'
        self.assertEqual(S._extract_fresh_token("authenticity_token_csrf", html, []), "METATOK")

    def test_set_cookie_double_submit(self):
        hdrs = [{"name": "Set-Cookie", "value": "XSRF-TOKEN=COOKIETOK; Path=/"}]
        self.assertEqual(S._extract_fresh_token("xsrf", "", hdrs), "COOKIETOK")

    def test_miss_returns_empty(self):
        self.assertEqual(S._extract_fresh_token("_token", "<p>no token here</p>", []), "")


class SubstituteTest(unittest.TestCase):

    def test_form_replaced_and_encoded(self):
        out = S._substitute_token("a=1&_token=OLD&b=2", "_token", "N+W/Eq=")
        self.assertIn("_token=N%2BW%2FEq%3D", out)
        self.assertNotIn("OLD", out)

    def test_json_replaced(self):
        out = S._substitute_token('{"_token":"OLD","x":1}', "_token", "NEW")
        self.assertIn('"_token":"NEW"', out)


class ResendWiringTest(unittest.IsolatedAsyncioTestCase):

    async def test_end_to_end_refreshes_and_resends(self):
        captured = {}

        async def fake_get(path, params=None):
            return {}  # proxy detail (normalized below)

        async def fake_post(url, json=None):
            if json.get("method") == "GET":  # source page
                return {"status": 200,
                        "response_body": '<input name="csrfmiddlewaretoken" value="FRESH999">',
                        "response_headers": []}
            captured["resend"] = json  # the replay
            return {"status": 200, "response_length": 12, "response_body": "transfer ok"}

        req = {"method": "POST", "url": "https://t.io/transfer",
               "headers": {"Referer": "https://t.io/form"},
               "body": "amount=100&csrfmiddlewaretoken=OLDTOK&to=bob"}

        with patch.object(S, "client") as c, \
             patch("praetor.tools.notes._proxy_entry._normalize_entry", return_value=req):
            c.get = AsyncMock(side_effect=fake_get)
            c.post = AsyncMock(side_effect=fake_post)
            out = await _fn("resend_with_csrf_refresh")(index=7, session="userB")

        # fresh token substituted into the resent body; old gone
        self.assertIn("csrfmiddlewaretoken=FRESH999", captured["resend"]["body"])
        self.assertNotIn("OLDTOK", captured["resend"]["body"])
        self.assertEqual(captured["resend"]["session"], "userB")
        self.assertIn("-> 200", out)
        self.assertNotIn("OLDTOK", out)  # token shaped, never dumped raw

    async def test_fail_closed_when_token_not_refreshable(self):
        async def fake_post(url, json=None):
            # source page has no token
            return {"status": 200, "response_body": "<p>nothing</p>", "response_headers": []}

        req = {"method": "POST", "url": "https://t.io/x", "headers": {},
               "body": "csrf=OLD&a=1"}
        with patch.object(S, "client") as c, \
             patch("praetor.tools.notes._proxy_entry._normalize_entry", return_value=req):
            c.get = AsyncMock(return_value={})
            c.post = AsyncMock(side_effect=fake_post)
            out = await _fn("resend_with_csrf_refresh")(index=1, session="userB")
        self.assertIn("Not resending with a stale token", out)

    async def test_no_token_found(self):
        req = {"method": "POST", "url": "https://t.io/x", "headers": {}, "body": "amount=1&to=b"}
        with patch.object(S, "client") as c, \
             patch("praetor.tools.notes._proxy_entry._normalize_entry", return_value=req):
            c.get = AsyncMock(return_value={})
            out = await _fn("resend_with_csrf_refresh")(index=1, session="userB")
        self.assertIn("No anti-CSRF token found", out)


if __name__ == "__main__":
    unittest.main()
