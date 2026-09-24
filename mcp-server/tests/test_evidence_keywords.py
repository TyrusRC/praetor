"""Keyword picker for the auto-scroll+highlight message screenshot (pure)."""

import unittest

from praetor.tools._evidence_keywords import pick_search_term


class PickSearchTermTest(unittest.TestCase):

    def test_payload_reflected_wins(self):
        text = "<div>Hello {{7*7}} rendered as 49</div>"
        term, reason = pick_search_term(text, payload="{{7*7}}")
        self.assertEqual(term, "{{7*7}}")
        self.assertEqual(reason, "payload_reflected")

    def test_payload_absent_falls_through(self):
        # payload not in text -> ignored, evidence shape used instead
        term, reason = pick_search_term("root:x:0:0:root:/root:/bin/bash", payload="{{7*7}}")
        self.assertEqual(reason, "passwd_file")
        self.assertTrue(term.startswith("root:"))

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        term, reason = pick_search_term(f"Set-Cookie: jwt={jwt}; Path=/")
        self.assertEqual(reason, "jwt")
        self.assertTrue(term.startswith("eyJ"))

    def test_secret_kv(self):
        term, reason = pick_search_term('{"api_key": "abcdef012345"}')
        self.assertEqual(reason, "secret_kv")
        self.assertIn("api_key", term)

    def test_sql_error(self):
        term, reason = pick_search_term(
            "Warning: you have an error in your SQL syntax near '''")
        self.assertEqual(reason, "sqli_error")

    def test_interesting_path(self):
        term, reason = pick_search_term("Location: /admin/dashboard")
        self.assertEqual(reason, "interesting_path")
        self.assertTrue(term.startswith("/admin"))

    def test_long_hex_lowest(self):
        term, reason = pick_search_term("etag: 0123456789abcdef0123456789abcdef")
        self.assertEqual(reason, "long_hex")

    def test_extra_keyword_precedence(self):
        # operator keyword beats the evidence shapes when present
        text = "flag{found_it} and also 0123456789abcdef0123456789abcdef"
        term, reason = pick_search_term(text, extra_keywords=("flag{",))
        self.assertEqual(reason, "keyword")
        self.assertEqual(term, "flag{")

    def test_nothing_interesting(self):
        self.assertEqual(pick_search_term("GET /home HTTP/1.1\nHost: x.com"), ("", ""))

    def test_empty_text(self):
        self.assertEqual(pick_search_term(""), ("", ""))

    def test_clip_length(self):
        long_hex = "a" * 200
        term, _ = pick_search_term(f"x={long_hex}")
        self.assertLessEqual(len(term), 90)


if __name__ == "__main__":
    unittest.main()
