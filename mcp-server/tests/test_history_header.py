"""Proxy > HTTP history context header (pure row/title helpers)."""

import unittest

from praetor.tools._history_header import row_values, title_from_body


class TitleFromBodyTest(unittest.TestCase):
    def test_extracts_title(self):
        self.assertEqual(title_from_body("<html><title>Example Domain</title></html>"),
                         "Example Domain")

    def test_multiline_title(self):
        self.assertEqual(title_from_body("<title>\n  Hello\n</title>"), "Hello")

    def test_no_title(self):
        self.assertEqual(title_from_body("<html>no title here</html>"), "")

    def test_empty(self):
        self.assertEqual(title_from_body(""), "")


class RowValuesTest(unittest.TestCase):
    def test_columns(self):
        entry = {
            "url": "https://pentest-ground.com:4280/vulnerabilities/xss_r/?name=x",
            "method": "GET", "status_code": 200, "response_length": 4258,
            "mime_type": "HTML", "response_body": "<title>XSS</title>",
        }
        v = row_values(entry, 2)
        self.assertEqual(v["#"], "2")
        self.assertEqual(v["Host"], "pentest-ground.com:4280")
        self.assertEqual(v["Method"], "GET")
        self.assertEqual(v["URL"], "/vulnerabilities/xss_r/?name=x")   # path + query
        self.assertEqual(v["Status"], "200")
        self.assertEqual(v["Length"], "4258")
        self.assertEqual(v["MIME"], "HTML")
        self.assertEqual(v["Title"], "XSS")

    def test_root_path(self):
        v = row_values({"url": "https://example.com/", "method": "GET"}, 1)
        self.assertEqual(v["URL"], "/")
        self.assertEqual(v["Host"], "example.com")


if __name__ == "__main__":
    unittest.main()
