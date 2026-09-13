"""confirm_sqli injection-point routing.

The cookie branch is new behavior that can silently break: a tracking-cookie
lab needs the payload in the Cookie header, not the query string. These pin
_build_send_params so a regression can't quietly send the payload to the wrong
place (which reads as "not vulnerable").
"""

import unittest

from praetor.tools.exploit.confirm_sqli import _build_send_params


class BuildSendParams(unittest.TestCase):
    def test_cookie_injection_puts_payload_in_cookie_not_query(self):
        p = _build_send_params("cookie:TrackingId", "GET",
                               "https://t/", "TrackingId", "x'||pg_sleep(10)--")
        self.assertEqual(p["cookies"], {"TrackingId": "x'||pg_sleep(10)--"})
        self.assertEqual(p["url"], "https://t/", "cookie payload must not touch the URL")
        self.assertNotIn("data", p)

    def test_cookie_name_falls_back_to_parameter(self):
        p = _build_send_params("cookie:", "GET", "https://t/", "sid", "'--")
        self.assertEqual(p["cookies"], {"sid": "'--"})

    def test_default_get_appends_query_param(self):
        p = _build_send_params("", "GET", "https://t/search", "q", "1' OR '1'='1")
        self.assertEqual(p["url"], "https://t/search?q=1' OR '1'='1")
        self.assertNotIn("cookies", p)

    def test_get_with_existing_query_uses_ampersand(self):
        p = _build_send_params("param", "GET", "https://t/?a=1", "id", "2")
        self.assertEqual(p["url"], "https://t/?a=1&id=2")

    def test_post_uses_form_data(self):
        p = _build_send_params("", "POST", "https://t/login", "user", "admin'--")
        self.assertEqual(p["data"], "user=admin'--")
        self.assertEqual(p["url"], "https://t/login")
        self.assertNotIn("cookies", p)


if __name__ == "__main__":
    unittest.main()
