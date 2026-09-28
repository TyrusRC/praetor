"""Confirm-before-dangerous gate for the unrestricted raw HTTP tools."""

import unittest

from praetor.tools.send._danger import dangerous_action, parse_raw


class DangerousActionTest(unittest.TestCase):

    def test_flags_high_risk_actions(self):
        cases = [
            ("DELETE", "https://t/api/users/42", ""),                     # user deletion
            ("POST", "https://t/account/deactivate", "user_id=42"),
            ("POST", "https://t/api/change-password", "new=Passw0rd!"),
            ("PUT", "https://t/users/1/password", '{"password":"x"}'),
            ("POST", "https://t/api/refund", '{"amount":9999}'),          # money
            ("POST", "https://t/admin/roles", "grant=admin&user=2"),      # privilege
            ("POST", "https://t/deploy", "env=production"),               # prod op
            ("POST", "https://t/notify", "send email to all users"),     # blast
        ]
        for method, url, body in cases:
            self.assertTrue(dangerous_action(method, url, body),
                            f"should flag {method} {url}")

    def test_ordinary_traffic_not_flagged(self):
        benign = [
            ("GET", "https://t/api/users/42", ""),          # read = never dangerous
            ("GET", "https://t/account/settings", ""),
            ("POST", "https://t/login", "user=admin&pass=admin"),   # auth-control test
            ("POST", "https://t/cart/add", "sku=1&qty=1"),
            ("POST", "https://t/search", "q=' OR 1=1--"),           # SQLi probe
            ("PUT", "https://t/api/profile/bio", '{"bio":"hi"}'),   # benign update
        ]
        for method, url, body in benign:
            self.assertEqual(dangerous_action(method, url, body), "",
                             f"should NOT flag {method} {url} {body}")

    def test_delete_method_always_confirms(self):
        self.assertTrue(dangerous_action("DELETE", "https://t/cart/item/9", ""))

    def test_parse_raw_extracts_method_path_body(self):
        raw = ("DELETE /api/users/7 HTTP/1.1\r\nHost: t\r\n"
               "Content-Type: application/json\r\n\r\n{\"confirm\":true}")
        method, path, body = parse_raw(raw)
        self.assertEqual(method, "DELETE")
        self.assertEqual(path, "/api/users/7")
        self.assertIn("confirm", body)
        # and the raw send would be gated:
        self.assertTrue(dangerous_action(method, path, body))


if __name__ == "__main__":
    unittest.main()
