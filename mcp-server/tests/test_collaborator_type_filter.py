"""get_collaborator_interactions must be able to filter by interaction type.

Motivation: on OOB-exfil labs (XSS cookie theft, blind XXE/SSRF) the exfiltrated
data lands in the HTTP/SMTP callback body, but Collaborator also records a flood
of DNS resolver lookups for the same subdomain. Dumping everything buried the two
HTTP POSTs (carrying the victim's cookies) under ~25 DNS entries and led to the
wrong cookie being picked first. type_filter="HTTP" cuts straight to the signal.
"""

from __future__ import annotations

import unittest

from praetor.tools.collaborate._payloads import _filter_interactions


DNS = {"type": "DNS", "client_ip": "1.1.1.1"}
HTTP1 = {"type": "HTTP", "client_ip": "2.2.2.2",
         "http_details": {"request_body": "session=aaa"}}
HTTP2 = {"type": "HTTP", "client_ip": "3.3.3.3",
         "http_details": {"request_body": "secret=x; session=bbb"}}
SMTP = {"type": "SMTP", "client_ip": "4.4.4.4"}
MIXED = [DNS, HTTP1, DNS, DNS, HTTP2, SMTP]


class CollaboratorTypeFilterTest(unittest.TestCase):

    def test_empty_filter_returns_all(self):
        self.assertEqual(_filter_interactions(MIXED, ""), MIXED)

    def test_blank_filter_returns_all(self):
        # Whitespace-only is treated as "no filter", not "match nothing".
        self.assertEqual(_filter_interactions(MIXED, "   "), MIXED)

    def test_http_only(self):
        self.assertEqual(_filter_interactions(MIXED, "HTTP"), [HTTP1, HTTP2])

    def test_case_insensitive(self):
        self.assertEqual(_filter_interactions(MIXED, "http"), [HTTP1, HTTP2])

    def test_no_match_returns_empty(self):
        self.assertEqual(_filter_interactions([DNS, DNS], "HTTP"), [])

    def test_missing_type_field_never_matches(self):
        # An interaction with no 'type' must not slip through a non-empty filter.
        self.assertEqual(_filter_interactions([{"client_ip": "9.9.9.9"}], "HTTP"), [])


if __name__ == "__main__":
    unittest.main()
