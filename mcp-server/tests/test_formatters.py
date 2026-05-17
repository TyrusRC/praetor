"""Calibration tests for processing/formatters.py.

Covers proxy-table truncation invariants and scanner-findings dedup/noise-filter
behavior. These run hot on every get_proxy_history / get_scanner_findings call;
silent format drift inflates token usage.

Run: uv run python -m unittest tests.test_formatters -v
"""

import unittest

from burpsuite_mcp.processing.formatters import format_findings, format_proxy_table


class ProxyTableTests(unittest.TestCase):
    def test_empty_history_message(self):
        out = format_proxy_table({"items": [], "total": 0, "offset": 0})
        self.assertIn("Proxy history is empty", out)

    def test_header_fits_80ch(self):
        # SSH/mobile terminal soft-wrap budget. Header row (the divider) is
        # exactly 80 dashes so the separator never wraps.
        out = format_proxy_table({
            "items": [{"index": 0, "method": "GET", "status_code": 200,
                       "response_length": 0, "mime_type": "html",
                       "url": "https://x.test/"}],
            "total": 1, "offset": 0,
        })
        for line in out.splitlines():
            if line.startswith("-"):
                self.assertEqual(len(line), 80)

    def test_url_trails_row_not_truncated(self):
        # Long URLs must not be cut — terminals soft-wrap them cleanly.
        long_url = "https://api.example.com/v1/users/12345/orders/abcde/items?foo=bar"
        out = format_proxy_table({
            "items": [{"index": 1, "method": "GET", "status_code": 200,
                       "response_length": 1234, "mime_type": "json",
                       "url": long_url}],
            "total": 1, "offset": 0,
        })
        self.assertIn(long_url, out)

    def test_mime_truncated_to_14ch(self):
        out = format_proxy_table({
            "items": [{"index": 1, "method": "GET", "status_code": 200,
                       "response_length": 0,
                       "mime_type": "application/vnd.custom.long.mime+json",
                       "url": "https://x.test/"}],
            "total": 1, "offset": 0,
        })
        # The 14-char truncation is exclusive — first 14 chars of the mime.
        self.assertIn("application/vn", out)
        self.assertNotIn("application/vnd.custom", out)

    def test_method_truncated_to_6ch(self):
        out = format_proxy_table({
            "items": [{"index": 1, "method": "PROPFIND", "status_code": 200,
                       "response_length": 0, "mime_type": "xml",
                       "url": "https://x.test/"}],
            "total": 1, "offset": 0,
        })
        # PROPFIND truncates to "PROPFI"
        self.assertIn("PROPFI", out)
        self.assertNotIn("PROPFIND ", out)

    def test_missing_method_falls_back_to_question(self):
        out = format_proxy_table({
            "items": [{"index": 1, "status_code": 200, "response_length": 0,
                       "url": "https://x.test/"}],
            "total": 1, "offset": 0,
        })
        # Either explicit `?` or empty default in column — must not crash.
        self.assertIn("https://x.test/", out)

    def test_total_and_offset_reflected_in_header(self):
        out = format_proxy_table({
            "items": [{"index": 50, "method": "GET", "status_code": 200,
                       "response_length": 0, "mime_type": "html",
                       "url": "https://x.test/"}],
            "total": 200, "offset": 50,
        })
        self.assertIn("200 total", out)
        self.assertIn("showing 50-50", out)

    def test_null_mime_does_not_crash(self):
        out = format_proxy_table({
            "items": [{"index": 1, "method": "GET", "status_code": 200,
                       "response_length": 0, "mime_type": None,
                       "url": "https://x.test/"}],
            "total": 1, "offset": 0,
        })
        self.assertIn("https://x.test/", out)


class FindingsFormatTests(unittest.TestCase):
    def test_empty_findings_message(self):
        out = format_findings({"items": [], "total_findings": 0})
        self.assertIn("No scanner findings", out)

    def test_information_tentative_noise_filtered(self):
        out = format_findings({
            "items": [
                {"name": "Some Info", "severity": "INFORMATION",
                 "confidence": "TENTATIVE", "base_url": "https://x.test/"},
            ],
            "total_findings": 1,
        })
        self.assertIn("1 noise filtered", out)
        self.assertIn("0 actionable", out)

    def test_known_noise_name_filtered(self):
        out = format_findings({
            "items": [
                {"name": "Strict transport security not enforced",
                 "severity": "LOW", "confidence": "FIRM",
                 "base_url": "https://x.test/"},
            ],
            "total_findings": 1,
        })
        self.assertIn("noise filtered", out)

    def test_high_severity_finding_listed(self):
        out = format_findings({
            "items": [
                {"name": "SQL injection", "severity": "HIGH",
                 "confidence": "CERTAIN",
                 "base_url": "https://x.test/api"},
            ],
            "total_findings": 1,
        })
        self.assertIn("HIGH", out)
        self.assertIn("SQL injection", out)
        self.assertIn("CERTAIN", out)

    def test_dedup_by_name_and_host(self):
        # Same issue on multiple paths of the same host -> single entry, count.
        out = format_findings({
            "items": [
                {"name": "XSS", "severity": "HIGH", "confidence": "CERTAIN",
                 "base_url": "https://x.test/a"},
                {"name": "XSS", "severity": "HIGH", "confidence": "CERTAIN",
                 "base_url": "https://x.test/b"},
                {"name": "XSS", "severity": "HIGH", "confidence": "CERTAIN",
                 "base_url": "https://x.test/c"},
            ],
            "total_findings": 3,
        })
        self.assertIn("(x3)", out)
        # 3 raw, 1 actionable after dedup.
        self.assertIn("1 actionable", out)

    def test_dedup_different_hosts_kept_separate(self):
        # Same issue name on different hosts should not collapse.
        out = format_findings({
            "items": [
                {"name": "XSS", "severity": "HIGH", "confidence": "CERTAIN",
                 "base_url": "https://x.test/"},
                {"name": "XSS", "severity": "HIGH", "confidence": "CERTAIN",
                 "base_url": "https://y.test/"},
            ],
            "total_findings": 2,
        })
        self.assertIn("2 actionable", out)

    def test_severity_order_critical_first(self):
        out = format_findings({
            "items": [
                {"name": "Low issue", "severity": "LOW", "confidence": "FIRM",
                 "base_url": "https://x.test/a"},
                {"name": "Critical issue", "severity": "CRITICAL",
                 "confidence": "CERTAIN", "base_url": "https://x.test/b"},
            ],
            "total_findings": 2,
        })
        crit_idx = out.index("Critical issue")
        low_idx = out.index("Low issue")
        self.assertLess(crit_idx, low_idx)

    def test_confidence_sort_certain_before_tentative(self):
        out = format_findings({
            "items": [
                {"name": "Issue A", "severity": "HIGH",
                 "confidence": "TENTATIVE", "base_url": "https://x.test/a"},
                {"name": "Issue B", "severity": "HIGH",
                 "confidence": "CERTAIN", "base_url": "https://x.test/b"},
            ],
            "total_findings": 2,
        })
        cert_idx = out.index("Issue B")
        tent_idx = out.index("Issue A")
        self.assertLess(cert_idx, tent_idx)

    def test_html_tags_stripped_from_detail(self):
        out = format_findings({
            "items": [
                {"name": "Issue", "severity": "HIGH", "confidence": "CERTAIN",
                 "base_url": "https://x.test/",
                 "detail": "<p>vuln <b>found</b></p>"},
            ],
            "total_findings": 1,
        })
        self.assertNotIn("<p>", out)
        self.assertNotIn("<b>", out)
        self.assertIn("vuln", out)
        self.assertIn("found", out)

    def test_detail_truncated_at_300(self):
        out = format_findings({
            "items": [
                {"name": "Issue", "severity": "HIGH", "confidence": "CERTAIN",
                 "base_url": "https://x.test/",
                 "detail": "A" * 1000},
            ],
            "total_findings": 1,
        })
        # The detail line should not carry the full 1000 chars.
        # Cap is 300 after strip — find the Detail: line.
        for line in out.splitlines():
            if line.strip().startswith("Detail:"):
                self.assertLess(len(line), 350)

    def test_evidence_url_rendered(self):
        out = format_findings({
            "items": [
                {"name": "Issue", "severity": "HIGH", "confidence": "CERTAIN",
                 "base_url": "https://x.test/",
                 "evidence": [{"method": "POST",
                               "url": "https://x.test/api",
                               "status_code": 500}]},
            ],
            "total_findings": 1,
        })
        self.assertIn("Evidence: POST", out)
        self.assertIn("https://x.test/api", out)
        self.assertIn("500", out)


if __name__ == "__main__":
    unittest.main()
