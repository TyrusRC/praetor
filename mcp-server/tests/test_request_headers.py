"""Calibration tests for apply_realistic_headers.

Run: uv run python -m unittest tests.test_request_headers -v
"""

import unittest
from unittest.mock import patch

from burpsuite_mcp.tools._request_headers import (
    _DEFAULT_BROWSER_HEADERS,
    _domain_from_url,
    apply_realistic_headers,
)


class DomainExtractionTests(unittest.TestCase):
    def test_https_domain(self):
        self.assertEqual(_domain_from_url("https://example.com/path"), "example.com")

    def test_http_with_port(self):
        self.assertEqual(_domain_from_url("http://api.example.com:8080/x"), "api.example.com")

    def test_invalid_url(self):
        self.assertEqual(_domain_from_url(""), "")

    def test_no_scheme(self):
        # urlparse returns "" hostname when scheme missing
        self.assertEqual(_domain_from_url("example.com/path"), "")


class ApplyRealisticHeadersTests(unittest.TestCase):
    def test_no_caller_no_profile_injects_defaults(self):
        with patch(
            "burpsuite_mcp.tools._request_headers._load_realistic_headers",
            return_value={},
        ):
            out = apply_realistic_headers("https://example.com/", None)
        self.assertIn("User-Agent", out)
        self.assertIn("Mozilla", out["User-Agent"])
        self.assertIn("Accept", out)
        self.assertIn("Sec-Ch-Ua", out)
        self.assertIn("Accept-Language", out)

    def test_caller_user_agent_wins_over_default(self):
        with patch(
            "burpsuite_mcp.tools._request_headers._load_realistic_headers",
            return_value={},
        ):
            out = apply_realistic_headers(
                "https://example.com/", {"User-Agent": "my-tool/1.0"},
            )
        self.assertEqual(out["User-Agent"], "my-tool/1.0")

    def test_caller_case_insensitive_overrides_default(self):
        with patch(
            "burpsuite_mcp.tools._request_headers._load_realistic_headers",
            return_value={},
        ):
            out = apply_realistic_headers(
                "https://example.com/", {"user-agent": "lowercase-tool"},
            )
        # caller key stays as-is
        self.assertEqual(out.get("user-agent"), "lowercase-tool")
        # default key should NOT be added (would duplicate UA)
        self.assertNotIn("User-Agent", out)

    def test_profile_overrides_defaults(self):
        profile = {
            "User-Agent": "Mozilla/5.0 (real browser)",
            "Cookie": "session=abc123",
            "Authorization": "Bearer xyz",
        }
        with patch(
            "burpsuite_mcp.tools._request_headers._load_realistic_headers",
            return_value=profile,
        ):
            out = apply_realistic_headers("https://example.com/", None)
        self.assertEqual(out["User-Agent"], "Mozilla/5.0 (real browser)")
        self.assertEqual(out["Cookie"], "session=abc123")
        self.assertEqual(out["Authorization"], "Bearer xyz")
        # defaults still fill gaps
        self.assertIn("Accept-Language", out)

    def test_caller_overrides_profile(self):
        profile = {"User-Agent": "profile-ua", "Cookie": "profile-cookie"}
        with patch(
            "burpsuite_mcp.tools._request_headers._load_realistic_headers",
            return_value=profile,
        ):
            out = apply_realistic_headers(
                "https://example.com/",
                {"User-Agent": "caller-ua"},
            )
        self.assertEqual(out["User-Agent"], "caller-ua")
        # profile Cookie still flows through
        self.assertEqual(out["Cookie"], "profile-cookie")

    def test_bare_skips_everything(self):
        profile = {"User-Agent": "profile-ua"}
        with patch(
            "burpsuite_mcp.tools._request_headers._load_realistic_headers",
            return_value=profile,
        ):
            out = apply_realistic_headers(
                "https://example.com/",
                {"X-Custom": "val"},
                bare=True,
            )
        self.assertEqual(out, {"X-Custom": "val"})
        self.assertNotIn("User-Agent", out)
        self.assertNotIn("Accept", out)

    def test_bare_with_no_headers_returns_empty(self):
        with patch(
            "burpsuite_mcp.tools._request_headers._load_realistic_headers",
            return_value={"User-Agent": "ua"},
        ):
            out = apply_realistic_headers("https://example.com/", None, bare=True)
        self.assertEqual(out, {})

    def test_profile_blocklist_stripped(self):
        profile = {
            "User-Agent": "Mozilla/5.0",
            "Host": "old-host.example.com",
            "Content-Length": "1234",
            "Content-Type": "application/json",
            "Transfer-Encoding": "chunked",
            "Connection": "keep-alive",
        }
        with patch(
            "burpsuite_mcp.tools._request_headers._load_realistic_headers",
            return_value=profile,
        ):
            out = apply_realistic_headers("https://new.example.com/", None)
        self.assertEqual(out["User-Agent"], "Mozilla/5.0")
        self.assertNotIn("Host", out)
        self.assertNotIn("Content-Length", out)
        self.assertNotIn("Content-Type", out)
        self.assertNotIn("Transfer-Encoding", out)
        self.assertNotIn("Connection", out)

    def test_empty_url_no_profile_lookup_defaults_apply(self):
        with patch(
            "burpsuite_mcp.tools._request_headers._load_realistic_headers",
            return_value={},
        ) as m:
            out = apply_realistic_headers("", None)
        # defaults still fire
        self.assertIn("User-Agent", out)
        # but profile lookup gets empty domain
        m.assert_called_once_with("")

    def test_all_default_headers_present_with_clean_request(self):
        with patch(
            "burpsuite_mcp.tools._request_headers._load_realistic_headers",
            return_value={},
        ):
            out = apply_realistic_headers("https://example.com/", None)
        for k in _DEFAULT_BROWSER_HEADERS:
            self.assertIn(k, out)

    def test_unsafe_headers_passes_blocklisted_profile_through(self):
        profile = {
            "User-Agent": "Mozilla/5.0",
            "Host": "victim.example.com",
            "Content-Length": "10",
            "Transfer-Encoding": "chunked",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        with patch(
            "burpsuite_mcp.tools._request_headers._load_realistic_headers",
            return_value=profile,
        ):
            out = apply_realistic_headers(
                "https://attack.example.com/", None, unsafe_headers=True,
            )
        self.assertEqual(out["Host"], "victim.example.com")
        self.assertEqual(out["Content-Length"], "10")
        self.assertEqual(out["Transfer-Encoding"], "chunked")
        self.assertEqual(out["Content-Type"], "application/x-www-form-urlencoded")

    def test_unsafe_caller_still_wins(self):
        profile = {"Host": "profile-host.com", "Content-Length": "999"}
        with patch(
            "burpsuite_mcp.tools._request_headers._load_realistic_headers",
            return_value=profile,
        ):
            out = apply_realistic_headers(
                "https://x.com/",
                {"Host": "caller-host.com"},
                unsafe_headers=True,
            )
        self.assertEqual(out["Host"], "caller-host.com")
        self.assertEqual(out["Content-Length"], "999")

    def test_unsafe_bare_takes_priority(self):
        profile = {"Host": "profile-host.com"}
        with patch(
            "burpsuite_mcp.tools._request_headers._load_realistic_headers",
            return_value=profile,
        ):
            out = apply_realistic_headers(
                "https://x.com/", None, bare=True, unsafe_headers=True,
            )
        self.assertEqual(out, {})

    def test_does_not_mutate_caller_dict(self):
        caller = {"X-Custom": "val"}
        with patch(
            "burpsuite_mcp.tools._request_headers._load_realistic_headers",
            return_value={},
        ):
            out = apply_realistic_headers("https://example.com/", caller)
        self.assertEqual(caller, {"X-Custom": "val"})
        self.assertIsNot(out, caller)


if __name__ == "__main__":
    unittest.main(verbosity=2)
