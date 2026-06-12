"""W31-b — token-economy wave 2.

Covers:
- get_request_detail(fields=[...], body_first, body_last) slice path
- find_targets_for_class(vuln_class, domain, host, limit) vuln-class mapping
- extract_*_batch tools dedup + cap
- summary_only flag presence on smart_analyze / discover_attack_surface / full_recon
- tightened defaults on get_sitemap / fetch_wayback_urls / get_unique_endpoints / get_scanner_findings
"""

from __future__ import annotations

import inspect
import unittest


class GetRequestDetailFieldsTest(unittest.TestCase):
    """Unit-test the pure helpers; signature gets a smoke check."""

    def test_slice_status_codes_and_redirect(self):
        from burpsuite_mcp.tools.read import _slice_request_detail
        data = {
            "method": "GET", "url": "https://app.test/login?next=/x",
            "status_code": 302,
            "response_headers": [
                {"name": "Content-Type", "value": "text/html"},
                {"name": "Location", "value": "/login"},
                {"name": "Set-Cookie", "value": "sid=abc"},
            ],
            "response_body": "<html><form action=/submit></form></html>",
        }
        out = _slice_request_detail(
            data,
            ["status_code", "content_type", "has_form", "has_redirect",
             "location_header", "set_cookie", "host", "path", "query_params"],
            1024, 0,
        )
        self.assertEqual(out["status_code"], 302)
        self.assertEqual(out["content_type"], "text/html")
        self.assertTrue(out["has_form"])
        self.assertTrue(out["has_redirect"])
        self.assertEqual(out["location_header"], "/login")
        self.assertEqual(out["set_cookie"], ["sid=abc"])
        self.assertEqual(out["host"], "app.test")
        self.assertEqual(out["path"], "/login")
        self.assertEqual(out["query_params"], {"next": "/x"})

    def test_error_markers_sqli(self):
        from burpsuite_mcp.tools.read import _slice_request_detail
        data = {"response_body": "pg_query() failed: ERROR pg_query SQLSTATE[42P01]"}
        out = _slice_request_detail(data, ["error_markers"], 1024, 0)
        self.assertIn("sqli", out["error_markers"])

    def test_trim_head_tail(self):
        from burpsuite_mcp.tools.read import _trim_body
        body = "x" * 5000
        head_only = _trim_body(body, 100, 0)
        self.assertTrue(head_only.startswith("x" * 100))
        self.assertIn("TRUNCATED", head_only)
        both = _trim_body(body, 100, 100)
        self.assertTrue(both.startswith("x" * 100))
        self.assertTrue(both.endswith("x" * 100))

    def test_unknown_field_skipped(self):
        from burpsuite_mcp.tools.read import _slice_request_detail
        out = _slice_request_detail({}, ["bogus_field", "status_code"], 1024, 0)
        self.assertIn("status_code", out)
        self.assertNotIn("bogus_field", out)

    def test_no_recognised_fields(self):
        from burpsuite_mcp.tools.read import _slice_request_detail
        out = _slice_request_detail({}, ["bogus_only"], 1024, 0)
        self.assertIn("error", out)


class FindTargetsForClassMappingTest(unittest.TestCase):
    def test_token_map_basic(self):
        from burpsuite_mcp.tools.scan.rank_targets import _vuln_class_to_risk_token
        self.assertEqual(_vuln_class_to_risk_token("sqli"), "SQLI")
        self.assertEqual(_vuln_class_to_risk_token("open_redirect"), "REDIRECT")
        self.assertEqual(_vuln_class_to_risk_token("rce"), "CMDI")
        self.assertEqual(_vuln_class_to_risk_token("mass_assignment"), "MASS")
        self.assertEqual(_vuln_class_to_risk_token("web_llm"), "WEB/LLM")

    def test_token_map_fallback(self):
        from burpsuite_mcp.tools.scan.rank_targets import _vuln_class_to_risk_token
        self.assertEqual(_vuln_class_to_risk_token("unknown_class"), "UNKNOWN/CLASS")

    def test_matches_vuln_class(self):
        from burpsuite_mcp.tools.scan.rank_targets import _matches_vuln_class
        self.assertTrue(_matches_vuln_class(["SQLI/IDOR"], "SQLI"))
        self.assertTrue(_matches_vuln_class(["REDIRECT/SSRF"], "REDIRECT"))
        self.assertTrue(_matches_vuln_class(["MASS/ASSIGNMENT"], "MASS"))
        self.assertFalse(_matches_vuln_class(["BASELINE_PROBE"], "SQLI"))
        self.assertFalse(_matches_vuln_class([], "SQLI"))


class ExtractBatchTest(unittest.TestCase):
    def test_normalize_indices_dedup_and_cap(self):
        from burpsuite_mcp.tools.extract_batch import _normalize_indices, _BATCH_HARD_CAP
        out, err = _normalize_indices([1, 2, 3, 2, 1])
        self.assertIsNone(err)
        self.assertEqual(out, [1, 2, 3])

        out, err = _normalize_indices([])
        self.assertIsNotNone(err)

        many = list(range(_BATCH_HARD_CAP + 10))
        out, err = _normalize_indices(many)
        self.assertEqual(len(out), _BATCH_HARD_CAP)


class SignaturesTest(unittest.TestCase):
    """Confirm the new params actually landed on the tool signatures.

    Tools are registered by passing FastMCP — we just import the source and
    grep the function signatures with inspect.
    """

    def test_get_request_detail_has_fields(self):
        import textwrap
        from pathlib import Path
        src = Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "tools" / "read.py"
        text = src.read_text()
        self.assertIn("fields: list[str] | None = None", text)
        self.assertIn("body_first: int = 1024", text)
        self.assertIn("body_last: int = 0", text)

    def test_smart_analyze_has_summary_only(self):
        from pathlib import Path
        src = Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "tools" / "analyze.py"
        self.assertIn("summary_only: bool = False", src.read_text())

    def test_discover_attack_surface_has_summary_only(self):
        from pathlib import Path
        src = Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "tools" / "scan" / "discovery.py"
        self.assertIn("summary_only: bool = False", src.read_text())

    def test_full_recon_has_summary_only(self):
        from pathlib import Path
        src = Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "tools" / "scan" / "recon_full.py"
        self.assertIn("summary_only: bool = False", src.read_text())

    def test_tightened_defaults(self):
        from pathlib import Path
        read = (Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "tools" / "read.py").read_text()
        self.assertIn("async def get_sitemap(url_prefix: str = \"\", limit: int = 30)", read)
        # get_scanner_findings default — multi-line signature
        self.assertIn("limit: int = 20", read)

        analyze = (Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "tools" / "analyze.py").read_text()
        self.assertIn("async def get_unique_endpoints(url_prefix: str = \"\", limit: int = 30)", analyze)

        wayback = (Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "tools" / "recon_extended" / "wayback.py").read_text()
        self.assertIn("limit: int = 30", wayback)


if __name__ == "__main__":
    unittest.main()
