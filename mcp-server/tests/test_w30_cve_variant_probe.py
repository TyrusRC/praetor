"""W30-a — probe_cve_with_variants: CVE-aware bounded PoC sweep."""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from burpsuite_mcp.tools import cve_variant_probe as cvp


def _stub_mcp():
    captured: dict = {}

    class _Stub:
        def tool(self, *a, **kw):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    return _Stub(), captured


def _get_tool():
    stub, captured = _stub_mcp()
    cvp.register(stub)
    return captured["probe_cve_with_variants"]


class CveToClassMappingTest(unittest.TestCase):

    def test_react2shell_aliases_map_to_rsc(self):
        for cve in ("CVE-2025-55182", "CVE-2025-66478", "react2shell"):
            self.assertEqual(cvp._resolve_class(cve, ""),
                             "react_server_components")

    def test_trpc_sspp_routes(self):
        self.assertEqual(cvp._resolve_class("CVE-2025-68130", ""), "trpc_sspp")

    def test_proto_pollution_routes(self):
        for cve in ("CVE-2026-40175", "CVE-2026-44789",
                    "CVE-2026-44790", "CVE-2026-44791"):
            self.assertEqual(cvp._resolve_class(cve, ""), "prototype_pollution")

    def test_nextjs_cache_routes(self):
        self.assertEqual(cvp._resolve_class("CVE-2025-29927", ""),
                         "nextjs_cache_poisoning")

    def test_unknown_cve_falls_to_generic(self):
        self.assertEqual(cvp._resolve_class("CVE-9999-99999", ""), "generic")

    def test_explicit_class_wins_over_cve(self):
        self.assertEqual(
            cvp._resolve_class("CVE-2025-55182", "prototype_pollution"),
            "prototype_pollution")


class VariantGeneratorTest(unittest.TestCase):

    def test_rsc_yields_at_least_five_shapes(self):
        v = cvp._rsc_variants("baseline-__CANARY__", "PRAETOR-DEADBEEF", "abc123")
        self.assertGreaterEqual(len(v), 5)
        labels = [x["label"] for x in v]
        self.assertIn("rsc.children_chunk", labels)
        self.assertIn("rsc.multipart_action", labels)
        self.assertIn("rsc.form_state_urlencoded", labels)

    def test_rsc_canary_substituted_into_baseline(self):
        v = cvp._rsc_variants("body=__CANARY__", "PRAETOR-AAAA", "")
        baseline = [x for x in v if x["label"] == "rsc.baseline_with_headers"][0]
        self.assertIn("PRAETOR-AAAA", baseline["body"])
        self.assertNotIn("__CANARY__", baseline["body"])

    def test_rsc_action_id_in_next_action_header(self):
        v = cvp._rsc_variants("", "CANARY", "MYACTIONID")
        first = v[0]
        self.assertEqual(first["headers"].get("Next-Action"), "MYACTIONID")

    def test_nextjs_cache_variants_use_known_headers(self):
        v = cvp._nextjs_cache_variants("", "PRAETOR-FEED", "")
        labels = [x["label"] for x in v]
        self.assertIn("next.x_now_route_matches", labels)
        # Verify the canary is in the route matches header
        rm = [x for x in v if x["label"] == "next.x_now_route_matches"][0]
        self.assertIn("PRAETOR-FEED", rm["headers"]["x-now-route-matches"])

    def test_trpc_variants_target_proto_and_constructor(self):
        v = cvp._trpc_variants("", "PRAETOR-BEEF", "")
        labels = [x["label"] for x in v]
        self.assertIn("trpc.batch_proto", labels)
        self.assertIn("trpc.batch_constructor", labels)
        self.assertIn("trpc.querystring_proto", labels)

    def test_proto_variants_cover_canonical_sinks(self):
        v = cvp._proto_variants("", "PRAETOR-CAFE", "")
        labels = [x["label"] for x in v]
        for required in ("proto.dunder", "proto.constructor",
                         "proto.nested_dunder", "proto.unicode_key",
                         "proto.array_proto"):
            self.assertIn(required, labels)

    def test_generic_requires_baseline(self):
        self.assertEqual(cvp._generic_variants("", "C", ""), [])
        v = cvp._generic_variants("foo=__CANARY__", "PRAETOR-1234", "")
        self.assertGreaterEqual(len(v), 4)
        labels = [x["label"] for x in v]
        self.assertIn("gen.url_encoded", labels)
        self.assertIn("gen.double_url_encoded", labels)


class ScoringTest(unittest.TestCase):

    def test_canary_in_body_is_confirmed(self):
        verdict, conf, _ = cvp._score_response(
            "react_server_components", "PRAETOR-DEAD", 200, "",
            "Hello PRAETOR-DEAD world")
        self.assertEqual(verdict, "CONFIRMED")
        self.assertGreaterEqual(conf, 0.85)

    def test_canary_in_headers_is_confirmed(self):
        verdict, conf, _ = cvp._score_response(
            "react_server_components", "PRAETOR-BEEF", 200,
            "X-Echo: PRAETOR-BEEF", "")
        self.assertEqual(verdict, "CONFIRMED")

    def test_rsc_marker_with_500_is_suspected(self):
        verdict, conf, _ = cvp._score_response(
            "react_server_components", "PRAETOR-CAFE", 500, "",
            "React Flight decodeChunk parse failure")
        self.assertEqual(verdict, "SUSPECTED")
        self.assertGreaterEqual(conf, 0.55)

    def test_no_marker_no_canary_is_failed(self):
        verdict, conf, _ = cvp._score_response(
            "react_server_components", "PRAETOR-ZZZZ", 404, "",
            "Not Found")
        self.assertEqual(verdict, "FAILED")

    def test_sspp_typeerror_marker_hits(self):
        verdict, _, _ = cvp._score_response(
            "trpc_sspp", "X", 500, "",
            "TypeError: Cannot set property of prototype")
        self.assertEqual(verdict, "SUSPECTED")


class _AsyncRunner:
    @staticmethod
    def run(coro):
        return asyncio.get_event_loop().run_until_complete(coro) \
            if hasattr(asyncio.get_event_loop(), "_running") \
            else asyncio.new_event_loop().run_until_complete(coro)


class BoundedLoopTest(unittest.TestCase):

    def test_first_confirmed_short_circuits(self):
        tool = _get_tool()
        # Mock client.post: first variant returns canary echo (CONFIRMED) →
        # loop must stop, second variant must NOT be called.
        call_count = {"n": 0}

        async def fake_post(path, json):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return {
                    "status_code": 200,
                    "response_body": "PRAETOR-AAAAAAAA echoed back",
                    "response_headers": "",
                    "proxy_index": 42,
                }
            return {"status_code": 200, "response_body": "",
                    "response_headers": "", "proxy_index": 43}

        # Patch canary to a known value
        with patch.object(cvp, "_canary", return_value="PRAETOR-AAAAAAAA"), \
             patch.object(cvp.client, "post", side_effect=fake_post):
            result = asyncio.run(tool(
                cve_id="CVE-2025-55182",
                target_url="https://example.test/api/action",
                max_variants=12,
            ))
        self.assertEqual(result["verdict"], "CONFIRMED")
        self.assertEqual(call_count["n"], 1, "must short-circuit on first CONFIRMED")
        self.assertIn(42, result["logger_indices"])

    def test_max_variants_is_a_hard_cap(self):
        tool = _get_tool()
        call_count = {"n": 0}

        async def fake_post(path, json):
            call_count["n"] += 1
            return {"status_code": 404, "response_body": "Not Found",
                    "response_headers": "", "proxy_index": call_count["n"]}

        with patch.object(cvp.client, "post", side_effect=fake_post):
            result = asyncio.run(tool(
                cve_id="CVE-2025-55182",
                target_url="https://example.test/api/action",
                max_variants=2,  # hard cap
            ))
        self.assertLessEqual(call_count["n"], 2,
                             "must respect max_variants hard cap")
        self.assertEqual(result["verdict"], "FAILED")

    def test_missing_target_url_returns_error(self):
        tool = _get_tool()
        result = asyncio.run(tool(cve_id="CVE-2025-55182", target_url=""))
        self.assertEqual(result["verdict"], "ERROR")

    def test_missing_cve_and_class_returns_error(self):
        tool = _get_tool()
        result = asyncio.run(tool(cve_id="", target_url="https://x.test/"))
        self.assertEqual(result["verdict"], "ERROR")

    def test_generic_class_without_baseline_returns_error(self):
        tool = _get_tool()
        result = asyncio.run(tool(
            cve_id="CVE-9999-99999",
            target_url="https://x.test/",
        ))
        self.assertEqual(result["verdict"], "ERROR")
        self.assertIn("baseline_payload", result["details"]["error"])


class RegistrationAndRoutingTest(unittest.TestCase):

    def test_tool_registers(self):
        stub, captured = _stub_mcp()
        cvp.register(stub)
        self.assertIn("probe_cve_with_variants", captured)

    def test_pick_tool_routes_react2shell(self):
        from burpsuite_mcp.tools.advisor.pick_tool import _MAPPINGS
        match = None
        for keywords, tool_name, _ex in _MAPPINGS:
            if any(k == "react2shell" for k in keywords):
                match = tool_name
                break
        self.assertEqual(match, "probe_cve_with_variants")

    def test_pick_tool_routes_cve_id(self):
        from burpsuite_mcp.tools.advisor.pick_tool import _MAPPINGS
        match = None
        for keywords, tool_name, _ex in _MAPPINGS:
            if "cve-2025-55182" in keywords:
                match = tool_name
                break
        self.assertEqual(match, "probe_cve_with_variants")


if __name__ == "__main__":
    unittest.main()
