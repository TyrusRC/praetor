"""W31-d — commercial DAST gap closure.

Covers:
- probe_graphql_csrf — Burp 2026.6 parity (helpers + JSON-shape detection)
- probe_struts2_ognl — Rapid7 May 2026 parity (arithmetic marker + stack markers)
- enumerate_mcp_server — ZAP May 2026 parity (JSON-RPC body parser + summarisers)
- predict_paths_from_crawl — Invicti AI crawler parity (5 heuristics)
- ssti_java.json got OGNL/SpEL contexts (KB-org rule, no new sibling file)
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

KB_DIR = Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "knowledge"


class GraphqlCsrfHelpersTest(unittest.TestCase):
    def test_is_graphql_response_data(self):
        from burpsuite_mcp.tools.graphql_csrf_probe import _is_graphql_response
        self.assertTrue(_is_graphql_response('{"data":{"__typename":"Query"}}'))

    def test_is_graphql_response_errors(self):
        from burpsuite_mcp.tools.graphql_csrf_probe import _is_graphql_response
        self.assertTrue(_is_graphql_response('{"errors":[{"message":"x"}]}'))

    def test_is_graphql_response_non_json(self):
        from burpsuite_mcp.tools.graphql_csrf_probe import _is_graphql_response
        self.assertFalse(_is_graphql_response("hello world"))
        self.assertFalse(_is_graphql_response(""))

    def test_is_graphql_response_unrelated_json(self):
        from burpsuite_mcp.tools.graphql_csrf_probe import _is_graphql_response
        self.assertFalse(_is_graphql_response('{"status":"ok"}'))


class Struts2OgnlTest(unittest.TestCase):
    def test_arithmetic_marker_is_canonical(self):
        from burpsuite_mcp.tools.struts2_ognl_probe import _ARITHMETIC_MARKER
        # 1337 * 1338 = 1788706 — invariant
        self.assertEqual(_ARITHMETIC_MARKER, str(1337 * 1338))

    def test_payload_coverage(self):
        from burpsuite_mcp.tools.struts2_ognl_probe import _OGNL_PAYLOADS
        engines = [e for e, _ in _OGNL_PAYLOADS]
        self.assertIn("ognl_curly", engines)
        self.assertIn("ognl_at", engines)
        self.assertIn("spel_hash", engines)
        self.assertIn("spel_t", engines)
        self.assertGreaterEqual(len(_OGNL_PAYLOADS), 6)

    def test_stack_marker_detect(self):
        from burpsuite_mcp.tools.struts2_ognl_probe import _has_ognl_stack_marker
        self.assertTrue(_has_ognl_stack_marker("... ognl.OgnlException ..."))
        self.assertTrue(_has_ognl_stack_marker("org.springframework.expression.spel.SpelEvaluationException"))
        self.assertFalse(_has_ognl_stack_marker("plain old 500"))

    def test_ssti_java_carries_ognl_contexts(self):
        kb = json.loads((KB_DIR / "ssti_java.json").read_text())
        ctx = kb.get("contexts", {})
        self.assertIn("struts2_ognl_url_param", ctx)
        self.assertIn("spel_arithmetic_echo", ctx)


class McpEnumerateTest(unittest.TestCase):
    def test_parse_jsonrpc_raw_json(self):
        from burpsuite_mcp.tools.mcp_enumerate import _parse_jsonrpc_body
        body = '{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"x"}}}'
        out = _parse_jsonrpc_body(body)
        self.assertIsNotNone(out)
        self.assertEqual(out["result"]["serverInfo"]["name"], "x")

    def test_parse_jsonrpc_sse_wrapped(self):
        from burpsuite_mcp.tools.mcp_enumerate import _parse_jsonrpc_body
        body = 'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n\n'
        out = _parse_jsonrpc_body(body)
        self.assertIsNotNone(out)
        self.assertEqual(out["result"]["ok"], True)

    def test_parse_jsonrpc_invalid(self):
        from burpsuite_mcp.tools.mcp_enumerate import _parse_jsonrpc_body
        self.assertIsNone(_parse_jsonrpc_body("not json"))
        self.assertIsNone(_parse_jsonrpc_body(""))

    def test_summarise_tool_truncates(self):
        from burpsuite_mcp.tools.mcp_enumerate import _summarise_tool
        long_desc = "x" * 1000
        out = _summarise_tool({
            "name": "do_thing",
            "description": long_desc,
            "inputSchema": {
                "required": ["a"],
                "properties": {"a": {}, "b": {}, "c": {}},
            },
        })
        self.assertEqual(out["name"], "do_thing")
        self.assertLessEqual(len(out["description"]), 240)
        self.assertEqual(out["input_schema_summary"]["required"], ["a"])
        self.assertEqual(out["input_schema_summary"]["param_names"], ["a", "b", "c"])

    def test_summarise_resource(self):
        from burpsuite_mcp.tools.mcp_enumerate import _summarise_resource
        out = _summarise_resource({
            "uri": "file:///x",
            "name": "x",
            "mimeType": "text/plain",
        })
        self.assertEqual(out["uri"], "file:///x")
        self.assertEqual(out["mime_type"], "text/plain")

    def test_summarise_prompt_arg_counting(self):
        from burpsuite_mcp.tools.mcp_enumerate import _summarise_prompt
        out = _summarise_prompt({
            "name": "p",
            "arguments": [{"name": "x"}, {"name": "y"}, {"name": "z"}],
        })
        self.assertEqual(out["arg_count"], 3)
        self.assertEqual(out["arg_names"], ["x", "y", "z"])


class PredictPathsTest(unittest.TestCase):
    def test_normalise(self):
        from burpsuite_mcp.tools.predict_paths import _normalise
        self.assertEqual(_normalise("/api/v1/users/123"), "/api/v1/users/<id>")
        self.assertEqual(_normalise("/api/v1/users/123?next=/"), "/api/v1/users/<id>")
        self.assertEqual(
            _normalise("/api/v1/users/12345678-1234-1234-1234-123456789012"),
            "/api/v1/users/<uuid>",
        )

    def test_plural_singular_predictions(self):
        from burpsuite_mcp.tools.predict_paths import _predict_plural_singular
        predictions: dict = {}
        _predict_plural_singular(
            {"/api/users"},
            {"/api/users"},
            predictions,
        )
        # Expect /user/<id> materialised and /user/me predictions
        paths = list(predictions.keys())
        self.assertTrue(any("/user/me" in p for p in paths))

    def test_version_siblings(self):
        from burpsuite_mcp.tools.predict_paths import _predict_version_siblings
        predictions: dict = {}
        _predict_version_siblings(
            {"/api/v2/users"},
            {"/api/v2/users"},
            predictions,
        )
        paths = list(predictions.keys())
        self.assertTrue(any("/v1/" in p for p in paths))
        self.assertTrue(any("/v3/" in p for p in paths))

    def test_high_value_counterparts(self):
        from burpsuite_mcp.tools.predict_paths import _predict_high_value_counterparts
        predictions: dict = {}
        _predict_high_value_counterparts(
            {"/api/users"},
            {"/api/users"},
            predictions,
        )
        paths = list(predictions.keys())
        self.assertTrue(any("/admin/api/" in p for p in paths))
        self.assertTrue(any("/internal/api/" in p for p in paths))

    def test_id_shape_list_counterpart(self):
        from burpsuite_mcp.tools.predict_paths import _predict_id_shape_counterparts
        predictions: dict = {}
        _predict_id_shape_counterparts(
            set(),
            {"/api/users/<id>"},
            predictions,
        )
        # Note: this heuristic reads `known` for raw input — fix:
        # the impl iterates `known` arg, not normalised. So pass paths
        # whose _normalise produces /<id> form.
        # Re-test with raw-path input:
        from burpsuite_mcp.tools.predict_paths import _predict_id_shape_counterparts as _f
        predictions2: dict = {}
        _f({"/api/users/123"}, {"/api/users/<id>"}, predictions2)
        paths = list(predictions2.keys())
        self.assertIn("/api/users", paths)
        self.assertIn("/api/users/me", paths)

    def test_verb_pair_predictions(self):
        from burpsuite_mcp.tools.predict_paths import _predict_verb_counterparts
        predictions: dict = {}
        _predict_verb_counterparts(
            {"/api/orders/get"},
            {"/api/orders/get"},
            predictions,
        )
        paths = list(predictions.keys())
        self.assertTrue(any(p.endswith("/create") for p in paths))
        self.assertTrue(any(p.endswith("/update") for p in paths))
        self.assertTrue(any(p.endswith("/delete") for p in paths))


class W31dToolsImportableTest(unittest.TestCase):
    def test_all_imports(self):
        from burpsuite_mcp.tools import graphql_csrf_probe, struts2_ognl_probe, mcp_enumerate, predict_paths
        for mod in (graphql_csrf_probe, struts2_ognl_probe, mcp_enumerate, predict_paths):
            self.assertTrue(hasattr(mod, "register"))


if __name__ == "__main__":
    unittest.main()
