"""W36 frontier work — pure helper + filesystem coverage.

Scope (per task): test only the PURE helpers / filesystem paths. No Burp
client, no network. The HTTP/3 race tool, export_proof_capsule, and any tool
that fetches from 127.0.0.1:8111 are NOT invoked — their extracted helpers are.

Covers:
  1. race_singlepacket: _tally_race per-stream tally + _ALT_SVC_H3_RE + the
     verdict_from_tally contract it feeds.
  2. sast_handoff: _scan_source_tree / _route_from_match / _dedupe_routes
     across Flask/FastAPI, Express, Spring.
  3. report/business_logic_gate: business_logic_gate warn/None states +
     record_business_logic_test upsert.
  4. notes/poc_bundle: export_proof_capsule pure oracle path (_oracle_spec,
     _raw_request).
  5. easm/findings_diff: scope_targets_to_diff scopes to CHANGED targets only.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import unittest
from pathlib import Path

from burpsuite_mcp.tools.notes._helpers import _intel_dir, _sanitized


class _ToolCapture:
    """Minimal FastMCP stand-in: capture @mcp.tool()-decorated coroutines."""

    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self, *args, **kwargs):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


# ---------------------------------------------------------------------------
# 1. race_singlepacket — pure tally + regex + verdict contract
# ---------------------------------------------------------------------------
class RaceSinglepacketTest(unittest.TestCase):
    def test_tally_race_counts_2xx_and_status_dist(self):
        from burpsuite_mcp.tools.testing.race_singlepacket import _tally_race

        stream_ids = [1, 3, 5]
        results = {
            1: {"status": 200, "time_ns": 5_000_000, "length": 12, "body_preview": "ok"},
            3: {"status": 200, "time_ns": 6_000_000, "length": 12, "body_preview": "ok"},
            5: {"status": 403, "time_ns": 4_000_000, "length": 9, "body_preview": "no"},
        }
        statuses, success_count, time_samples, lines = _tally_race(stream_ids, results)
        self.assertEqual(success_count, 2)
        self.assertEqual(statuses, {200: 2, 403: 1})
        self.assertEqual(len(time_samples), 3)
        self.assertEqual(len(lines), 3)

    def test_tally_race_missing_stream_and_timeout(self):
        from burpsuite_mcp.tools.testing.race_singlepacket import _tally_race

        stream_ids = [1, 7]
        # stream 7 absent from results -> status 0, no time sample.
        results = {1: {"status": 201, "time_ns": -1, "length": 3, "body_preview": ""}}
        statuses, success_count, time_samples, _ = _tally_race(stream_ids, results)
        self.assertEqual(success_count, 1)          # 201 is 2xx
        self.assertEqual(statuses.get(0), 1)        # missing stream tallied as 0
        self.assertEqual(time_samples, [])          # time_ns -1 excluded

    def test_alt_svc_h3_regex_matches_h3(self):
        from burpsuite_mcp.tools.testing.race_singlepacket import _ALT_SVC_H3_RE

        m = _ALT_SVC_H3_RE.search('h3=":443"; ma=86400')
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), ":443")
        # draft label with version suffix
        self.assertIsNotNone(_ALT_SVC_H3_RE.search('h3-29=":443"'))

    def test_alt_svc_h3_regex_no_match_plain(self):
        from burpsuite_mcp.tools.testing.race_singlepacket import _ALT_SVC_H3_RE

        # h2-only Alt-Svc advertisement — no QUIC/h3 listener.
        self.assertIsNone(_ALT_SVC_H3_RE.search('h2=":443"; ma=3600'))
        self.assertIsNone(_ALT_SVC_H3_RE.search("max-age=3600"))

    def test_verdict_from_tally_contract(self):
        # The canonical 0/1/2+ mapping the race success_count feeds.
        from burpsuite_mcp.tools.testing._verdict import verdict_from_tally

        self.assertEqual(verdict_from_tally(0)[0], "FAILED")
        self.assertEqual(verdict_from_tally(1)[0], "SUSPECTED")
        self.assertEqual(verdict_from_tally(2)[0], "CONFIRMED")
        self.assertEqual(verdict_from_tally(9)[0], "CONFIRMED")


# ---------------------------------------------------------------------------
# 2. sast_handoff — source route extraction
# ---------------------------------------------------------------------------
class SastRouteExtractionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(
            __import__("tempfile").mkdtemp(prefix="w36-sast-")
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _write(self, rel: str, text: str) -> None:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def test_scan_extracts_multiframework_routes(self):
        from burpsuite_mcp.tools.sast_handoff import _scan_source_tree

        self._write("app.py", "@app.get('/x')\ndef x():\n    return 1\n")
        self._write("routes.js", "router.post('/y', handler)\n")
        self._write("Ctrl.java", '@GetMapping("/z")\npublic String z() { return \"\"; }\n')

        routes, files_scanned = _scan_source_tree(self.root, max_files=100)
        self.assertGreaterEqual(files_scanned, 3)
        got = {(r["method"], r["path"]) for r in routes}
        self.assertIn(("GET", "/x"), got)
        self.assertIn(("POST", "/y"), got)
        self.assertIn(("GET", "/z"), got)
        # spring_method normalises framework name to "spring"
        spring = next(r for r in routes if r["path"] == "/z")
        self.assertEqual(spring["framework"], "spring")
        # source pointer is file:line
        self.assertRegex(spring["source"], r":\d+$")

    def test_scan_skips_pruned_dirs(self):
        from burpsuite_mcp.tools.sast_handoff import _scan_source_tree

        self._write("real.py", "@app.get('/keep')\ndef k(): pass\n")
        self._write("node_modules/dep.js", "app.get('/vendor', h)\n")

        routes, _ = _scan_source_tree(self.root, max_files=100)
        paths = {r["path"] for r in routes}
        self.assertIn("/keep", paths)
        self.assertNotIn("/vendor", paths)  # node_modules pruned

    def test_route_from_match_per_framework(self):
        from burpsuite_mcp.tools.sast_handoff import _ROUTE_PATTERNS, _route_from_match

        patterns = dict(_ROUTE_PATTERNS)
        m_fa = patterns["fastapi"].search("@app.get('/x')")
        self.assertEqual(_route_from_match("fastapi", m_fa),
                         {"framework": "fastapi", "method": "GET", "path": "/x"})
        m_ex = patterns["express"].search("router.post('/y', handler)")
        self.assertEqual(_route_from_match("express", m_ex),
                         {"framework": "express", "method": "POST", "path": "/y"})
        m_sp = patterns["spring_method"].search('@GetMapping("/z")')
        self.assertEqual(_route_from_match("spring_method", m_sp),
                         {"framework": "spring", "method": "GET", "path": "/z"})
        # Flask methods=[...] extraction
        m_fl = patterns["flask"].search("@app.route('/f', methods=['POST'])")
        self.assertEqual(_route_from_match("flask", m_fl),
                         {"framework": "flask", "method": "POST", "path": "/f"})

    def test_dedupe_collapses_duplicates(self):
        from burpsuite_mcp.tools.sast_handoff import _dedupe_routes

        routes = [
            {"method": "GET", "path": "/x", "framework": "fastapi", "source": "a.py:1"},
            {"method": "get", "path": "/x", "framework": "fastapi", "source": "b.py:9"},
            {"method": "POST", "path": "/x", "framework": "fastapi", "source": "c.py:2"},
        ]
        out = _dedupe_routes(routes)
        keys = {(r["method"].upper(), r["path"]) for r in out}
        self.assertEqual(keys, {("GET", "/x"), ("POST", "/x")})
        # first source wins for the collapsed GET /x pair
        get_row = next(r for r in out if r["method"].upper() == "GET")
        self.assertEqual(get_row["source"], "a.py:1")


# ---------------------------------------------------------------------------
# 3. business_logic_gate — completion gate + upsert
# ---------------------------------------------------------------------------
class BusinessLogicGateTest(unittest.TestCase):
    DOMAIN = "w36-bizlogic.test-throwaway.example"

    def tearDown(self) -> None:
        shutil.rmtree(_intel_dir() / _sanitized(self.DOMAIN), ignore_errors=True)

    def _record_tool(self):
        from burpsuite_mcp.tools.report import business_logic_gate as mod
        cap = _ToolCapture()
        mod.register(cap)
        return cap.tools["record_business_logic_test"]

    def test_gate_warns_when_absent(self):
        from burpsuite_mcp.tools.report.business_logic_gate import business_logic_gate
        warn = business_logic_gate(self.DOMAIN)
        self.assertIsNotNone(warn)
        self.assertIn("no testcase matrix", warn)

    def test_gate_warns_on_zero_tested_then_none_after_test(self):
        from burpsuite_mcp.tools.report.business_logic_gate import business_logic_gate

        record = self._record_tool()
        # Seed an UNtested row -> matrix present, 0 tested -> still warns.
        asyncio.run(record(self.DOMAIN, "coupon one-use", "/api/redeem",
                            "", False))
        warn = business_logic_gate(self.DOMAIN)
        self.assertIsNotNone(warn)
        self.assertIn("0 are tested", warn)

        # Now mark a tested invariant -> gate clears.
        asyncio.run(record(self.DOMAIN, "coupon one-use", "/api/redeem", "held", True))
        self.assertIsNone(business_logic_gate(self.DOMAIN))

    def test_record_upsert_in_place_vs_append(self):
        from burpsuite_mcp.tools.report.business_logic_gate import _matrix_path

        record = self._record_tool()
        asyncio.run(record(self.DOMAIN, "refund idempotent", "/api/refund", "held", True))
        # same (invariant, endpoint) -> update in place, not a new row.
        asyncio.run(record(self.DOMAIN, "refund idempotent", "/api/refund",
                           "bypassed", True))
        # distinct endpoint -> append.
        asyncio.run(record(self.DOMAIN, "refund idempotent", "/api/refund/v2",
                           "held", True))

        data = json.loads(_matrix_path(self.DOMAIN).read_text(encoding="utf-8"))
        rows = data["invariants"]
        self.assertEqual(len(rows), 2)
        first = next(r for r in rows if r["endpoint"] == "/api/refund")
        self.assertEqual(first["result"], "bypassed")  # in-place overwrite

    def test_gate_empty_domain_returns_none(self):
        from burpsuite_mcp.tools.report.business_logic_gate import business_logic_gate
        self.assertIsNone(business_logic_gate(""))


# ---------------------------------------------------------------------------
# 4. poc_bundle — export_proof_capsule pure oracle path
# ---------------------------------------------------------------------------
class ProofCapsuleOracleTest(unittest.TestCase):
    def test_oracle_markers_class(self):
        from burpsuite_mcp.tools.notes.poc_bundle import _oracle_spec
        finding = {"vuln_type": "sqli", "endpoint": "https://t.example/api?q=1",
                   "evidence": {}}
        req = {"url": "https://t.example/api?q=1", "method": "GET"}
        oracle = _oracle_spec(finding, req)
        self.assertEqual(oracle["verdict_kind"], "markers")
        self.assertIn("mysql", oracle["markers"])
        self.assertEqual(oracle["vuln_class"], "sqli")

    def test_oracle_timing_class(self):
        from burpsuite_mcp.tools.notes.poc_bundle import _oracle_spec
        finding = {"vuln_type": "sqli_blind", "endpoint": "https://t.example/x",
                   "evidence": {}}
        oracle = _oracle_spec(finding, {"url": "https://t.example/x"})
        self.assertEqual(oracle["verdict_kind"], "timing")
        self.assertEqual(oracle["timing_threshold_ms"], 4000)

    def test_oracle_collaborator_class(self):
        from burpsuite_mcp.tools.notes.poc_bundle import _oracle_spec
        finding = {"vuln_type": "ssrf_blind",
                   "evidence": {"collaborator_interaction_id": "abc123.oast"}}
        oracle = _oracle_spec(finding, {"url": "https://t.example/x"})
        self.assertEqual(oracle["verdict_kind"], "collaborator")
        self.assertEqual(oracle["collaborator_interaction_id"], "abc123.oast")

    def test_oracle_baseline_delta_fallback(self):
        from burpsuite_mcp.tools.notes.poc_bundle import _oracle_spec
        # unknown class, no collab, no timing -> baseline delta oracle.
        finding = {"vuln_type": "weird_anomaly",
                   "evidence": {"baseline": {"status": 200, "length": 1000}}}
        oracle = _oracle_spec(finding, {"url": "https://t.example/x"})
        self.assertEqual(oracle["verdict_kind"], "baseline_delta")
        self.assertEqual(oracle["baseline"], {"status": 200, "length": 1000})

    def test_raw_request_bytes(self):
        from burpsuite_mcp.tools.notes.poc_bundle import _raw_request
        raw = _raw_request({"method": "post", "url": "https://t.example/api/x?a=1",
                            "headers": {"X-Test": "v"}, "body": "hi"})
        self.assertTrue(raw.startswith(b"POST /api/x?a=1 HTTP/1.1\r\n"))
        self.assertIn(b"Host: t.example", raw)
        self.assertIn(b"X-Test: v", raw)
        self.assertTrue(raw.endswith(b"hi"))


# ---------------------------------------------------------------------------
# 5. findings_diff — scope_targets_to_diff scopes to CHANGED targets only
# ---------------------------------------------------------------------------
class ScopeTargetsToDiffTest(unittest.TestCase):
    DOMAIN = "w36-scopediff.test-throwaway.example"

    def setUp(self) -> None:
        from burpsuite_mcp.tools.easm import findings_diff as mod
        cap = _ToolCapture()
        mod.register(cap)
        self.scope = cap.tools["scope_targets_to_diff"]
        # Seed endpoints.json at the domain root.
        root = _intel_dir() / _sanitized(self.DOMAIN)
        root.mkdir(parents=True, exist_ok=True)
        (root / "endpoints.json").write_text(json.dumps({"endpoints": [
            {"path": "/api/users", "method": "GET", "parameters": ["id"]},
            {"path": "/api/orders", "method": "POST", "parameters": ["oid"]},
            {"path": "/api/admin/settings", "method": "GET", "parameters": []},
        ]}), encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(_intel_dir() / _sanitized(self.DOMAIN), ignore_errors=True)

    def test_scopes_to_changed_endpoint_only(self):
        out = asyncio.run(self.scope(self.DOMAIN, ["/api/users"]))
        endpoints = {t["endpoint"] for t in out["matched_targets"]}
        self.assertEqual(endpoints, {"/api/users"})
        # unchanged endpoints excluded
        self.assertNotIn("/api/orders", endpoints)
        self.assertNotIn("/api/admin/settings", endpoints)

    def test_param_filter_narrows_to_named_param(self):
        out = asyncio.run(self.scope(self.DOMAIN, ["/api/users?id"]))
        params = {t["parameter"] for t in out["matched_targets"]}
        self.assertEqual(params, {"id"})

    def test_unmatched_changed_reported(self):
        out = asyncio.run(self.scope(self.DOMAIN, ["/api/nonexistent"]))
        self.assertEqual(out["matched_targets"], [])
        self.assertIn("/api/nonexistent", out["unmatched_changed"])

    def test_empty_endpoints_store_returns_note(self):
        # A different throwaway domain with no endpoints.json.
        empty_dom = "w36-scopediff-empty.test-throwaway.example"
        try:
            out = asyncio.run(self.scope(empty_dom, ["/api/x"]))
            self.assertEqual(out["matched_targets"], [])
            self.assertIn("no endpoints.json", out["note"])
        finally:
            shutil.rmtree(_intel_dir() / _sanitized(empty_dom), ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
