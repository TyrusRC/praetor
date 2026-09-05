import unittest

from praetor.tools.offline import _report


class TestReportHelpers(unittest.TestCase):
    def test_redact_shows_only_shape(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        red = _report.redact_secret(secret)
        self.assertNotIn(secret, red)
        self.assertTrue(red.startswith("AKIA"))
        self.assertTrue(red.endswith("MPLE"))
        self.assertIn("…", red)

    def test_redact_short_value_fully_masked(self):
        self.assertEqual(_report.redact_secret("abc"), "…")

    def test_confine_path_rejects_traversal(self):
        root = "/home/kali/project/trc/praetor/mcp-server/tests/fixtures/offline"
        self.assertIsNone(_report.confine_path(root, root + "/../../../etc/passwd"))

    def test_assemble_fills_missing_keys(self):
        out = _report.assemble("js", "app.js", {"secrets": [{"type": "aws"}]})
        self.assertEqual(out["kind"], "js")
        self.assertEqual(out["source"], "app.js")
        self.assertEqual(out["secrets"], [{"type": "aws"}])
        for k in ("attack_surface", "api_inventory", "inputs", "id_references",
                  "sources_sinks", "observations", "hypotheses", "priority_test_plan"):
            self.assertEqual(out[k], [])


import json
import os

from praetor.tools.offline import _raw_request

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "offline")


class TestRawRequest(unittest.TestCase):
    def _parse(self):
        with open(os.path.join(FIX, "signup.txt"), encoding="utf-8") as fh:
            return _raw_request.parse_raw_request(fh.read())

    def test_extracts_body_inputs(self):
        names = {i["name"] for i in self._parse()["inputs"]}
        self.assertTrue({"role", "inviteCode", "referrer", "email"} <= names)

    def test_flags_role_as_privilege_hypothesis(self):
        claims = " ".join(h["claim"].lower() for h in self._parse()["hypotheses"])
        self.assertIn("role", claims)

    def test_detects_jwt_session_cookie_observation(self):
        obs = " ".join(self._parse()["observations"]).lower()
        self.assertIn("session", obs)

    def test_no_raw_secret_in_output(self):
        out = self._parse()
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9.demo.session", json.dumps(out))


class TestJsExtract(unittest.TestCase):
    def _scan_app(self):
        from praetor.tools.offline import _js_extract
        with open(os.path.join(FIX, "app.js"), encoding="utf-8") as fh:
            return _js_extract.scan_js(fh.read(), "app.js")

    def test_extracts_endpoints(self):
        eps = {e["endpoint"] for e in self._scan_app()["api_inventory"]}
        self.assertIn("/api/admin/users", eps)
        self.assertIn("/api/orders", eps)

    def test_secret_detected_and_redacted(self):
        secs = self._scan_app()["secrets"]
        shapes = {s["shape"] for s in secs}
        self.assertTrue(any(sh.startswith("AKIA") for sh in shapes))
        blob = json.dumps(secs)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", blob)
        self.assertNotIn("sk-abc123def456ghi789jkl012mno345pqr678stu9", blob)

    def test_admin_route_flagged_in_attack_surface(self):
        surf = " ".join(a["why"].lower() for a in self._scan_app()["attack_surface"])
        self.assertIn("admin", surf)

    def test_dom_sink_source_captured(self):
        ss = json.dumps(self._scan_app()["sources_sinks"]).lower()
        self.assertIn("innerhtml", ss)

    def test_merge_dedupes_shared_endpoint(self):
        from praetor.tools.offline import _js_extract
        with open(os.path.join(FIX, "dir", "a.js")) as fa, \
                open(os.path.join(FIX, "dir", "b.js")) as fb:
            merged = _js_extract.merge_js_results([
                _js_extract.scan_js(fa.read(), "a.js"),
                _js_extract.scan_js(fb.read(), "b.js"),
            ])
        eps = [e["endpoint"] for e in merged["api_inventory"]]
        self.assertEqual(eps.count("/api/shared/resource"), 1)


class TestDetectAndProject(unittest.TestCase):
    def test_detect_kind(self):
        from praetor.tools.offline import _detect
        self.assertEqual(_detect.detect_kind("https://x/app.js"), "js_url")
        self.assertEqual(_detect.detect_kind(os.path.join(FIX, "signup.txt")), "raw_request")
        self.assertEqual(_detect.detect_kind(os.path.join(FIX, "app.js")), "js")
        self.assertEqual(_detect.detect_kind(os.path.join(FIX, "dir")), "js_dir")
        self.assertEqual(_detect.detect_kind(os.path.join(FIX, "project")), "project")

    def test_project_correlates_and_plans(self):
        from praetor.tools.offline import _project
        out = _project.correlate_project(os.path.join(FIX, "project"))
        eps = {e["endpoint"] for e in out["api_inventory"]}
        self.assertIn("/api/shared/resource", eps)
        self.assertTrue(out["hypotheses"])
        self.assertTrue(out["priority_test_plan"])


import asyncio

from praetor.tools.offline import entry


class TestAnalyzeArtifact(unittest.TestCase):
    def _run(self, **kw):
        return asyncio.run(entry.analyze_artifact(**kw))

    def test_routes_raw_request(self):
        out = self._run(source=os.path.join(FIX, "signup.txt"))
        self.assertEqual(out["kind"], "raw_request")
        self.assertTrue(out["inputs"])

    def test_routes_js_dir_with_dedupe(self):
        out = self._run(source=os.path.join(FIX, "dir"))
        self.assertEqual(out["kind"], "js_dir")
        eps = [e["endpoint"] for e in out["api_inventory"]]
        self.assertEqual(eps.count("/api/shared/resource"), 1)

    def test_oversized_file_skipped_gracefully(self):
        from praetor.tools.offline import _report
        original = _report.MAX_FILE_BYTES
        _report.MAX_FILE_BYTES = 10
        try:
            out = self._run(source=os.path.join(FIX, "app.js"), kind="js")
            self.assertEqual(out["kind"], "js")
            self.assertIn("skipped", json.dumps(out).lower())
        finally:
            _report.MAX_FILE_BYTES = original

    def test_missing_source_returns_error_not_crash(self):
        out = self._run(source="/nonexistent/path.js")
        self.assertIn("error", out)
