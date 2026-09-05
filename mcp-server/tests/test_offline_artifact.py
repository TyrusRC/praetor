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
