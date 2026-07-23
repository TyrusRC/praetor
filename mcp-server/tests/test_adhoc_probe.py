"""F1 — run_adhoc_probe validation (matcher allowlist + Rule-5 fail-closed)."""
import unittest

from burpsuite_mcp.tools.adhoc_probe import validate_probe_context, KNOWN_MATCHER_TYPES


class ValidateProbeContextTest(unittest.TestCase):
    def test_valid_probe_passes(self):
        ctx = {"probes": [{
            "payload": "{{1336+1}}",
            "matchers": [{"type": "word", "words": ["1337"]},
                         {"type": "status", "status": [200]}],
        }]}
        ok, errors = validate_probe_context(ctx)
        self.assertTrue(ok, errors)
        self.assertEqual(errors, [])

    def test_unknown_matcher_type_fails_closed(self):
        ctx = {"probes": [{"payload": "x",
                           "matchers": [{"type": "telepathy"}]}]}
        ok, errors = validate_probe_context(ctx)
        self.assertFalse(ok)
        self.assertTrue(any("unknown matcher type" in e for e in errors))

    def test_destructive_payload_rejected(self):
        ctx = {"probes": [{"payload": "'; DROP TABLE users;--",
                           "matchers": [{"type": "status", "status": [500]}]}]}
        ok, errors = validate_probe_context(ctx)
        self.assertFalse(ok)
        self.assertTrue(any("Rule 5" in e for e in errors))

    def test_no_matchers_fails(self):
        ok, errors = validate_probe_context({"probes": [{"payload": "x", "matchers": []}]})
        self.assertFalse(ok)

    def test_empty_probes_fails(self):
        ok, errors = validate_probe_context({"probes": []})
        self.assertFalse(ok)

    def test_missing_payload_flagged(self):
        ok, errors = validate_probe_context(
            {"probes": [{"matchers": [{"type": "regex", "pattern": "x"}]}]})
        self.assertFalse(ok)
        self.assertTrue(any("missing 'payload'" in e for e in errors))

    def test_allowlist_matches_engine(self):
        # Guard: these must stay in sync with MatcherEngine.KNOWN_MATCHER_TYPES.
        self.assertIn("differential_timing", KNOWN_MATCHER_TYPES)
        self.assertIn("collaborator", KNOWN_MATCHER_TYPES)
        self.assertIn("valid_vs_invalid_baseline", KNOWN_MATCHER_TYPES)


if __name__ == "__main__":
    unittest.main()
