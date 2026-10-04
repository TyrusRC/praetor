"""Codex / eager-host optimizations: description slimming + the codex profile.

Covers the manifest-trimming logic (first_sentence, slim_descriptions, the
opt-in/auto gate) and that the `codex` profile resolves to a lean lane set.
"""

import os
import unittest

from praetor import _lanes
from praetor import _schema_slim as S


class _T:
    def __init__(self, desc):
        self.description = desc
        self.parameters = {}


class _MCP:
    def __init__(self, tools):
        class _M:
            pass
        self._tool_manager = _M()
        self._tool_manager._tools = tools


class FirstSentenceTest(unittest.TestCase):

    def test_first_line_of_multiline(self):
        self.assertEqual(S.first_sentence("Summary line.\n\nLong body here."), "Summary line.")

    def test_long_first_line_cut_to_sentence(self):
        line = "This is the summary sentence. " + ("x" * 200)
        self.assertEqual(S.first_sentence(line), "This is the summary sentence.")

    def test_empty(self):
        self.assertEqual(S.first_sentence(""), "")


class SlimDescriptionsTest(unittest.TestCase):

    def test_trims_only_multiline_and_counts(self):
        mcp = _MCP({"a": _T("Do a thing.\n\nArgs: ..."), "b": _T("Short one-liner.")})
        n = S.slim_descriptions(mcp, enabled=True)
        self.assertEqual(n, 1)                      # only 'a' changed
        self.assertEqual(mcp._tool_manager._tools["a"].description, "Do a thing.")
        self.assertEqual(mcp._tool_manager._tools["b"].description, "Short one-liner.")

    def test_disabled_is_noop(self):
        mcp = _MCP({"a": _T("Do a thing.\n\nArgs: ...")})
        self.assertEqual(S.slim_descriptions(mcp, enabled=False), 0)
        self.assertIn("Args", mcp._tool_manager._tools["a"].description)


class ShouldSlimTest(unittest.TestCase):

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in ("PRAETOR_SLIM_DESCRIPTIONS", "PRAETOR_PROFILE")}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_explicit_on(self):
        os.environ["PRAETOR_SLIM_DESCRIPTIONS"] = "1"
        os.environ["PRAETOR_PROFILE"] = "all"
        self.assertTrue(S.should_slim_descriptions())

    def test_explicit_off_overrides_profile(self):
        os.environ["PRAETOR_SLIM_DESCRIPTIONS"] = "0"
        os.environ["PRAETOR_PROFILE"] = "codex"
        self.assertFalse(S.should_slim_descriptions())

    def test_auto_on_for_lean_profile(self):
        os.environ.pop("PRAETOR_SLIM_DESCRIPTIONS", None)
        os.environ["PRAETOR_PROFILE"] = "codex"
        self.assertTrue(S.should_slim_descriptions())

    def test_auto_off_for_all(self):
        os.environ.pop("PRAETOR_SLIM_DESCRIPTIONS", None)
        os.environ["PRAETOR_PROFILE"] = "all"
        self.assertFalse(S.should_slim_descriptions())


class CodexProfileTest(unittest.TestCase):

    def test_codex_resolves_to_web_lane(self):
        self.assertEqual(_lanes.resolve_lanes("codex"), {"web"})

    def test_codex_is_a_named_profile(self):
        self.assertIn("codex", _lanes.PROFILES)


if __name__ == "__main__":
    unittest.main()
