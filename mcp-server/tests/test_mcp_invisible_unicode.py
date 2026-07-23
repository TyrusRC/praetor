"""D1 — invisible-unicode MCP tool-metadata detector."""
import unittest

from burpsuite_mcp.tools.mcp_invisible_unicode import (
    find_hidden_unicode,
    scan_tool_metadata,
)


class FindHiddenUnicodeTest(unittest.TestCase):
    def test_tag_block_detected(self):
        # U+E0041 is TAG LATIN CAPITAL LETTER A (concealment channel).
        hits = find_hidden_unicode("safe\U000E0041text")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["category"], "tag_block")
        self.assertEqual(hits[0]["codepoint"], "U+E0041")

    def test_zero_width_detected(self):
        hits = find_hidden_unicode("da​ta")  # zero-width space
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["category"], "zero_width")

    def test_bidi_override_detected(self):
        hits = find_hidden_unicode("a‮b")  # RIGHT-TO-LEFT OVERRIDE
        self.assertEqual(hits[0]["category"], "bidi_override")

    def test_clean_text_no_hits(self):
        self.assertEqual(find_hidden_unicode("perfectly normal tool"), [])


class ScanToolMetadataTest(unittest.TestCase):
    def test_hidden_in_description_flagged_model_visible(self):
        tools = [{"name": "get_weather",
                  "description": "Gets weather.\U000E0041\U000E0042",
                  "inputSchema": {"type": "object"}}]
        r = scan_tool_metadata(tools)
        self.assertEqual(r["tools_flagged"], ["get_weather"])
        self.assertTrue(r["model_visible_hits"])
        self.assertFalse(r["schema_hits"])

    def test_hidden_only_in_schema(self):
        tools = [{"name": "x", "description": "clean",
                  "inputSchema": {"desc": "field⁠join"}}]  # word joiner
        r = scan_tool_metadata(tools)
        self.assertTrue(r["schema_hits"])
        self.assertFalse(r["model_visible_hits"])

    def test_clean_tools(self):
        tools = [{"name": "x", "description": "clean", "inputSchema": {}}]
        r = scan_tool_metadata(tools)
        self.assertEqual(r["tools_flagged"], [])


class RegistrationTest(unittest.TestCase):
    def test_registers_and_detectors_callable(self):
        from mcp.server.fastmcp import FastMCP
        from burpsuite_mcp.tools import mcp_invisible_unicode as m
        mcp = FastMCP("t")
        m.register(mcp)  # must not raise
        self.assertTrue(callable(m.find_hidden_unicode))
        self.assertTrue(callable(m.scan_tool_metadata))


if __name__ == "__main__":
    unittest.main()
