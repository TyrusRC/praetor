"""Tool-manifest slimming: pydantic `title` keys are dropped, nothing else is."""

import asyncio
import unittest

from burpsuite_mcp._schema_slim import strip_titles


class StripTitlesTest(unittest.TestCase):
    def test_drops_field_and_model_titles(self):
        schema = {
            "title": "fooArguments",
            "type": "object",
            "properties": {"domain": {"title": "Domain", "type": "string"}},
        }
        strip_titles(schema)
        self.assertNotIn("title", schema)
        self.assertNotIn("title", schema["properties"]["domain"])
        self.assertEqual(schema["properties"]["domain"]["type"], "string")

    def test_property_named_title_survives(self):
        """`title` as a property NAME is data, not metadata — save_finding has one."""
        schema = {
            "properties": {"title": {"title": "Title", "type": "string"}},
            "required": ["title"],
        }
        strip_titles(schema)
        self.assertIn("title", schema["properties"])
        self.assertNotIn("title", schema["properties"]["title"])
        self.assertEqual(schema["required"], ["title"])

    def test_constraints_are_preserved(self):
        schema = {
            "properties": {
                "mode": {"title": "Mode", "type": "string", "default": "operator",
                         "enum": ["operator", "strict"], "description": "keep me"},
                "ids": {"title": "Ids", "anyOf": [
                    {"items": {"title": "Item", "type": "string"}, "type": "array"},
                    {"type": "null"}]},
            },
            "required": ["mode"],
        }
        strip_titles(schema)
        mode = schema["properties"]["mode"]
        self.assertEqual(mode["default"], "operator")
        self.assertEqual(mode["enum"], ["operator", "strict"])
        self.assertEqual(mode["description"], "keep me")
        self.assertEqual(schema["required"], ["mode"])
        self.assertNotIn("title", schema["properties"]["ids"]["anyOf"][0]["items"])

    def test_non_dict_is_a_no_op(self):
        self.assertIsNone(strip_titles(None))


class ServerManifestTest(unittest.TestCase):
    """The slimming runs at import time in server.py — assert it took effect."""

    def test_no_title_metadata_remains_and_tools_still_run(self):
        from burpsuite_mcp.server import mcp

        tools = asyncio.run(mcp.list_tools())
        self.assertGreater(len(tools), 100)
        for tool in tools:
            schema = tool.inputSchema
            self.assertNotIn("title", schema, f"{tool.name} root title not stripped")
            for name, prop in (schema.get("properties") or {}).items():
                self.assertNotIn(
                    "title", prop, f"{tool.name}.{name} title not stripped"
                )

        # A slimmed schema must still validate + execute.
        result = asyncio.run(
            mcp.call_tool("smart_decode", {"input_text": "aGVsbG8gd29ybGQ="})
        )
        self.assertIn("hello world", str(result))


if __name__ == "__main__":
    unittest.main()
