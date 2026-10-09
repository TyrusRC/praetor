"""markdownify (keyless) + extract_structured (optional-LLM) over a captured response."""

import asyncio
import unittest

from praetor.tools import extract_structured as ES


class _FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self, *a, **k):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


class HelpersTest(unittest.TestCase):
    def test_html_to_markdown(self):
        md = ES._html_to_markdown(
            '<head><style>x{}</style></head><h1>T</h1>'
            '<p>Hi <a href="/x">link</a></p><ul><li>a</li><li>b</li></ul>')
        self.assertIn("# T", md)
        self.assertIn("[link](/x)", md)
        self.assertIn("- a", md)
        self.assertNotIn("x{}", md)  # style stripped

    def test_parse_json(self):
        self.assertEqual(ES._parse_json('```json\n{"a":1}\n```'), ({"a": 1}, True))
        self.assertEqual(ES._parse_json('{"b":2}'), ({"b": 2}, True))
        self.assertEqual(ES._parse_json("not json"), (None, False))


class ToolsTest(unittest.TestCase):
    def setUp(self):
        self.mcp = _FakeMCP()
        ES.register(self.mcp)
        # save shared globals we monkeypatch, so tests don't leak into the suite
        self._orig = (ES._body_for_index, ES._llm.resolve_llm, ES._llm.complete)

    def tearDown(self):
        ES._body_for_index, ES._llm.resolve_llm, ES._llm.complete = self._orig

    def _call(self, name, **kw):
        return asyncio.run(self.mcp.tools[name](**kw))

    def test_markdownify_needs_index(self):
        self.assertIn("pass index", self._call("markdownify", index=-1)["error"])

    def test_markdownify_reduces(self):
        async def fake_body(i):
            return "<h1>Hello</h1><p>world</p>", ""
        ES._body_for_index = fake_body
        out = self._call("markdownify", index=3)
        self.assertIn("# Hello", out["markdown"])
        self.assertEqual(out["index"], 3)

    def test_extract_structured_degrades_without_llm(self):
        class _Cfg:
            ok = False
            reason = "no LLM configured"
        ES._llm.resolve_llm = lambda *a, **k: _Cfg()
        out = self._call("extract_structured", index=1, prompt="list users")
        self.assertIn("no LLM configured", out["error"])
        self.assertIn("extract_css_selector", out["hint"])

    def test_extract_structured_returns_json(self):
        class _Cfg:
            ok = True
            reason = ""
            provider = "openai"
            model = "gpt-4o-mini"
        ES._llm.resolve_llm = lambda *a, **k: _Cfg()

        async def fake_complete(prompt, **kw):
            return '```json\n{"users":["alice","bob"]}\n```'
        ES._llm.complete = fake_complete

        async def fake_body(i):
            return "<table>...users...</table>", ""
        ES._body_for_index = fake_body

        out = self._call("extract_structured", index=1, prompt="list users")
        self.assertEqual(out["data"], {"users": ["alice", "bob"]})
        self.assertEqual(out["model"], "gpt-4o-mini")

    def test_extract_structured_needs_prompt_or_schema(self):
        out = self._call("extract_structured", index=1)
        self.assertIn("prompt", out["error"])


if __name__ == "__main__":
    unittest.main()
