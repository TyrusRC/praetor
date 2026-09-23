"""Tools-only-host parity bridge: agent playbooks + rules + bootstrap as TOOLS.

A host that bridges only MCP tools (dsh / Codex) cannot read the `burp://`
resources, so the agent roster and the rule files must also be reachable as
tools. These tests cover the properties that make that bridge trustworthy:
the roster is non-empty and fetchable, path traversal is refused, the rule
files load, and bootstrap advertises the flow.
"""

import asyncio
import unittest

from praetor.tools import (
    agents_access,
    host_bootstrap,
    knowledge_access,
    prompts_access,
)


def _tools(module) -> dict:
    holders: dict = {}

    class _Stub:
        def tool(self):
            def _wrap(fn):
                holders[fn.__name__] = fn
                return fn
            return _wrap

    module.register(_Stub())
    return holders


def _call(fn, *a, **k):
    return asyncio.run(fn(*a, **k))


class AgentsAccessTest(unittest.TestCase):
    def test_roster_is_nonempty_with_descriptions(self):
        entries = agents_access.agent_entries()
        self.assertTrue(entries, "expected agent playbooks under .claude/agents/")
        names = {e["name"] for e in entries}
        # Commanders are the roster's backbone — they must be listed.
        self.assertIn("pentest-commander", names)
        self.assertTrue(all(e["description"] for e in entries),
                        "every agent needs a frontmatter description")

    def test_get_agent_returns_full_markdown(self):
        got = agents_access.read_agent("pentest-commander")
        self.assertIn("markdown", got)
        self.assertIn("pentest-commander", got["markdown"])

    def test_missing_agent_lists_available(self):
        got = agents_access.read_agent("does-not-exist")
        self.assertIn("error", got)
        self.assertIn("pentest-commander", got["available"])

    def test_path_traversal_is_refused(self):
        for bad in ("../rules/hunting", "..\\x", "a/b"):
            self.assertEqual(agents_access.read_agent(bad).get("error"),
                             "invalid agent name")

    def test_registers_list_and_get_tools(self):
        t = _tools(agents_access)
        self.assertIn("list_agents", t)
        self.assertIn("get_agent", t)
        listed = _call(t["list_agents"])
        self.assertGreater(listed["count"], 0)

    def test_roster_exposes_host_agnostic_tier(self):
        # A non-Claude host cannot resolve 'opus'/'sonnet' — it needs a generic tier.
        entries = agents_access.agent_entries()
        cmd = next(e for e in entries if e["name"] == "pentest-commander")
        self.assertEqual(cmd["tier"], "strategic")  # commanders pin opus
        self.assertTrue(all(e["tier"] for e in entries))


class PromptsAccessTest(unittest.TestCase):
    def test_entries_cover_every_template(self):
        names = {e["name"] for e in prompts_access.prompt_entries()}
        # The two with no skill equivalent are the ones dsh loses without this.
        self.assertIn("triage-program", names)
        self.assertIn("save-finding-checklist", names)

    def test_render_fills_args(self):
        got = prompts_access.render_prompt("hunt-target", {"target": "https://acme.test"})
        self.assertIn("https://acme.test", got["text"])

    def test_render_ignores_unknown_args_and_uses_defaults(self):
        got = prompts_access.render_prompt("triage-program", {"bogus": "x"})
        self.assertNotIn("bogus", got["args"])
        self.assertIn("set_program_policy", got["text"])

    def test_unknown_prompt_lists_available(self):
        got = prompts_access.render_prompt("nope")
        self.assertIn("error", got)
        self.assertIn("hunt-target", got["available"])

    def test_registers_list_and_get_tools(self):
        t = _tools(prompts_access)
        self.assertIn("list_prompts", t)
        self.assertIn("get_prompt", t)
        listed = _call(t["list_prompts"])
        self.assertEqual(listed["count"], len(prompts_access.PROMPTS))


class KnowledgeAccessTest(unittest.TestCase):
    def test_categories_nonempty(self):
        entries = knowledge_access.knowledge_entries()
        self.assertTrue(entries, "expected knowledge/*.json categories")
        self.assertTrue(all(e["name"] for e in entries))

    def test_get_known_category_returns_data(self):
        name = knowledge_access.knowledge_entries()[0]["name"]
        got = knowledge_access.read_knowledge(name)
        self.assertEqual(got["name"], name)
        self.assertIsInstance(got["data"], dict)

    def test_unknown_category_lists_available(self):
        got = knowledge_access.read_knowledge("does-not-exist")
        self.assertIn("error", got)
        self.assertTrue(got["available"])

    def test_path_traversal_is_refused(self):
        for bad in ("../rules/hunting", "..\\x", "a/b"):
            self.assertEqual(knowledge_access.read_knowledge(bad).get("error"),
                             "invalid category name")

    def test_registers_list_and_get_tools(self):
        t = _tools(knowledge_access)
        self.assertIn("list_knowledge", t)
        self.assertIn("get_knowledge", t)
        self.assertGreater(_call(t["list_knowledge"])["count"], 0)


class HostBootstrapTest(unittest.TestCase):
    def setUp(self):
        self.t = _tools(host_bootstrap)

    def test_get_rules_loads_hunting(self):
        got = _call(self.t["get_rules"], "hunting")
        self.assertEqual(got["name"], "hunting")
        self.assertIn("Hunting Rules", got["markdown"])

    def test_get_rules_rejects_unknown(self):
        got = _call(self.t["get_rules"], "nope")
        self.assertIn("error", got)
        self.assertIn("hunting", got["available"])

    def test_get_rules_loads_project_claude_md(self):
        # dsh never auto-loads CLAUDE.md; the project spec must be fetchable.
        got = _call(self.t["get_rules"], "project")
        self.assertEqual(got["name"], "project")
        self.assertIn("Save-Finding Pipeline", got["markdown"])

    def test_bootstrap_advertises_the_flow(self):
        b = _call(self.t["praetor_bootstrap"])
        for key in ("load_first", "web_hunt_loop", "network_lane",
                    "mobile_lane", "save_finding_pipeline", "model_tiers"):
            self.assertIn(key, b)
        # It must point at the real entrypoints, not prose.
        self.assertTrue(any("get_rules('project')" in s for s in b["load_first"]))
        self.assertTrue(any("list_prompts" in s for s in b["load_first"]))
        self.assertTrue(any("list_knowledge" in s for s in b["load_first"]))
        self.assertTrue(any("run_network_recon" in s for s in b["network_lane"]))
        # Non-Claude hosts need the generic-tier mapping, not raw Anthropic names.
        self.assertTrue(any("strongest reasoning model" in s for s in b["model_tiers"]))


class DiscoverabilityTest(unittest.TestCase):
    """GAP 4: a tools-only host that skips the server `instructions` field still
    learns to bootstrap — the canonical discovery tool points at it."""

    def test_list_tier1_tools_points_to_bootstrap(self):
        from praetor.server import mcp
        res = asyncio.run(mcp.call_tool("list_tier1_tools", {}))
        text = "".join(getattr(c, "text", "") for c in res)
        self.assertIn("praetor_bootstrap", text)


if __name__ == "__main__":
    unittest.main()
