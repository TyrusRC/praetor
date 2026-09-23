"""Tools-only-host parity bridge: agent playbooks + rules + bootstrap as TOOLS.

A host that bridges only MCP tools (dsh / Codex) cannot read the `burp://`
resources, so the agent roster and the rule files must also be reachable as
tools. These tests cover the properties that make that bridge trustworthy:
the roster is non-empty and fetchable, path traversal is refused, the rule
files load, and bootstrap advertises the flow.
"""

import asyncio
import unittest

from praetor.tools import agents_access, host_bootstrap


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

    def test_bootstrap_advertises_the_flow(self):
        b = _call(self.t["praetor_bootstrap"])
        for key in ("load_first", "web_hunt_loop", "network_lane",
                    "mobile_lane", "save_finding_pipeline"):
            self.assertIn(key, b)
        # It must point at the real entrypoints, not prose.
        self.assertTrue(any("get_rules" in s for s in b["load_first"]))
        self.assertTrue(any("run_network_recon" in s for s in b["network_lane"]))


if __name__ == "__main__":
    unittest.main()
