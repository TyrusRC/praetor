"""Engagement-narrative graph pure core (intel/_engagement.py)."""

import unittest

from praetor.tools.intel import _engagement as E


def _seed():
    g = E.new_graph("acme.tld", "map + prove auth bugs", "SOW-42")
    i1 = E.add_intent(g, "enumerate API endpoints")          # spawns goal->intent-1
    f1 = E.add_fact(g, "/api/v1/users?id= reflects 500", i1)  # yields
    i2 = E.add_intent(g, "test IDOR on user id", parent=f1)   # derived_from fact-1
    a1 = E.add_asset(g, "acme.tld", "host")
    a2 = E.add_asset(g, "/api/v1/users", "endpoint", parent=a1)
    fn = E.add_finding(g, "f007", "IDOR on /api/v1/users", i2, assets=[a2], severity="high")
    return g, dict(i1=i1, f1=f1, i2=i2, a1=a1, a2=a2, fn=fn)


class IdsAndEdgesTest(unittest.TestCase):
    def test_deterministic_ids_and_edges(self):
        g, r = _seed()
        self.assertEqual(r["i1"], "intent-1")
        self.assertEqual(r["f1"], "fact-1")
        self.assertEqual(r["i2"], "intent-2")
        self.assertEqual(r["a2"], "asset-2")
        self.assertEqual(r["fn"], "finding-1")
        types = {(e["type"], e["from"], e["to"]) for e in g["edges"]}
        self.assertIn(("spawns", "goal-1", "intent-1"), types)
        self.assertIn(("yields", "intent-1", "fact-1"), types)
        self.assertIn(("derived_from", "fact-1", "intent-2"), types)   # follow-up from a fact
        self.assertIn(("proves", "intent-2", "finding-1"), types)
        self.assertIn(("parent", "asset-1", "asset-2"), types)
        self.assertIn(("affects", "finding-1", "asset-2"), types)


class ReferenceRejectionTest(unittest.TestCase):
    def test_fact_needs_existing_intent(self):
        g = E.new_graph("t", "o")
        with self.assertRaises(ValueError):
            E.add_fact(g, "obs", "intent-99")

    def test_fact_rejects_non_intent_parent(self):
        g = E.new_graph("t", "o")
        a = E.add_asset(g, "h", "host")
        with self.assertRaises(ValueError):
            E.add_fact(g, "obs", a)                 # a is an asset, not an intent

    def test_finding_needs_existing_asset(self):
        g = E.new_graph("t", "o")
        i = E.add_intent(g, "x")
        with self.assertRaises(ValueError):
            E.add_finding(g, "f1", "t", i, assets=["asset-9"])

    def test_asset_parent_must_exist(self):
        g = E.new_graph("t", "o")
        with self.assertRaises(ValueError):
            E.add_asset(g, "svc", "service", parent="asset-9")

    def test_empty_required_fields(self):
        g = E.new_graph("t", "o")
        with self.assertRaises(ValueError):
            E.add_intent(g, "   ")


class RenderTest(unittest.TestCase):
    def test_text_lists_lineage(self):
        g, _ = _seed()
        txt = E.render_text(g)
        self.assertIn("GOAL goal-1: acme.tld", txt)
        self.assertIn("PROVES", txt)
        self.assertIn("f007", txt)

    def test_mermaid_has_nodes_and_edges(self):
        g, _ = _seed()
        m = E.render_mermaid(g)
        self.assertIn("flowchart TD", m)
        self.assertIn("-->|proves|", m)
        self.assertIn("-->|derived_from|", m)
        # goal node id must be sanitised to match the edge refs (goal_1, not goal-1)
        self.assertIn("goal_1[", m)
        self.assertNotIn("goal-1[", m)
        self.assertIn("spawns", m)

    def test_dsh_replay_shape(self):
        g, _ = _seed()
        calls = E.render_dsh(g)
        tools = [c["tool"] for c in calls]
        self.assertEqual(tools[0], "pentest_add_goal")
        self.assertIn("pentest_add_intent", tools)
        self.assertIn("pentest_add_finding", tools)
        # every finding replay carries reproducibleSteps (dsh requires >=1)
        for c in calls:
            if c["tool"] == "pentest_add_finding":
                self.assertTrue(c["args"]["reproducibleSteps"])


if __name__ == "__main__":
    unittest.main()
