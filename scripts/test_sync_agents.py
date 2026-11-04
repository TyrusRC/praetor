"""Tests for scripts/sync_agents.py — the harness agent-wrapper generator.

Run: uv run python scripts/test_sync_agents.py
Each test guards a behaviour that can really break: frontmatter shape per
harness, the single-source-of-truth invariant (no subset drift), tier mapping,
and the --check drift gate.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sync_agents as sa  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


class ParseTests(unittest.TestCase):
    def test_loads_every_canonical_role(self):
        agents = sa.load_canonical(REPO)
        names = {a["name"] for a in agents}
        # roster is ~19 roles; assert the shape is right, not an exact count
        self.assertGreaterEqual(len(agents), 15)
        self.assertIn("recon-agent", names)
        self.assertIn("pentest-commander", names)
        for a in agents:
            self.assertTrue(a["name"])
            self.assertTrue(a["description"], f"{a['name']} missing description")

    def test_tier_from_model_pin(self):
        self.assertEqual(sa.tier_for("opus"), "strategic")
        self.assertEqual(sa.tier_for("haiku"), "fast")
        self.assertEqual(sa.tier_for("sonnet"), "standard")
        self.assertEqual(sa.tier_for(None), "standard")
        self.assertEqual(sa.tier_for(""), "standard")


class EmitterTests(unittest.TestCase):
    def setUp(self):
        self.agent = {
            "name": "recon-agent",
            "description": "Map a target's attack surface.",
            "model": "haiku",
        }

    def test_opencode_shape(self):
        path, content = sa.emit_opencode(self.agent)
        self.assertEqual(path, ".opencode/agent/recon-agent.md")
        self.assertIn("mode: subagent", content)
        self.assertIn("description: Map a target's attack surface.", content)
        # must point back to the canonical manual, not copy it
        self.assertIn(".claude/agents/recon-agent.md", content)
        self.assertIn(sa.GENERATED_MARK, content)
        # frontmatter is well-formed (opens and closes)
        self.assertEqual(content.count("---\n"), 2)

    def test_gemini_shape(self):
        path, content = sa.emit_gemini(self.agent)
        self.assertEqual(path, ".gemini/agents/recon-agent.md")
        self.assertIn("name: recon-agent", content)
        self.assertIn("description: Map a target's attack surface.", content)
        self.assertIn(".claude/agents/recon-agent.md", content)
        self.assertIn(sa.GENERATED_MARK, content)

    def test_tier_surfaced_in_body(self):
        _, content = sa.emit_opencode(self.agent)
        self.assertIn("fast", content)  # haiku -> fast tier


class SingleSourceInvariant(unittest.TestCase):
    """The drift bug: .gemini shipped 3 of 19 roles. Every harness must emit
    EXACTLY the canonical role set — no subset, no extras."""

    def test_no_subset_drift(self):
        agents = sa.load_canonical(REPO)
        canonical = {a["name"] for a in agents}
        out = sa.generate(agents, harnesses=["opencode", "gemini"])
        for harness, prefix in (("opencode", ".opencode/agent/"),
                                 ("gemini", ".gemini/agents/")):
            emitted = {
                p[len(prefix):-3] for p in out if p.startswith(prefix)
            }
            self.assertEqual(
                emitted, canonical,
                f"{harness} emits {emitted ^ canonical} differing from canonical",
            )


class CheckGate(unittest.TestCase):
    def test_check_detects_drift(self):
        agents = [{"name": "ghost-agent", "description": "not on disk", "model": None}]
        # a role that cannot exist on disk must be reported stale by check
        results = sa.sync(REPO, harnesses=["opencode"], check=True, agents=agents)
        self.assertTrue(any(status != "ok" for _, status in results))


if __name__ == "__main__":
    unittest.main(verbosity=2)
