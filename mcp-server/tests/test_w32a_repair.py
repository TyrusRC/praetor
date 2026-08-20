"""W32-a — internal repair wave.

Covers:
- A3 CLAUDE.md drift (tool count + KB count regression guards)
- A4 str→dict conversions on 4 high-traffic tools (backwards-compat via human_summary)
- A6 chain_with[] presence on 12 NEVER-SUBMIT KBs
- A8 W-version markers absent from operator-facing skill body text

A4 conversions tested via source-grep contract pattern (matches W31-b test style).
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
KB_DIR = Path(__file__).resolve().parent.parent / "src" / "praetor" / "knowledge"
TOOLS_DIR = Path(__file__).resolve().parent.parent / "src" / "praetor" / "tools"
SKILLS_DIR = ROOT / ".claude" / "skills"
CLAUDE_MD = ROOT / "CLAUDE.md"


class CountDriftTest(unittest.TestCase):
    """CLAUDE.md must not carry exact inventory counts at all.

    These used to assert "the count is current". That guard failed at its own
    job: every release moved the real number, the doc lagged, and the count
    line was loaded into context on every session while being wrong. The fix
    is not a fresher number — it is not stating one. Discovery goes through
    `list_tier1_tools()` / `pick_tool()` / `skill.json` / the KB `_INDEX.md`,
    all of which are generated from the tree and cannot drift.
    """

    def test_claude_md_states_no_tool_count(self):
        text = CLAUDE_MD.read_text()
        m = re.search(r"~?\d{3}\+? MCP tools", text)
        self.assertIsNone(
            m,
            "CLAUDE.md states an exact tool count "
            f"({m.group(0) if m else ''}) — it will be stale by the next release. "
            "Point at list_tier1_tools() / pick_tool() / skill.json instead.",
        )

    def test_claude_md_states_no_kb_file_count(self):
        text = CLAUDE_MD.read_text()
        m = re.search(r"\d{3}\+? knowledge-base JSON files", text)
        self.assertIsNone(
            m,
            "CLAUDE.md states an exact knowledge-base file count "
            f"({m.group(0) if m else ''}) — point at knowledge/_INDEX.md instead.",
        )

    def test_claude_md_points_at_the_generated_indexes(self):
        """Removing the counts is only safe if the lookup path is still stated."""
        text = CLAUDE_MD.read_text()
        for marker in ("list_tier1_tools()", "pick_tool(", "skill.json", "_INDEX.md"):
            self.assertIn(marker, text, f"CLAUDE.md lost the discovery pointer: {marker}")


class ChainWithCoverageTest(unittest.TestCase):
    """Rule 17 chain reasoning depends on chain_with[]. NEVER-SUBMIT KBs are
    standalone-unreportable — must declare chains for assess_finding."""

    NEVER_SUBMIT_KBS_WITH_CHAINS = [
        "cache_poisoning", "http_methods_enum", "crlf_injection",
        "crypto_weakness", "error_handling_misuse", "nextjs_cache_poisoning",
        "web_cache_deception", "web_cache_poisoning_dos", "csv_injection",
        "dangling_markup", "cspp", "email_injection",
    ]

    def test_chain_with_present_and_non_empty(self):
        for name in self.NEVER_SUBMIT_KBS_WITH_CHAINS:
            with self.subTest(kb=name):
                kb = json.loads((KB_DIR / f"{name}.json").read_text())
                cw = kb.get("chain_with")
                self.assertIsInstance(cw, list, f"{name}.json missing chain_with[]")
                self.assertGreaterEqual(len(cw), 2, f"{name}.json chain_with too sparse")
                for c in cw:
                    self.assertRegex(c, r"^[a-z][a-z0-9_]*$")

    def test_chain_with_majority_reference_existing_kbs(self):
        existing = {p.stem for p in KB_DIR.glob("*.json")}
        for name in self.NEVER_SUBMIT_KBS_WITH_CHAINS:
            kb = json.loads((KB_DIR / f"{name}.json").read_text())
            cw = kb.get("chain_with", [])
            matched = sum(1 for c in cw if c in existing)
            self.assertGreaterEqual(
                matched / len(cw), 0.5,
                f"{name}.json chain_with targets have low KB match rate",
            )


class SmartMoveCoverageTest(unittest.TestCase):
    HIGH_TRAFFIC_SKILLS = [
        "hunt", "investigate", "chain-findings", "craft-payload",
        "verify-finding", "burp-workflow", "resume",
        "playbook-idor-bola", "playbook-ssrf-deep-dive",
    ]

    def test_high_traffic_skills_have_smart_move(self):
        for name in self.HIGH_TRAFFIC_SKILLS:
            with self.subTest(skill=name):
                p = SKILLS_DIR / f"{name}.md"
                if not p.exists():
                    self.skipTest(f"{name}.md not present")
                self.assertIn(
                    "SMART MOVE", p.read_text(),
                    f"{name}.md missing SMART MOVE section",
                )


class StyleDisciplineTest(unittest.TestCase):
    """No W-version markers leaked into operator-facing skill body text."""

    def test_no_w_version_markers_in_skill_bodies(self):
        leak_re = re.compile(r"\(W\d+-[a-z]\)|W\d+-[a-z]\s")
        offenders = []
        for p in SKILLS_DIR.glob("*.md"):
            for i, line in enumerate(p.read_text().splitlines(), 1):
                if leak_re.search(line):
                    offenders.append(f"{p.name}:{i} {line.strip()}")
        self.assertEqual(
            offenders, [],
            "W-version markers found in operator-facing skills:\n" + "\n".join(offenders),
        )


class StrToDictContractTest(unittest.TestCase):
    """Source-grep contract tests for the 4 converted tools.

    Each must (a) declare `-> dict` return type, (b) emit `human_summary`
    for backwards-compat, (c) use `{"error": ...}` shape on error paths."""

    def test_get_findings_returns_dict(self):
        # Signature-shape, not signature-literal: get_findings gained pagination
        # and filter params, and pinning the exact argument list made an
        # unrelated feature look like a contract break.
        src = (TOOLS_DIR / "notes" / "query.py").read_text()
        sig = re.search(r"async def get_findings\((.*?)\)\s*->\s*(\w+):", src, re.S)
        self.assertIsNotNone(sig, "get_findings signature not found")
        self.assertEqual(sig.group(2), "dict", "get_findings must return dict, not str")
        self.assertIn("endpoint", sig.group(1))
        self.assertIn('"human_summary"', src)
        self.assertIn('"error": data["error"]', src)

    def test_check_scope_returns_dict(self):
        src = (TOOLS_DIR / "read.py").read_text()
        self.assertIn("async def check_scope(url: str) -> dict:", src)
        block = src.split("async def check_scope")[1].split("async def")[0]
        self.assertIn('"in_scope"', block)
        self.assertIn('"url"', block)
        self.assertIn('"human_summary"', block)
        self.assertIn('"error":', block)

    def test_extract_api_endpoints_returns_dict(self):
        src = (TOOLS_DIR / "analyze.py").read_text()
        self.assertIn("async def extract_api_endpoints(index: int) -> dict:", src)
        block = src.split("async def extract_api_endpoints")[1].split("async def")[0]
        self.assertIn('"human_summary"', block)
        self.assertIn("total_found", block)
        self.assertIn('"error":', block)

    def test_extract_js_secrets_returns_dict(self):
        src = (TOOLS_DIR / "analyze.py").read_text()
        self.assertIn("async def extract_js_secrets(index: int) -> dict:", src)
        block = src.split("async def extract_js_secrets")[1].split("async def")[0]
        self.assertIn('"human_summary"', block)
        self.assertIn('"total_secrets"', block)
        self.assertIn('"secrets"', block)
        self.assertIn('"error":', block)


if __name__ == "__main__":
    unittest.main()
