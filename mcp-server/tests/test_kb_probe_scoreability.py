"""Every active knowledge-base probe must be scoreable.

A probe with no matchers at either the probe or the context level is sent to
the target and scored against nothing. It cannot ever produce a finding, but
auto_probe still records the (endpoint, parameter, category) tuple as covered —
so Rule 19/20 then skip re-testing a class that was never actually evaluated.
That is strictly worse than not running the probe at all, and it is silent.

This suite is the regression guard. It caught the cloud-metadata SSRF set,
where `cloud_webapp.json` declares matchers per context while the orchestrator
only read them per probe.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from burpsuite_mcp.tools.scan._constants import _REFERENCE_ONLY

KB_DIR = Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "knowledge"

# Contexts that intentionally carry matchers but no probes: they describe
# response patterns for a passive/manual read, not something auto_probe fires.
# Listed explicitly so a genuinely broken context cannot hide among them.
PASSIVE_ONLY_CONTEXTS = {
    ("cloud_webapp", "azure_sas_token_leak"),
    ("cloud_webapp", "cognito_jwt"),
    ("cloud_webapp", "leaked_keys_in_response"),
    ("cloud_webapp", "cloud_sdk_errors"),
    ("cloud_webapp", "irsa_projected_token_persistent_harvest_2026"),
}


def _active_kb_files() -> list[Path]:
    return sorted(p for p in KB_DIR.glob("*.json") if p.stem not in _REFERENCE_ONLY)


class ProbeScoreabilityTest(unittest.TestCase):

    @staticmethod
    def _is_reference_only(probe: dict) -> bool:
        """Mirrors AutoProbeOrchestrator.isReferenceOnly — documentation, not a payload."""
        flag = (probe.get("variables") or {}).get("reference_only")
        return flag is True or str(flag).lower() == "true"

    def test_every_active_probe_has_matchers_somewhere(self):
        unscoreable: list[str] = []
        for path in _active_kb_files():
            data = json.loads(path.read_text())
            for ctx_name, ctx in (data.get("contexts") or {}).items():
                ctx_matchers = ctx.get("matchers") or []
                for i, probe in enumerate(ctx.get("probes") or []):
                    if self._is_reference_only(probe):
                        continue
                    if not (probe.get("matchers") or ctx_matchers):
                        unscoreable.append(f"{path.stem}/{ctx_name}[{i}]")
        self.assertEqual(
            unscoreable, [],
            "Probes with no matchers at probe OR context level — these are sent "
            "and can never match, while still counting as coverage:\n  "
            + "\n  ".join(unscoreable),
        )

    def test_contexts_without_probes_are_declared_passive(self):
        undeclared: list[str] = []
        for path in _active_kb_files():
            data = json.loads(path.read_text())
            for ctx_name, ctx in (data.get("contexts") or {}).items():
                if ctx.get("probes"):
                    continue
                if (path.stem, ctx_name) in PASSIVE_ONLY_CONTEXTS:
                    continue
                undeclared.append(f"{path.stem}/{ctx_name}")
        self.assertEqual(
            undeclared, [],
            "Active contexts with zero probes. Either give them probes, add them "
            "to PASSIVE_ONLY_CONTEXTS, or move the file to _REFERENCE_ONLY:\n  "
            + "\n  ".join(undeclared),
        )

    def test_reference_only_probes_carry_no_sendable_payload_expectation(self):
        """A reference-only probe's payload is prose. Assert it is marked, not
        that it looks like a payload — the orchestrator skips on the flag, so
        the flag is the contract."""
        for path in _active_kb_files():
            data = json.loads(path.read_text())
            for ctx_name, ctx in (data.get("contexts") or {}).items():
                ctx_matchers = ctx.get("matchers") or []
                for i, probe in enumerate(ctx.get("probes") or []):
                    if probe.get("matchers") or ctx_matchers:
                        continue
                    self.assertTrue(
                        self._is_reference_only(probe),
                        f"{path.stem}/{ctx_name}[{i}] has no matchers but is not "
                        f"marked variables.reference_only — it will be sent and "
                        f"scored against nothing",
                    )

    def test_declared_passive_contexts_still_exist(self):
        """Keeps the allowlist honest — a stale entry hides a real regression."""
        for file_stem, ctx_name in sorted(PASSIVE_ONLY_CONTEXTS):
            path = KB_DIR / f"{file_stem}.json"
            self.assertTrue(path.exists(), f"{file_stem}.json no longer exists")
            data = json.loads(path.read_text())
            self.assertIn(
                ctx_name, data.get("contexts") or {},
                f"PASSIVE_ONLY_CONTEXTS lists {file_stem}/{ctx_name} but it is gone — "
                f"drop the stale allowlist entry",
            )

    def test_matcher_types_are_all_supported_by_the_engine(self):
        """An unknown matcher type fails closed — the probe silently never fires."""
        engine = (
            Path(__file__).resolve().parent.parent.parent
            / "burp-extension/src/main/java/com/praetor/analysis/MatcherEngine.java"
        )
        if not engine.exists():          # Python-only checkout
            self.skipTest("MatcherEngine.java not present")
        import re
        supported = set(re.findall(r'case\s+"([a-z_0-9]+)"', engine.read_text()))
        unknown: dict[str, list[str]] = {}
        for path in _active_kb_files():
            data = json.loads(path.read_text())
            for ctx_name, ctx in (data.get("contexts") or {}).items():
                matcher_sets = [ctx.get("matchers") or []]
                matcher_sets += [p.get("matchers") or [] for p in (ctx.get("probes") or [])]
                for ms in matcher_sets:
                    for m in ms:
                        t = m.get("type", "")
                        if t and t not in supported:
                            unknown.setdefault(t, []).append(f"{path.stem}/{ctx_name}")
        self.assertEqual(
            unknown, {},
            "Matcher types unknown to MatcherEngine (fail closed, probe never "
            f"matches): { {k: v[:3] for k, v in unknown.items()} }",
        )


if __name__ == "__main__":
    unittest.main()
