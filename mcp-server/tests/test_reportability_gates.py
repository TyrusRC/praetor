"""Reportability policy: what may become a finding at all.

Bug-bounty programs rate Low/Medium/High/Critical on business impact, pay the
first distinct report, and close generic configuration observations as
ineligible. These gates encode that so the board only ever holds things worth
submitting.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock, patch

from praetor import server
from praetor.tools._vuln_class import aliases_of, canonical
from praetor.tools.advisor_kb.never_submit import (
    CONDITIONAL_NEVER_SUBMIT_TYPES,
    NEVER_SUBMIT_TYPES,
)
from praetor.tools.report.severity import SEVERITY_CAPS_BY_VULN_TYPE, tier_guidance


class TestClassVocabulary(unittest.TestCase):
    """One spelling per class, or the gates guard names nobody passes."""

    def test_ineligible_classes_are_reachable_under_their_common_spelling(self):
        gated = set(NEVER_SUBMIT_TYPES) | set(CONDITIONAL_NEVER_SUBMIT_TYPES)
        missed = sorted(c for c in SEVERITY_CAPS_BY_VULN_TYPE if canonical(c) not in gated)
        self.assertEqual(
            missed, [],
            "classes the report caps as low-value but the ineligible gate cannot see",
        )

    def test_open_redirect_resolves_to_its_gated_name(self):
        self.assertEqual(canonical("open_redirect"), "open_redirect_no_chain")

    def test_information_disclosure_variants_collapse(self):
        for spelling in ("information_disclosure", "path_disclosure",
                         "directory_listing", "verbose_error", "debug_endpoint"):
            self.assertEqual(canonical(spelling), "info_disclosure", spelling)

    def test_unknown_class_passes_through_untouched(self):
        """Silently rewriting an unrecognised class would be worse than nothing."""
        self.assertEqual(canonical("some_novel_bug_class"), "some_novel_bug_class")

    def test_aliases_round_trip(self):
        self.assertIn("missing_csp", aliases_of("missing_headers"))

    def test_separators_are_normalised(self):
        self.assertEqual(canonical("Open-Redirect"), "open_redirect_no_chain")


class TestTierGuidance(unittest.TestCase):
    def test_scale_starts_at_low(self):
        out = tier_guidance()
        self.assertIn("LOW", out)
        self.assertNotIn("INFO", out)

    def test_tiers_describe_business_impact(self):
        out = tier_guidance()
        self.assertIn("remote code execution", out)
        self.assertIn("privilege escalation", out)


class _SaveHarness(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / ".burp-intel").mkdir()
        self._cwd = mock.patch("pathlib.Path.cwd", return_value=self.root)
        self._cwd.start()

    def tearDown(self):
        self._cwd.stop()
        self._tmp.cleanup()

    def seed(self, domain, findings):
        d = self.root / ".burp-intel" / domain
        d.mkdir(parents=True, exist_ok=True)
        (d / "findings.json").write_text(json.dumps({"findings": findings}))

    async def save(self, **kw):
        base = dict(
            title="t", description="d", evidence={"logger_index": 1},
            endpoint="https://t.example/a", domain="t.example",
            parameter="p", vuln_type="xss", severity="LOW",
            force_recon_gate=True,
        )
        base.update(kw)
        with patch("praetor.tools.notes.save.client.post",
                   new=AsyncMock(return_value={"id": "burp-1"})), \
             patch("praetor.tools.intel.recon_gate_check", return_value=None):
            fn = server.mcp._tool_manager._tools["save_finding"].fn
            return await fn(**base)


class TestInfoGate(_SaveHarness):
    async def test_info_severity_is_refused(self):
        out = await self.save(severity="INFO", vuln_type="info_disclosure")
        self.assertIn("INFO GATE", out)
        self.assertIn("lead, not a result", out)

    async def test_refusal_names_the_escalation_to_try(self):
        out = await self.save(severity="INFO", vuln_type="info_disclosure")
        self.assertIn("ENABLES", out)

    async def test_low_and_above_pass_the_info_gate(self):
        out = await self.save(severity="LOW")
        self.assertNotIn("INFO GATE", out)

    async def test_override_is_available_and_audited(self):
        out = await self.save(severity="INFO",
                              overrides=["severity_info:program wants it as context"])
        self.assertNotIn("INFO GATE", out)


class TestSystemicDuplicateGate(_SaveHarness):
    def _existing(self, **kw):
        base = {"id": "f001", "vuln_type": "xss", "endpoint": "https://t.example/one",
                "parameter": "p", "status": "confirmed", "title": "x", "created": "2026-01-01"}
        base.update(kw)
        return base

    async def test_same_class_on_another_endpoint_is_a_duplicate(self):
        self.seed("t.example", [self._existing()])
        out = await self.save(endpoint="https://t.example/two", parameter="q")
        self.assertIn("SYSTEMIC GATE", out)
        self.assertIn("f001", out)

    async def test_the_message_lists_what_is_already_covered(self):
        self.seed("t.example", [self._existing()])
        out = await self.save(endpoint="https://t.example/two", parameter="q")
        self.assertIn("https://t.example/one", out)

    async def test_a_different_class_is_not_systemic(self):
        self.seed("t.example", [self._existing(vuln_type="sqli")])
        out = await self.save(vuln_type="xss", endpoint="https://t.example/two")
        self.assertNotIn("SYSTEMIC GATE", out)

    async def test_spelling_variants_still_count_as_the_same_class(self):
        self.seed("t.example", [self._existing(vuln_type="reflected_xss")])
        out = await self.save(vuln_type="xss_reflected", endpoint="https://t.example/two")
        self.assertIn("SYSTEMIC GATE", out)

    async def test_dead_findings_do_not_block_a_new_report(self):
        self.seed("t.example", [self._existing(status="likely_false_positive")])
        out = await self.save(endpoint="https://t.example/two")
        self.assertNotIn("SYSTEMIC GATE", out)

    async def test_same_endpoint_and_parameter_falls_through_to_normal_dedup(self):
        self.seed("t.example", [self._existing(endpoint="https://t.example/a", parameter="p")])
        out = await self.save(endpoint="https://t.example/a", parameter="p")
        self.assertNotIn("SYSTEMIC GATE", out)

    async def test_override_files_it_as_a_distinct_defect(self):
        self.seed("t.example", [self._existing()])
        out = await self.save(endpoint="https://t.example/two", parameter="q",
                              overrides=["systemic_dup:different sink and fix"])
        self.assertNotIn("SYSTEMIC GATE", out)

    async def test_first_report_of_a_class_is_never_blocked(self):
        out = await self.save()
        self.assertNotIn("SYSTEMIC GATE", out)


class TestNeverSubmitCanonicalGate(_SaveHarness):
    """The persistence layer must reject NEVER-SUBMIT classes regardless of
    spelling. The authoritative Java gate matches raw against a differently-
    spelled set, so a canonical Python spelling (open_redirect, missing_headers)
    slipped past the hard-reject; save_finding now canonicalises first.
    """

    async def test_open_redirect_common_spelling_is_rejected(self):
        # canonical('open_redirect') -> 'open_redirect_no_chain'; Java's raw
        # set only knows the latter, so this spelling was the bypass.
        out = await self.save(vuln_type="open_redirect", severity="LOW")
        self.assertIn("NEVER-SUBMIT GATE", out)
        self.assertIn("open_redirect_no_chain", out)

    async def test_missing_headers_is_rejected(self):
        out = await self.save(vuln_type="missing_security_header", severity="LOW")
        self.assertIn("NEVER-SUBMIT GATE", out)

    async def test_chain_lets_it_through_the_gate(self):
        self.seed("t.example", [{"id": "f001", "vuln_type": "sqli",
                                 "endpoint": "https://t.example/x", "parameter": "z",
                                 "status": "confirmed", "title": "anchor",
                                 "created": "2026-01-01"}])
        out = await self.save(vuln_type="open_redirect", severity="LOW",
                              chain_with=["f001"])
        self.assertNotIn("NEVER-SUBMIT GATE", out)

    async def test_override_bypasses_the_gate(self):
        out = await self.save(vuln_type="open_redirect", severity="LOW",
                              overrides=["q6_never_submit:chained in report body"])
        self.assertNotIn("NEVER-SUBMIT GATE", out)

    async def test_reportable_class_is_not_blocked(self):
        out = await self.save(vuln_type="sqli", severity="HIGH",
                              impact="reads other users' rows")
        self.assertNotIn("NEVER-SUBMIT GATE", out)


if __name__ == "__main__":
    unittest.main()
