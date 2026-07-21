"""W34 — coverage / framework-tagging / triage-reconciliation work.

Pure-function + JSON-load coverage only. No Burp client, no network.

Covers:
- tools/_framework_map.py::framework_tags — ATT&CK/WSTG/CWE/OWASP lookup + safe
  default for unknown classes (W34-b).
- tools/advisor/assess.py::_framework_line — one-line framework tag, degrades to
  None for unknown classes.
- tools/cve/_register_kev_epss.py::_ACTOR_MAP — actor attribution for known CVEs,
  None for unknown.
- tools/advisor/__init__.py::validate_severity — CVSS-vector vs claimed-severity
  reconciliation (MATCH / INFLATED / UNDERSTATED).
- tools/advisor/__init__.py::debate_triage — Red/Blue/Judge scaffold shape +
  class-specific FP modes + NEVER-SUBMIT judge warning.
- W34-a edge-appliance KB files load as valid JSON with expected contexts shape.

validate_severity / debate_triage live as @mcp.tool() closures inside
advisor.register(). Both are pure (validate_severity reads _cvss4 module math;
debate_triage is pure data). A capturing fake FastMCP extracts them without any
real client — see _capture_advisor_tools().
"""

from __future__ import annotations

import asyncio
import json
import unittest
from pathlib import Path

KB_DIR = Path(__file__).resolve().parent.parent / "src" / "burpsuite_mcp" / "knowledge"


class _Capture:
    """Fake FastMCP: @tool() records the decorated fn by name, no client."""

    def __init__(self) -> None:
        self.tools: dict = {}

    def tool(self, *args, **kwargs):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


def _capture_advisor_tools() -> dict:
    from burpsuite_mcp.tools import advisor
    cap = _Capture()
    advisor.register(cap)
    return cap.tools


# ---------------------------------------------------------------------------
# 1. framework_tags — the ATT&CK/WSTG/CWE/OWASP lookup
# ---------------------------------------------------------------------------
class FrameworkTagsTest(unittest.TestCase):
    def setUp(self):
        from burpsuite_mcp.tools._framework_map import framework_tags
        self.framework_tags = framework_tags

    def test_known_classes_map_to_real_ids(self):
        # sqli -> A03 injection, CWE-89, WSTG-INPV-05, ATT&CK T1190
        sqli = self.framework_tags("sqli")
        self.assertIn("T1190", sqli["attack_ck"])
        self.assertEqual(sqli["cwe"], "CWE-89")
        self.assertEqual(sqli["wstg"], "WSTG-INPV-05")
        self.assertTrue(sqli["owasp"].startswith("A03:2021"))

        # xss -> CWE-79
        self.assertEqual(self.framework_tags("xss")["cwe"], "CWE-79")

        # ssrf -> CWE-918, A10 SSRF
        ssrf = self.framework_tags("ssrf")
        self.assertEqual(ssrf["cwe"], "CWE-918")
        self.assertIn("A10:2021", ssrf["owasp"])

    def test_alias_and_suffix_resolution(self):
        # alias table + suffix strip must reach the same canonical row as 'sqli'.
        canonical = self.framework_tags("sqli")["cwe"]
        self.assertEqual(self.framework_tags("sql_injection")["cwe"], canonical)  # alias
        self.assertEqual(self.framework_tags("sqli_blind")["cwe"], canonical)      # suffix strip

    def test_unknown_class_returns_safe_empty_default_without_raising(self):
        row = self.framework_tags("totally_made_up_class_xyz")
        # well-formed empty row — callers never KeyError
        self.assertEqual(row["attack_ck"], [])
        self.assertEqual(row["cwe"], "")
        self.assertEqual(row["wstg"], "")
        self.assertEqual(row["detection"], {})
        # keys always present
        for k in ("attack_ck", "attack_name", "wstg", "owasp", "cwe", "detection"):
            self.assertIn(k, row)

    def test_empty_and_non_string_input_do_not_raise(self):
        self.assertEqual(self.framework_tags("")["cwe"], "")
        self.assertEqual(self.framework_tags(None)["cwe"], "")  # type: ignore[arg-type]

    def test_returned_row_is_independent_copy(self):
        # mutating a returned row must not corrupt the shared table.
        a = self.framework_tags("sqli")
        a["attack_ck"].append("TAMPERED")
        b = self.framework_tags("sqli")
        self.assertNotIn("TAMPERED", b["attack_ck"])


# ---------------------------------------------------------------------------
# 2. _framework_line — assess.py one-line tag
# ---------------------------------------------------------------------------
class FrameworkLineTest(unittest.TestCase):
    def setUp(self):
        from burpsuite_mcp.tools.advisor.assess import _framework_line
        self._framework_line = _framework_line

    def test_known_class_contains_framework_ids(self):
        line = self._framework_line("sqli")
        self.assertIsNotNone(line)
        self.assertIn("ATT&CK", line)
        self.assertIn("T1190", line)
        self.assertIn("WSTG-INPV-05", line)
        self.assertIn("CWE-89", line)

    def test_unknown_class_degrades_to_none(self):
        # empty framework row -> no parts -> None (not a crash, not "")
        self.assertIsNone(self._framework_line("totally_made_up_class_xyz"))


# ---------------------------------------------------------------------------
# 3. _ACTOR_MAP — CVE actor attribution
# ---------------------------------------------------------------------------
class ActorMapTest(unittest.TestCase):
    def setUp(self):
        from burpsuite_mcp.tools.cve._register_kev_epss import _ACTOR_MAP
        self._ACTOR_MAP = _ACTOR_MAP

    def test_known_cve_is_attributed(self):
        self.assertTrue(self._ACTOR_MAP)  # non-empty
        log4shell = self._ACTOR_MAP.get("CVE-2021-44228")
        self.assertIsNotNone(log4shell)
        self.assertIn("Log4Shell", log4shell)
        # a second, distinct actor mapping
        self.assertIn("UNC5221", self._ACTOR_MAP.get("CVE-2023-46805", ""))

    def test_unknown_cve_degrades_to_none(self):
        self.assertIsNone(self._ACTOR_MAP.get("CVE-9999-00000"))


# ---------------------------------------------------------------------------
# 4. validate_severity — CVSS-band vs claimed-severity reconciliation
# ---------------------------------------------------------------------------
class ValidateSeverityTest(unittest.TestCase):
    def setUp(self):
        self.validate_severity = _capture_advisor_tools()["validate_severity"]

    def _run(self, *a, **k):
        return asyncio.run(self.validate_severity(*a, **k))

    def test_match_when_claimed_equals_cvss_band(self):
        # first resolve the CVSS-derived band, then claim exactly it -> MATCH.
        base = self._run("sqli", "HIGH")
        band = base["cvss_band"]
        self.assertIn(band, ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
        self.assertEqual(self._run("sqli", band)["verdict"], "MATCH")

    def test_inflated_and_understated_reported_against_the_math(self):
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        band = self._run("sqli", "HIGH")["cvss_band"]
        idx = order.index(band)
        # one band above the computed value must be flagged INFLATED
        if idx < len(order) - 1:
            r = self._run("sqli", order[idx + 1])
            self.assertEqual(r["verdict"], "INFLATED")
        # one band below must be flagged UNDERSTATED
        if idx > 0:
            r = self._run("sqli", order[idx - 1])
            self.assertEqual(r["verdict"], "UNDERSTATED")

    def test_unknown_claimed_severity_is_rejected(self):
        r = self._run("sqli", "banana")
        self.assertIn("error", r)


# ---------------------------------------------------------------------------
# 5. debate_triage — Red/Blue/Judge scaffold
# ---------------------------------------------------------------------------
class DebateTriageTest(unittest.TestCase):
    def setUp(self):
        self.debate_triage = _capture_advisor_tools()["debate_triage"]

    def _run(self, *a, **k):
        return asyncio.run(self.debate_triage(*a, **k))

    def test_scaffold_keys_present(self):
        d = self._run("sqli", "500 with pg error", has_chain=False)
        for k in ("vuln_type", "red_advocate", "blue_advocate", "judge_rubric", "next"):
            self.assertIn(k, d)
        self.assertTrue(d["red_advocate"])
        self.assertTrue(d["judge_rubric"])

    def test_blue_advocate_seeds_class_specific_fp_modes(self):
        # sqli Blue case must carry sqli-specific FP ammo (WAF 500 vs true DB error),
        # not just the generic base modes.
        blue = self._run("sqli")["blue_advocate"]
        joined = " ".join(blue)
        self.assertIn("WAF", joined)
        # xss carries its own distinct FP mode
        xss_blue = " ".join(self._run("xss")["blue_advocate"])
        self.assertIn("executable context", xss_blue)

    def test_never_submit_class_without_chain_gets_judge_warning(self):
        d = self._run("open_redirect", has_chain=False)
        self.assertIn("NEVER-SUBMIT", d["judge_rubric"][0])
        # with a chain the leading NEVER-SUBMIT warning is not prepended
        d2 = self._run("open_redirect", has_chain=True)
        self.assertNotIn("NEVER-SUBMIT", d2["judge_rubric"][0])


# ---------------------------------------------------------------------------
# 6. W34-a edge-appliance KB files
# ---------------------------------------------------------------------------
class EdgeApplianceKBTest(unittest.TestCase):
    # file -> a context key that must exist in it
    CASES = {
        "ivanti.json": "ics_authbypass_cmdi_2024",
        "citrix_netscaler.json": "shitrix_path_traversal_2019",
        "f5_bigip.json": "tmui_rce_2020",
        "log4shell.json": "log4shell_jndi_2021",
    }

    def test_files_load_with_expected_contexts_shape(self):
        for fname, known_ctx in self.CASES.items():
            path = KB_DIR / fname
            self.assertTrue(path.exists(), f"{fname} missing")
            data = json.loads(path.read_text())  # raises on invalid JSON
            self.assertIn("category", data)
            self.assertIn("contexts", data)
            contexts = data["contexts"]
            self.assertTrue(contexts, f"{fname} has no contexts")
            self.assertIn(known_ctx, contexts, f"{fname} missing context {known_ctx}")

    def test_probes_carry_payload_and_valid_matchers(self):
        valid_types = {
            "status", "not_status", "word", "not_word", "regex", "timing",
            "differential_timing", "length_diff", "length_delta",
            "word_count_diff", "header", "not_header", "header_change",
            "header_added", "header_removed", "mime_changes", "reflection",
            "literal", "collaborator", "shape_fingerprint",
            "valid_vs_invalid_baseline",
        }
        for fname, known_ctx in self.CASES.items():
            data = json.loads((KB_DIR / fname).read_text())
            ctx = data["contexts"][known_ctx]
            self.assertIn("probes", ctx)
            self.assertTrue(ctx["probes"], f"{fname}:{known_ctx} has no probes")
            for probe in ctx["probes"]:
                self.assertIn("payload", probe)
                self.assertIn("matchers", probe)
                self.assertTrue(probe["matchers"])
                for m in probe["matchers"]:
                    self.assertIn("type", m)
                    self.assertIn(
                        m["type"], valid_types,
                        f"{fname}:{known_ctx} unknown matcher type {m['type']!r}",
                    )


if __name__ == "__main__":
    unittest.main()
