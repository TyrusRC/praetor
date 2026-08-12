"""Probe quality: relevance ordering, and matcher sets that can actually fail.

Two defects found on a live engagement against a known-vulnerable target:

  - auto_probe sent 20 of 1585 probes chosen by list order, so an integer `id`
    on a classic-ASP app never received a single SQLi probe;
  - 16 findings came back, 9 of them HIGH, every one from a matcher set that any
    HTTP 200 satisfies.

These tests hold both closed. The matcher rule mirrors MatcherEngine.isDiscriminating
in Java — if one side changes, this should fail.
"""

import glob
import json
import os
import unittest
from pathlib import Path

from burpsuite_mcp.tools.scan._helpers import _load_all_knowledge
from burpsuite_mcp.tools.scan._prioritise import class_value, prioritise, score_entry

KNOWLEDGE_DIR = Path(__file__).resolve().parents[1] / "src" / "burpsuite_mcp" / "knowledge"


# ── Mirror of MatcherEngine.isDiscriminating (Java) ────────────────────────
def _only_success(m: dict) -> bool:
    v = m.get("status") or m.get("codes") or m.get("value")
    codes = v if isinstance(v, list) else ([] if v is None else [v])
    if not codes:
        return True
    for c in codes:
        try:
            if not (200 <= int(str(c).strip()) <= 299):
                return False
        except ValueError:
            return False
    return True


def discriminating(matchers) -> bool:
    for m in matchers or []:
        if not isinstance(m, dict):
            continue
        t = m.get("type", "")
        if t == "status":
            if _only_success(m):
                continue
            return True
        if t in ("not_word", "not_words"):
            if not (m.get("words") or m.get("word")):
                continue
            return True
        if t == "not_header":
            if not (m.get("header") or m.get("name")):
                continue
            return True
        return True
    return False


class TestDiscriminatingRule(unittest.TestCase):
    def test_success_status_plus_empty_negative_cannot_fail(self):
        self.assertFalse(discriminating([
            {"type": "status", "status": [200]},
            {"type": "not_word", "words": []},
        ]))

    def test_error_status_is_real_signal(self):
        """A 500 where the baseline gave 200 is how blind SQLi is confirmed."""
        self.assertTrue(discriminating([{"type": "status", "status": [500]}]))

    def test_populated_negative_matcher_is_real_signal(self):
        self.assertTrue(discriminating([
            {"type": "status", "status": [200]},
            {"type": "not_header", "header": "Strict-Transport-Security"},
        ]))

    def test_content_matcher_is_real_signal(self):
        self.assertTrue(discriminating([{"type": "word", "words": ["SQL syntax"]}]))

    def test_empty_set_cannot_fail(self):
        self.assertFalse(discriminating([]))


class TestKnowledgeBaseHygiene(unittest.TestCase):
    """The unfalsifiable population is capped so it shrinks, never grows."""

    # Measured after the fix. Lower it as probes get repaired; never raise it.
    # 62 -> 57: repaired 5 OOB/SSRF probes whose true signal is a Collaborator
    # hit or leaked IMDS content, not a 200 (jwt jku/x5u/kid, graphql IMDS SSRF).
    MAX_UNFALSIFIABLE = 57

    def _scan(self):
        dead = []
        total = 0
        for path in glob.glob(str(KNOWLEDGE_DIR / "**" / "*.json"), recursive=True):
            if os.path.basename(path).startswith("_"):
                continue
            try:
                d = json.loads(Path(path).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for ctx_name, ctx in (d.get("contexts") or {}).items():
                if not isinstance(ctx, dict):
                    continue
                for p in ctx.get("probes") or []:
                    if not isinstance(p, dict) or p.get("matchers") is None:
                        continue
                    total += 1
                    if not discriminating(p["matchers"]):
                        dead.append(f"{os.path.basename(path)}::{ctx_name}")
        return total, dead

    def test_unfalsifiable_probe_count_does_not_grow(self):
        total, dead = self._scan()
        self.assertGreater(total, 1000, "knowledge base failed to load")
        self.assertLessEqual(
            len(dead), self.MAX_UNFALSIFIABLE,
            "new probes shipped with matchers that any 200 response satisfies:\n  "
            + "\n  ".join(sorted(set(dead))[:20]),
        )

    def test_the_vast_majority_of_probes_can_fail(self):
        total, dead = self._scan()
        self.assertGreater((total - len(dead)) / total, 0.95)


class TestOOBProbesUseTrueSignal(unittest.TestCase):
    """OOB/SSRF probes must not regress to a bare 200 matcher.

    A jku/x5u/kid-callback probe succeeds when a Collaborator interaction
    lands, and the IMDS remote-schema probe succeeds when metadata leaks into
    the body — never on the clean baseline these {{baseline}} probes replay.
    A 200-only matcher on such a probe fires on every clean response.
    """

    @staticmethod
    def _probe(cat, ctx_name, needle):
        d = json.loads((KNOWLEDGE_DIR / f"{cat}.json").read_text(encoding="utf-8"))
        for p in d["contexts"][ctx_name]["probes"]:
            if needle in p.get("description", ""):
                return p
        raise AssertionError(f"{cat}.{ctx_name} probe matching {needle!r} not found")

    def _types(self, probe):
        return {m.get("type") for m in probe.get("matchers", [])}

    def test_jwt_jku_injection_uses_collaborator(self):
        p = self._probe("jwt", "jku_injection", "SSRF via key URL")
        self.assertIn("collaborator", self._types(p))

    def test_jwt_jku_x5u_attacker_both_use_collaborator(self):
        for needle in ("jku: https://COLLABORATOR", "x5u: https://COLLABORATOR"):
            p = self._probe("jwt", "jku_x5u_attacker", needle)
            self.assertIn("collaborator", self._types(p),
                          f"{needle} probe lost its collaborator matcher")

    def test_jwt_kid_command_injection_uses_collaborator(self):
        p = self._probe("jwt", "kid_injection", "command injection in shelled-out key fetch")
        self.assertIn("collaborator", self._types(p))

    def test_graphql_imds_ssrf_matches_metadata_content(self):
        p = self._probe("graphql_engines", "hasura_remote_schema_ssrf", "AWS IMDS")
        word = next((m for m in p["matchers"] if m.get("type") == "word"), None)
        self.assertIsNotNone(word, "IMDS SSRF probe must assert leaked metadata content")
        self.assertTrue(any("ami-id" in w or "meta-data" in w for w in word["words"]))


class TestPrioritisation(unittest.TestCase):
    def setUp(self):
        self.kb = _load_all_knowledge(None)
        self.assertGreater(len(self.kb), 50, "knowledge base failed to load")

    def _order(self, param, tech):
        targets = [{"path": f"/x.asp?{param}=1", "parameter": param, "method": "GET"}]
        return [k.get("category") for k in prioritise(self.kb, targets, tech)]

    def test_sqli_outranks_clickjacking_for_an_integer_id(self):
        order = self._order("id", ["IIS", "ASP.NET"])
        self.assertLess(
            order.index("sqli"), order.index("clickjacking"),
            "an integer id parameter must be probed for injection before framing",
        )

    def test_sqli_lands_inside_a_default_probe_budget(self):
        """The live miss: sqli sat at rank 107 with a budget of 20."""
        order = self._order("id", ["IIS", "ASP.NET"])
        self.assertLess(order.index("sqli"), 20)

    def test_low_value_classes_fall_outside_the_probe_budget(self):
        """The classes that produced 16 false positives must not lead the list.

        Asserted against the default budget rather than a position in the list:
        landing outside it is the property that matters — those classes are
        still probed when the operator asks for them by name or raises the cap.
        """
        order = self._order("id", ["IIS", "ASP.NET"])
        for junk in ("clickjacking", "crypto_weakness", "session_security"):
            if junk in order:
                self.assertGreater(order.index(junk), 20, junk)
                self.assertGreater(order.index(junk), order.index("sqli"), junk)

    def test_impact_first_tiering(self):
        self.assertGreater(class_value("sqli"), class_value("clickjacking"))
        self.assertGreater(class_value("idor"), class_value("session_security"))

    def test_split_files_inherit_the_parent_tier(self):
        self.assertEqual(class_value("sqli_mssql"), class_value("sqli"))

    def test_unknown_class_sits_mid_table(self):
        self.assertLess(class_value("clickjacking"), class_value("some_new_class"))
        self.assertLess(class_value("some_new_class"), class_value("sqli"))

    def test_ordering_is_total_and_lossless(self):
        targets = [{"path": "/x", "parameter": "id"}]
        out = prioritise(self.kb, targets, [])
        self.assertEqual(len(out), len(self.kb))
        self.assertEqual({id(k) for k in out}, {id(k) for k in self.kb})

    def test_no_targets_does_not_raise(self):
        self.assertEqual(len(prioritise(self.kb, [], [])), len(self.kb))

    def test_score_entry_ranks_a_matching_param_above_a_universal_context(self):
        matching = {"category": "sqli", "contexts": {"c": {"param_match": ["id"]}}}
        universal = {"category": "clickjacking", "contexts": {"c": {}}}
        self.assertGreater(
            score_entry(matching, {"id"}, set()),
            score_entry(universal, {"id"}, set()),
        )


class TestSingleShotDesyncExcluded(unittest.TestCase):
    """CL.0 / CSD / TE desync cannot be confirmed by one request's length_diff.

    A live run fired critical/high http_desync findings on a benign Classic-ASP
    GET from length_diff alone — any malformed raw request differs in length from
    the baseline. Smuggling needs the differential follow-up / socket timing that
    test_request_smuggling drives, so the whole class is reference-only, exactly
    like its already-excluded request_smuggling sibling.
    """

    def test_desync_classes_are_not_in_the_auto_probe_kb(self):
        cats = {k.get("category") for k in _load_all_knowledge(None)}
        self.assertNotIn("http_desync", cats)
        self.assertNotIn("request_smuggling", cats)

    def test_naming_the_class_by_category_does_not_reintroduce_it(self):
        cats = {k.get("category") for k in _load_all_knowledge(["http_desync"])}
        self.assertNotIn(
            "http_desync", cats,
            "reference-only classes stay out of auto_probe even when named",
        )


if __name__ == "__main__":
    unittest.main()
