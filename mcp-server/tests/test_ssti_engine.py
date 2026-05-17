"""Calibration tests for the native test_ssti orchestrator.

We don't run end-to-end HTTP here — those need a live Burp + target. The
calibration covers data invariants: every engine in the polyglot hint
table has at least one capability probe, every distinguisher payload
parses to a non-empty string, marker substrings are non-empty, and the
blind-sleep gadgets all contain the __SECS__ placeholder.
"""

from __future__ import annotations

import unittest

from burpsuite_mcp.tools.vuln.test_ssti import (
    _POLYGLOT,
    _POLYGLOT_HINTS,
    _DISTINGUISHERS,
    _CAPABILITIES,
    _BLIND_SLEEPS,
    _build_request,
)


class PolyglotInvariants(unittest.TestCase):
    def test_polyglot_is_nonempty(self):
        self.assertGreater(len(_POLYGLOT), 0)

    def test_polyglot_covers_multiple_syntax_families(self):
        # The canonical universal SSTI polyglot ${{<%[%'"}}%\ is crafted
        # to trigger errors across template families simultaneously.
        # Markers: ${...} ${...}, {{...}}, <%...%>, [%...%], plus quote
        # chaos. (Jinja {% statement tag isn't in this polyglot — that's
        # what the math distinguishers in Phase 2 cover.)
        for marker in ("${", "{{", "<%", "[%"):
            self.assertIn(marker, _POLYGLOT,
                          f"polyglot missing {marker!r} family trigger")

    def test_hint_engines_have_capability_or_blind_coverage(self):
        # If we can fingerprint an engine from a polyglot error, we
        # should also have something to do about it.
        for engine, _patterns in _POLYGLOT_HINTS:
            self.assertTrue(
                engine in _CAPABILITIES or engine in _BLIND_SLEEPS,
                f"polyglot hint engine {engine!r} has no follow-up probe",
            )

    def test_hint_patterns_nonempty(self):
        for engine, patterns in _POLYGLOT_HINTS:
            self.assertTrue(patterns, f"{engine} has empty pattern list")
            for p in patterns:
                self.assertGreater(len(p), 3, f"{engine}: pattern {p!r} too short")


class DistinguisherInvariants(unittest.TestCase):
    def test_each_distinguisher_well_formed(self):
        for payload, marker, engines in _DISTINGUISHERS:
            self.assertGreater(len(payload), 0, "empty payload")
            self.assertGreater(len(marker), 0, f"empty marker for {payload!r}")
            self.assertGreater(len(engines), 0, f"no engines for {payload!r}")

    def test_jinja_twig_differentiator_pair_present(self):
        # The {{7*'7'}} pair MUST resolve differently for Jinja2 vs Twig.
        pair = [(p, m, e) for p, m, e in _DISTINGUISHERS if p == "{{7*'7'}}"]
        self.assertEqual(len(pair), 2,
                         "expected exactly 2 entries for {{7*'7'}} (Jinja+Twig)")
        markers = {entry[1] for entry in pair}
        self.assertEqual(markers, {"7777777", "49"},
                         "Jinja/Twig differentiator markers wrong")

    def test_single_engine_distinguishers_are_strong(self):
        # A distinguisher with only ONE candidate engine should produce a
        # marker that's harder to false-positive than just "49". E.g.
        # Jinja's '7777777' is single-engine.
        for payload, marker, engines in _DISTINGUISHERS:
            if len(engines) == 1 and marker == "49":
                # That's fine for {7*7} (smarty), but the marker shape
                # alone is weak — must be paired with syntax uniqueness.
                # Just assert payload is syntactically distinctive.
                self.assertTrue(
                    any(s in payload for s in ("{", "${", "<%", "#{", "@", "#set")),
                    f"single-engine {engines[0]} has no distinctive syntax",
                )


class CapabilityInvariants(unittest.TestCase):
    def test_every_capability_probe_well_formed(self):
        for engine, probes in _CAPABILITIES.items():
            self.assertTrue(probes, f"engine {engine} has no capability probes")
            for cap, payload, marker in probes:
                self.assertGreater(len(cap), 0)
                self.assertGreater(len(payload), 0)
                # marker may be "" for engines where any non-empty body is
                # the signal (razor), but that's only razor.
                if engine != "razor":
                    self.assertGreater(len(marker), 0,
                                       f"{engine}/{cap}: empty marker")

    def test_capability_payloads_do_not_contain_destructive_ops(self):
        # READ-ONLY contract. Detection probes must never invoke RCE
        # primitives like popen/exec/Runtime.exec/system/`backtick`/sleep.
        FORBIDDEN = ("popen(", "Runtime.exec", "system(", "exec(",
                     "sleep(", "execSync", "child_process")
        for engine, probes in _CAPABILITIES.items():
            for cap, payload, _ in probes:
                for f in FORBIDDEN:
                    self.assertNotIn(
                        f, payload,
                        f"{engine}/{cap}: detection payload contains "
                        f"destructive primitive {f!r} — move to confirm_rce",
                    )


class BlindGadgetInvariants(unittest.TestCase):
    def test_every_blind_gadget_has_secs_placeholder(self):
        for engine, gadget in _BLIND_SLEEPS.items():
            self.assertIn(
                "__SECS__", gadget,
                f"blind gadget for {engine} missing __SECS__ placeholder",
            )

    def test_blind_engines_overlap_with_known(self):
        # Every blind-sleep engine should be a known engine elsewhere.
        known = set(_CAPABILITIES) | {e for e, _ in _POLYGLOT_HINTS}
        for engine in _BLIND_SLEEPS:
            self.assertIn(engine, known,
                          f"blind engine {engine} unknown to other phases")


class RequestBuilder(unittest.TestCase):
    def test_get_appends_param(self):
        r = _build_request("https://x.test/path", "name", "GET", "{{7*7}}")
        self.assertEqual(r["method"], "GET")
        # URL-encoded: %7B%7B...%7D%7D
        self.assertIn("name=%7B%7B7%2A7%7D%7D", r["url"])
        self.assertNotIn("data", r)

    def test_get_with_existing_query_uses_amp(self):
        r = _build_request("https://x.test/p?a=1", "name", "GET", "v")
        self.assertIn("?a=1&name=v", r["url"])

    def test_post_puts_body(self):
        r = _build_request("https://x.test/p", "name", "POST", "{{7*7}}")
        self.assertEqual(r["method"], "POST")
        self.assertEqual(r["url"], "https://x.test/p")
        self.assertIn("name=%7B%7B7%2A7%7D%7D", r["data"])


if __name__ == "__main__":
    unittest.main()
