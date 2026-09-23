"""Regression tests for the codebase-audit gap sweep.

Each test reproduces one verified defect from the audit and locks the fix.
Grouped by wave; see the sweep branch commits for the corresponding change.
"""

from __future__ import annotations

import inspect
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from cryptography.fernet import Fernet

from praetor import server
from praetor.tools.testing_extended import quota_window, host_header, smuggling, line_item_mutation


def _tool(name: str):
    return server.mcp._tool_manager._tools[name].fn


# ── Wave 1: crashes & verdict type-safety ────────────────────────────────

class OastDecryptGracefulTest(unittest.IsolatedAsyncioTestCase):
    """_oast_tools.py:196 referenced base64.binascii.Error with no `import base64`,
    so the common wrong-key/corrupt-token path raised NameError instead of the
    graceful error message. The whole failure branch was dead."""

    async def test_bad_token_returns_graceful_error_not_nameerror(self):
        key = Fernet.generate_key()
        with patch("praetor.tools.collaborate._oast_tools._get_oast_fernet",
                   return_value=(Fernet(key), key.decode(), None)):
            fn = _tool("decrypt_oast_capture")
            out = await fn(ciphertext="!!!not-a-valid-token!!!")
        self.assertIsInstance(out, str)
        self.assertIn("decryption failed", out.lower())


class IdempotencyVerdictTest(unittest.IsolatedAsyncioTestCase):
    """idempotency_key.py: (a) canonical-send error returned a raw str from a
    `-> dict` tool; (b) critical_keywords never matched the emitted tokens, so a
    cross-principal / double-charge hit fell to SUSPECTED instead of CONFIRMED."""

    async def test_canonical_error_returns_verdict_dict(self):
        async def fake_post(path, json=None):
            return {"error": "session dead"}
        with patch("praetor.tools.testing_extended.idempotency_key.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_idempotency_key")
            out = await fn(session_primary="p", endpoint="/pay", body={"amount": 1})
        self.assertIsInstance(out, dict)
        self.assertEqual(out["verdict"], "ERROR")

    async def test_cross_principal_hit_is_confirmed(self):
        async def fake_post(path, json=None):
            return {"status": 200, "response_body": '{"ok":1}'}
        with patch("praetor.tools.testing_extended.idempotency_key.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_idempotency_key")
            out = await fn(session_primary="p", endpoint="/pay",
                           body={"amount": 1}, session_secondary="s")
        self.assertEqual(out["verdict"], "CONFIRMED")


class VerdictToolSourceGuardTest(unittest.TestCase):
    """Static guards against the exact regressions fixed this wave: a verdict
    tool must not return a raw string, and quota's off-by-one predicate must
    match the emitted DOUBLE_CONSUME token (underscore, not space)."""

    def test_quota_double_consume_token_matches_predicate(self):
        src = Path(quota_window.__file__).read_text(encoding="utf-8")
        self.assertIn('"DOUBLE_CONSUME"', src)          # predicate uses the real token
        self.assertNotIn('"DOUBLE CONSUME"', src)       # not the space-typo that never matched

    def test_no_raw_string_returns_from_dict_verdict_tools(self):
        for mod in (host_header, smuggling, line_item_mutation):
            src = inspect.getsource(mod)
            self.assertNotIn("return scope_err", src,
                             f"{mod.__name__} returns a raw scope str from a -> dict tool")
            self.assertNotIn('return "\\n".join(lines)', src,
                             f"{mod.__name__} returns a raw joined str from a -> dict tool")


# ── Wave 2: exploit-confirm reflection / OOB coercion ────────────────────

class ConfirmReflectionGuardTest(unittest.IsolatedAsyncioTestCase):
    """The marker frame rides in the outbound payload, so pure input reflection
    used to yield a false CONFIRMED. Reflection must resolve to INCONCLUSIVE."""

    async def test_confirm_rce_reflection_is_inconclusive(self):
        async def fake_post(path, json=None):
            # App echoes the decoded payload verbatim (search box, error page):
            body = "you searched for: ; echo M-deadbeef-START; id; echo M-deadbeef-END — no results"
            return {"response_body": body, "status_code": 200, "proxy_index": 5}
        with patch("praetor.tools.exploit.confirm_rce.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("praetor.tools.exploit.confirm_rce.make_marker",
                   return_value="m-deadbeef"):
            fn = _tool("confirm_rce")
            out = await fn(endpoint="https://t/x", parameter="cmd",
                           command="id", os="linux", wrapper_index=0)
        self.assertEqual(out["verdict"], "INCONCLUSIVE")

    async def test_confirm_sqli_reflection_is_inconclusive(self):
        # App echoes the sent union payload verbatim (marker M-M-deadbeef included).
        async def fake_post(path, json=None):
            body = "results for '+UNION+SELECT+'M-M-deadbeef',VERSION()--+- : none found"
            return {"response_body": body, "status_code": 200, "proxy_index": 8}
        with patch("praetor.tools.exploit.confirm_sqli.client.post",
                   new=AsyncMock(side_effect=fake_post)), \
             patch("praetor.tools.exploit.confirm_sqli.make_marker",
                   return_value="M-deadbeef"):
            fn = _tool("confirm_sqli")
            out = await fn(endpoint="https://t/x", parameter="id",
                           dbms="mysql", strategy="union")
        self.assertEqual(out["verdict"], "INCONCLUSIVE")


# ── Wave 3: network / probe validity gates ───────────────────────────────

class RateLimitValidityTest(unittest.IsolatedAsyncioTestCase):
    """All requests erroring (dead session) used to yield CONFIRMED 'no rate
    limiting'. Zero successful requests must be INCONCLUSIVE."""

    async def test_all_errored_is_inconclusive(self):
        async def fake_post(path, json=None):
            return {"error": "connection refused"}
        with patch("praetor.tools.testing.rate_limit.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("test_rate_limit")
            out = await fn(session="s", method="GET", path="/login", requests_count=5)
        self.assertEqual(out["verdict"], "INCONCLUSIVE")


# ── Wave 3b: probe-validity gate (all sub-probes errored) ────────────────

class TallyValidityGateTest(unittest.TestCase):
    """verdict_from_tally: zero valid runs is INCONCLUSIVE, not FAILED — the
    shared guard behind the ~10 probe modules that count sub-probe hits."""

    def test_zero_valid_runs_is_inconclusive(self):
        from praetor.tools.testing._verdict import verdict_from_tally
        self.assertEqual(verdict_from_tally(0, valid_runs=0)[0], "INCONCLUSIVE")
        # untracked (None) keeps the old two-outcome behaviour
        self.assertEqual(verdict_from_tally(0)[0], "FAILED")
        self.assertEqual(verdict_from_tally(0, valid_runs=3)[0], "FAILED")
        self.assertEqual(verdict_from_tally(2, valid_runs=3)[0], "CONFIRMED")


class WorkflowReorderBrokenBaselineTest(unittest.IsolatedAsyncioTestCase):
    """A broken legitimate happy-path used to still emit FAILED 'workflow
    defended'. A baseline that does not complete is INCONCLUSIVE."""

    async def test_broken_baseline_is_inconclusive(self):
        async def fake_post(path, json=None):
            return {"status": 500, "response_body": "err"}  # final step never 2xx
        with patch("praetor.tools.testing_extended.workflow_reorder.client.post",
                   new=AsyncMock(side_effect=fake_post)):
            fn = _tool("probe_workflow_reorder")
            out = await fn(session="s",
                           steps=[{"method": "POST", "path": "/a"},
                                  {"method": "POST", "path": "/b"}])
        self.assertEqual(out["verdict"], "INCONCLUSIVE")


# ── Wave 4: save-finding gate holes ──────────────────────────────────────

class NeverSubmitConditionalGateTest(unittest.TestCase):
    """save_finding's never_submit_gate enforced only the unconditional set, so a
    conditional class (cors_no_creds) persisted standalone. It now mirrors q6."""

    def test_conditional_class_standalone_rejected(self):
        from praetor.tools.notes.save._gates import never_submit_gate
        self.assertIsNotNone(never_submit_gate("cors_no_creds", None, set(), "/api/x"))

    def test_conditional_class_chained_allowed(self):
        from praetor.tools.notes.save._gates import never_submit_gate
        self.assertIsNone(never_submit_gate("cors_no_creds", ["f1"], set(), "/api/x"))

    def test_conditional_class_override_allowed(self):
        from praetor.tools.notes.save._gates import never_submit_gate
        self.assertIsNone(
            never_submit_gate("cors_no_creds", None, {"q6_never_submit"}, "/api/x"))


class ScannerProofGateTest(unittest.TestCase):
    """Rule 13c on the save path: a scanner-sourced claim with no independent
    corroboration is ineligible (assess enforced it; a direct save did not)."""

    def _g(self, **kw):
        from praetor.tools.notes.save._gates import scanner_proof_gate
        args = dict(evidence_text="", evidence={}, reproductions=None,
                    human_verified=False, impact="", description="", override_set=set())
        args.update(kw)
        return scanner_proof_gate(
            args["evidence_text"], args["evidence"], args["reproductions"],
            args["human_verified"], args["impact"], args["description"],
            args["override_set"])

    def test_bare_scanner_claim_rejected(self):
        self.assertIsNotNone(self._g(evidence_text="nuclei template matched on /x"))

    def test_scanner_with_captured_index_passes(self):
        self.assertIsNone(self._g(evidence_text="nuclei flagged",
                                  evidence={"proxy_history_index": 5}))

    def test_scanner_human_verified_passes(self):
        self.assertIsNone(self._g(evidence_text="nuclei flagged", human_verified=True))

    def test_scanner_override_passes(self):
        self.assertIsNone(self._g(evidence_text="nuclei flagged",
                                  override_set={"scanner_proof"}))

    def test_non_scanner_evidence_passes(self):
        self.assertIsNone(self._g(evidence_text="manual UNION SELECT extracted version()"))


class SeverityCapCanonicalTest(unittest.TestCase):
    """severity_cap_for keyed on non-canonical spellings, so the canonical class
    missed its cap and could false-reject an honestly-capped LOW."""

    def test_canonical_class_hits_noncanonical_cap_key(self):
        from praetor.tools.report.severity import severity_cap_for
        canon_cap = severity_cap_for("missing_headers")
        raw_cap = severity_cap_for("missing_security_header")
        self.assertTrue(canon_cap)                 # canonical spelling now finds a cap
        self.assertEqual(canon_cap, raw_cap)


class DedupCanonicalTest(unittest.TestCase):
    """Dedup keyed on raw-lower vuln_type, so two spellings of one class on the
    same endpoint created two records instead of merging."""

    def test_spelling_variants_merge(self):
        from praetor.tools.notes._findings_dedupe import _dedupe_finding
        existing = [{"id": "f1", "endpoint": "/x", "vuln_type": "reflected_xss",
                     "title": "xss", "parameter": "q", "status": "confirmed"}]
        new = {"endpoint": "/x", "vuln_type": "xss_reflected", "title": "xss",
               "parameter": "q", "status": "confirmed"}
        out, action, _idx = _dedupe_finding(existing, new)
        self.assertEqual(action, "updated")        # merged, not a second record
        self.assertEqual(len(out), 1)


# ── Wave 6: latent NameError crashes (used-but-not-imported) ─────────────

class UndefinedNameCrashTest(unittest.IsolatedAsyncioTestCase):
    """saml_xsw_probe used `client`/`base64` and web_llm_sweep used `client`/
    `urljoin`/`_LLM02_PAYLOAD` without importing them — every call NameError'd on
    the first scope check. Guard the exact names each module needs at runtime."""

    def test_saml_xsw_probe_has_runtime_names(self):
        import praetor.tools.saml_xsw_probe as m
        for n in ("client", "base64"):
            self.assertTrue(hasattr(m, n), f"saml_xsw_probe missing {n}")

    def test_web_llm_sweep_has_runtime_names(self):
        import praetor.tools.web_llm_sweep._sweep as m
        for n in ("client", "urljoin", "_LLM02_PAYLOAD"):
            self.assertTrue(hasattr(m, n), f"web_llm_sweep._sweep missing {n}")

    async def test_saml_xsw_probe_runs_without_nameerror(self):
        # Exercises the client.check_scope (line 79) and base64.b64decode (line 85)
        # paths that used to raise NameError before the imports were added.
        with patch("praetor.tools.saml_xsw_probe.client.check_scope",
                   new=AsyncMock(return_value={"in_scope": True})):
            fn = _tool("probe_saml_xsw")
            out = await fn(acs_url="https://t/acs", saml_response_b64="aGVsbG8=")
        self.assertIsInstance(out, dict)


if __name__ == "__main__":
    unittest.main()
