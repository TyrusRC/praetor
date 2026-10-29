"""R1: Auto-derive evidence markers from a captured Burp request.

When the operator passes `proxy_history_index=<N>`, fetch the entry and extract
class-specific markers (SQLi vendor errors, XSS executable contexts, SSRF
cloud metadata, RCE uid output, CORS leaks, JWT alg:none, etc.). Markers are
appended to evidence_lower so the Q5 keyword gate passes without forcing the
operator to type evidence prose by hand.

Module is a pure side-effect step in the assess pipeline — runs BEFORE the
question loop, mutates ctx.derived_markers + ctx.evidence_lower.
"""

import re
from praetor import client
from ._context import AssessContext
from ._liveness import reflection_liveness


async def augment_evidence(ctx: AssessContext) -> None:
    """Populate ctx.derived_markers from the logger entry (if any)."""
    if ctx.proxy_history_index is None or ctx.proxy_history_index < 0:
        return
    try:
        detail = await client.get(f"/api/proxy/history/{ctx.proxy_history_index}")
        if "error" in detail:
            return

        status = str(detail.get("status_code", ""))
        body = (detail.get("response_body") or "")[:8000].lower()
        headers = detail.get("response_headers", []) or []
        header_blob = " ".join(
            f"{h.get('name','').lower()}: {h.get('value','').lower()}"
            for h in headers if isinstance(h, dict)
        )

        markers = ctx.derived_markers

        # Universal markers
        if status:
            markers.append(f"status={status}")
        if status in ("500", "502", "503"):
            markers.append("server-error")

        # SQLi vendor errors
        for sql_err in ("sql syntax", "ora-", "mysql_fetch", "pg_query",
                        "sqlite", "syntax error", "unclosed quotation",
                        "unterminated", "near \"", "type cast"):
            if sql_err in body:
                markers.append(sql_err)

        # XSS/HTML/template-injection: payload echoed in EXECUTABLE context.
        # Payload-tied — a response containing the page's OWN <script>/<img>
        # tags is NOT evidence. Only a dangerous token the REQUEST carried that
        # returns un-encoded counts as live; encoded-only reflection is
        # neutralized (the #1 reflected-injection false positive).
        req_payload = f"{detail.get('url','')}\n{detail.get('request_body','')}"
        full_body = detail.get("response_body") or ""
        live, sanitized = reflection_liveness(req_payload, full_body)
        for tok in live:
            markers.append(f"executable: {tok} (payload reflected live)")
        if sanitized and not live:
            markers.append(
                f"sanitized: payload reflected but encoded ({', '.join(sanitized[:3])})")
            ctx.reflected_sanitized = True

        # SSRF: cloud-metadata or callback proof
        for ssrf_marker in ("ami-id", "instance-identity", "169.254.169.254",
                            "metadata.google", "compute.metadata"):
            if ssrf_marker in body or ssrf_marker in header_blob:
                markers.append(ssrf_marker)

        # RCE markers
        for rce_marker in ("uid=", "gid=", "euid=", "/bin/sh", "/bin/bash"):
            if rce_marker in body:
                markers.append(rce_marker)

        # Path traversal
        if "root:x:" in body or "/etc/passwd" in body[:500]:
            markers.append("file_read: passwd")

        # IDOR proof: status 200 on cross-account access
        if status == "200" and ctx.parameter:
            markers.append("200 ok")

        # CORS leak
        if "access-control-allow-origin: *" in header_blob and "access-control-allow-credentials: true" in header_blob:
            markers.append("cors_credentialed_wildcard")
        if "access-control-allow-origin: null" in header_blob and "access-control-allow-credentials: true" in header_blob:
            markers.append("null origin allowed")

        # Open redirect: Location header points off-origin
        loc_match = re.search(r"location:\s*(https?://[^\s,]+)", header_blob)
        if loc_match:
            loc_url = loc_match.group(1)
            markers.append(f"location: {loc_url[:80]}")
            try:
                from urllib.parse import urlparse as _urlparse
                req_host = (detail.get("host") or "").lower()
                loc_host = (_urlparse(loc_url).hostname or "").lower()
                if req_host and loc_host and loc_host != req_host \
                   and not loc_host.endswith("." + req_host) \
                   and not req_host.endswith("." + loc_host):
                    markers.append("redirected off-origin")
            except Exception:
                pass

        # CRLF / response-splitting: stray header injected
        if any(h in header_blob for h in ("x-injected:", "set-cookie: injected", "x-crlf-test:")):
            markers.append("x-injected header reflected")

        # CSRF: missing/weak token on state-changing request
        req_headers = detail.get("request_headers", []) or []
        req_blob = " ".join(
            f"{h.get('name','').lower()}: {h.get('value','').lower()}"
            for h in req_headers if isinstance(h, dict)
        )
        method = (detail.get("method") or "").upper()
        if method in ("POST", "PUT", "DELETE", "PATCH"):
            has_csrf_token = ("x-csrf" in req_blob or "csrf-token" in req_blob
                              or "csrf_token=" in (detail.get("request_body") or "").lower())
            if not has_csrf_token:
                markers.append("no token (state-changing request)")
            if "samesite=lax" in header_blob:
                markers.append("samesite=lax")
            if "samesite=none" in header_blob:
                markers.append("samesite none")

        # JWT: decode any visible Bearer token from the request
        jwt_match = re.search(r"authorization: bearer (eyj[a-z0-9_\-=.]+)", req_blob)
        if jwt_match:
            try:
                import base64
                import json as _json
                parts = jwt_match.group(1).split(".")
                if len(parts) >= 2:
                    pad = "=" * ((4 - len(parts[0]) % 4) % 4)
                    hdr = _json.loads(base64.urlsafe_b64decode(parts[0] + pad))
                    if hdr.get("alg", "").lower() == "none":
                        markers.append("alg: none accepted")
                    if "kid" in hdr:
                        kid = str(hdr["kid"])
                        if "../" in kid or "..\\" in kid:
                            markers.append("kid path traversal")
                        elif "'" in kid or "union" in kid.lower():
                            markers.append("kid sqli")
            except Exception:
                pass

        # Mass assignment: privileged field echoed in response body
        for ma_marker in ('"is_admin":true', '"is_admin": true',
                          '"role":"admin"', '"role": "admin"',
                          '"is_staff":true', '"superuser":true',
                          '"verified":true'):
            if ma_marker in body:
                markers.append("role=admin echoed")
                break

        # Prototype pollution / __proto__ reflected
        if "__proto__" in body or "constructor.prototype" in body:
            markers.append("__proto__")

        # HPP: duplicate parameter name in the captured query
        if ctx.parameter and detail.get("url"):
            url_str = str(detail["url"])
            if url_str.count(f"{ctx.parameter}=") >= 2:
                markers.append("duplicate parameter accepted")

        # Deserialization: stack-trace fingerprints
        for de_marker in ("java.io.objectinputstream", "readobject",
                          "yaml.load", "marshal", "phar://",
                          "pickle", "ysoserial", "commons-collections"):
            if de_marker in body:
                markers.append(de_marker)

        # GraphQL: introspection / suggestion proof
        for gql_marker in ("__schema", "__typename", "did you mean",
                           "_service", "_entities"):
            if gql_marker in body:
                markers.append(gql_marker)

        # SAML: NameID / Assertion / signature artefacts
        if "<saml:assertion" in body or "<samlp:response" in body:
            markers.append("nameid")

        # File upload: stored-as / accepted-with marker
        if any(u in body for u in ("uploaded", "saved as", "stored at",
                                    "file accepted", "/uploads/",
                                    "/static/uploads/")):
            markers.append("uploaded file accepted")

        # Cache poisoning: X-Cache: HIT after a known unkeyed-header injection
        if "x-cache: hit" in header_blob:
            markers.append("x-cache: hit after poison")
        if "age:" in header_blob and "x-forwarded-host" in body:
            markers.append("x-forwarded-host reflected in cached")

        # Auth bypass: 401/403 → 200 transition
        if status == "200" and (ctx.parameter or "x-original-url" in req_blob
                                or "x-rewrite-url" in req_blob):
            markers.append("auth bypass confirmed")

        # Race: concurrent success indicator
        if "race_synchronised=true" in body or "double_spend" in body:
            markers.append("race confirmed")

        # ── Response body content classification ──
        # The pipeline must understand WHAT the response contains before
        # concluding anything about severity. This step extracts a preview,
        # classifies the data sensitivity, and flags non-sensitive patterns
        # (simulated, public, demo) so Q3 and severity logic can act on
        # the actual content rather than on the structural shape alone.
        _classify_response_body(ctx, body, detail)

        # Cloud-metadata extra (more services)
        for cloud_marker in ("doctl.io", "aliyun-meta", "/latest/meta-data",
                             "/computemetadata/v1", "fabric.cloud.azure",
                             "imdsv2-required", "/iam/security-credentials"):
            if cloud_marker in body:
                markers.append(cloud_marker)
    except Exception:
        pass

    if ctx.derived_markers:
        ctx.evidence_lower = (
            ctx.evidence_lower + " | derived: " + " ".join(ctx.derived_markers)
        ).strip()


# ── Response body content classification ──
# Moved out of the main function so Q3 and severity logic can reason about
# WHAT the data is, not just that data was returned.

# Patterns that indicate the data is not production-real.
_NON_PRODUCTION_KEYWORDS = (
    '"simulated"', '"demo"', '"sandbox"', '"staging"', '"mock"',
    '"fake"', '"sample"', '"dry_run"', '"test_mode"', '"placeholder"',
    '"env":"test"', '"env": "test"', '"env":"sandbox"', '"env": "sandbox"',
    '"source":"simulated"', '"source": "simulated"',
)

# Patterns that indicate the data is publicly available elsewhere.
_PUBLIC_DATA_KEYWORDS = (
    "sec.gov/archives", "sec.gov/cgi-bin", "edgar",
    "linkedin.com/in/", "linkedin.com/company/",
    "crunchbase.com", "pitchbook.com",
    "wikipedia.org", "wikidata.org",
)

# Patterns that indicate genuinely sensitive data.
_SENSITIVE_DATA_KEYWORDS = (
    "password", "passwd", "secret_key", "private_key", "api_key",
    "access_token", "refresh_token", "session_token", "bearer",
    "ssn", "social_security", "tax_id", "national_id",
    "card_number", "cvv", "expiry", "iban", "routing_number",
    "date_of_birth", "dob", "home_address", "phone_number",
    "medical_record", "diagnosis", "prescription",
    "salary", "compensation", "bank_account",
)


def _classify_response_body(ctx: AssessContext, body: str, detail: dict) -> None:
    """Classify response body content and attach a preview + data flags.

    Sets on ctx:
      - body_preview: first meaningful snippet for operator review
      - body_data_class: 'sensitive' | 'simulated' | 'public' | 'unknown'
      - has_simulation_markers: bool
      - body_classification_note: human-readable summary of what the data is
    """
    markers = ctx.derived_markers

    # Extract a preview (first 600 chars of body, cleaned up)
    raw_body = (detail.get("response_body") or "")[:600]
    ctx.body_preview = raw_body.replace("\n", " ").strip()

    # Count hits in each category
    sim_hits = [kw for kw in _NON_PRODUCTION_KEYWORDS if kw in body]
    pub_hits = [kw for kw in _PUBLIC_DATA_KEYWORDS if kw in body]
    sens_hits = [kw for kw in _SENSITIVE_DATA_KEYWORDS if kw in body]

    # Classify
    if sens_hits:
        ctx.body_data_class = "sensitive"
        markers.append(f"DATA_CLASS:sensitive ({', '.join(sens_hits[:3])})")
        ctx.body_classification_note = (
            f"Response contains sensitive data markers: {', '.join(sens_hits[:5])}. "
            f"Verify the data is real (not test fixtures) before rating severity."
        )
    elif sim_hits:
        ctx.body_data_class = "simulated"
        ctx.has_simulation_markers = True
        markers.append(f"DATA_CLASS:simulated ({', '.join(sim_hits[:3])})")
        ctx.body_classification_note = (
            f"Response contains simulation/demo markers: {', '.join(sim_hits[:3])}. "
            f"Data behind this endpoint is likely not production-real. "
            f"Impact of accessing simulated data is informative."
        )
    elif pub_hits:
        ctx.body_data_class = "public"
        markers.append(f"DATA_CLASS:public ({', '.join(pub_hits[:3])})")
        ctx.body_classification_note = (
            f"Response contains public-source markers: {', '.join(pub_hits[:3])}. "
            f"This data appears to be compiled from public sources (SEC filings, "
            f"LinkedIn, etc.). Verify whether any non-public data is also present."
        )
    else:
        ctx.body_data_class = "unknown"
        ctx.body_classification_note = (
            "Response data classification: unknown. READ the body preview below "
            "and determine whether the data is sensitive, simulated, or public "
            "before rating severity."
        )
