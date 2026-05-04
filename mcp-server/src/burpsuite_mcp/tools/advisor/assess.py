"""assess_finding: 7-Question Validation Gate before save_finding.

Implements the rule pipeline (Q1 scope, Q2 reproducibility, Q4 dedup, Q5
evidence quality, Q6 NEVER-SUBMIT, Q7 triager-mass-report) plus auto-evidence
augmentation from logger_index, business-context impact scoring, grey-box
session boost, program-policy overrides, and confidence/severity inference.
"""

import json
import re
from pathlib import Path

from burpsuite_mcp import client
from burpsuite_mcp.tools.advisor._helpers import vuln_root
from burpsuite_mcp.tools.advisor_kb import (
    AUTH_STATE_DEPENDENT,
    CONDITIONAL_NEVER_SUBMIT_TYPES,
    LOW_IMPACT_CLASSES,
    NEVER_SUBMIT_KEYWORDS,
    NEVER_SUBMIT_TYPES,
    Q5_ALIASES,
    Q5_KEYWORDS,
    SENSITIVE_ENDPOINT_PATTERNS,
    TIMING_VULN_TYPES,
)


async def assess_finding_impl(
    vuln_type: str,
    evidence: str,
    endpoint: str,
    parameter: str = "",
    response_diff: str = "",
    domain: str = "",
    business_context: str = "",
    environment: str = "",
    logger_index: int = -1,
    human_verified: bool = False,
    overrides: list[str] | None = None,
    chain_with: list[str] | None = None,
    reproductions: list[dict] | None = None,
    session_name: str = "",
) -> str:
    issues = []
    audit_overrides: list[str] = []
    verdict = "REPORT"
    override_set: set[str] = set()
    for ov in (overrides or []):
        gate = (ov.split(":", 1)[0] if ":" in ov else ov).strip().lower()
        if gate:
            override_set.add(gate)
            audit_overrides.append(ov)

    # NEVER SUBMIT tables live in advisor_kb (lifted out of this closure
    # so the dicts are allocated once at import, not on every assess_finding
    # call). `never_submit_types` is a mutable copy because the per-program
    # policy below may pop entries from it.
    never_submit_types = dict(NEVER_SUBMIT_TYPES)
    conditional_never_submit_types = CONDITIONAL_NEVER_SUBMIT_TYPES
    sensitive_endpoint_patterns = SENSITIVE_ENDPOINT_PATTERNS
    never_submit_keywords = NEVER_SUBMIT_KEYWORDS

    vuln_lower = vuln_type.lower()
    evidence_lower = evidence.lower()

    # ── R1: Auto-augment evidence from logger_index ────────────────
    # Hunters often confirm via Burp UI but write thin prose evidence.
    # When a concrete proxy/logger index is provided, fetch the entry
    # and append class-specific markers programmatically. Result: Q5
    # passes on automation evidence the human didn't bother to type.
    derived_markers: list[str] = []
    if logger_index is not None and logger_index >= 0:
        try:
            detail = await client.get(f"/api/proxy/history/{logger_index}")
            if "error" not in detail:
                status = str(detail.get("status_code", ""))
                body = (detail.get("response_body") or "")[:8000].lower()
                headers = detail.get("response_headers", []) or []
                header_blob = " ".join(
                    f"{h.get('name','').lower()}: {h.get('value','').lower()}"
                    for h in headers if isinstance(h, dict)
                )

                # Universal markers
                if status:
                    derived_markers.append(f"status={status}")
                if status in ("500", "502", "503"):
                    derived_markers.append("server-error")

                # SQLi vendor errors
                for sql_err in ("sql syntax", "ora-", "mysql_fetch", "pg_query",
                                "sqlite", "syntax error", "unclosed quotation",
                                "unterminated", "near \"", "type cast"):
                    if sql_err in body:
                        derived_markers.append(sql_err)

                # XSS: payload echoed in executable context
                for xss_marker in ("<script", "onerror=", "onload=", "javascript:",
                                   "alert(", "<svg", "<img"):
                    if xss_marker in body:
                        derived_markers.append(f"executable: {xss_marker}")

                # SSRF: cloud-metadata or callback proof
                for ssrf_marker in ("ami-id", "instance-identity", "169.254.169.254",
                                    "metadata.google", "compute.metadata"):
                    if ssrf_marker in body or ssrf_marker in header_blob:
                        derived_markers.append(ssrf_marker)

                # RCE markers
                for rce_marker in ("uid=", "gid=", "euid=", "/bin/sh", "/bin/bash"):
                    if rce_marker in body:
                        derived_markers.append(rce_marker)

                # Path traversal
                if "root:x:" in body or "/etc/passwd" in body[:500]:
                    derived_markers.append("file_read: passwd")

                # IDOR proof: status 200 on cross-account access
                if status == "200" and parameter:
                    derived_markers.append("200 ok")

                # CORS leak
                if "access-control-allow-origin: *" in header_blob and "access-control-allow-credentials: true" in header_blob:
                    derived_markers.append("cors_credentialed_wildcard")
                if "access-control-allow-origin: null" in header_blob and "access-control-allow-credentials: true" in header_blob:
                    derived_markers.append("null origin allowed")

                # Open redirect: Location header points off-origin
                loc_match = re.search(r"location:\s*(https?://[^\s,]+)", header_blob)
                if loc_match:
                    loc_url = loc_match.group(1)
                    derived_markers.append(f"location: {loc_url[:80]}")
                    # Extract location host vs request host (best-effort)
                    try:
                        from urllib.parse import urlparse as _urlparse
                        req_host = (detail.get("host") or "").lower()
                        loc_host = (_urlparse(loc_url).hostname or "").lower()
                        if req_host and loc_host and loc_host != req_host \
                           and not loc_host.endswith("." + req_host) \
                           and not req_host.endswith("." + loc_host):
                            derived_markers.append("redirected off-origin")
                    except Exception:
                        pass

                # CRLF / response-splitting: stray header injected
                if any(h in header_blob for h in ("x-injected:", "set-cookie: injected", "x-crlf-test:")):
                    derived_markers.append("x-injected header reflected")

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
                        derived_markers.append("no token (state-changing request)")
                    if "samesite=lax" in header_blob:
                        derived_markers.append("samesite=lax")
                    if "samesite=none" in header_blob:
                        derived_markers.append("samesite none")

                # JWT: decode any visible Bearer token from the request
                jwt_match = re.search(r"authorization: bearer (eyj[a-z0-9_\-=.]+)", req_blob)
                if jwt_match:
                    try:
                        import base64, json as _json
                        parts = jwt_match.group(1).split(".")
                        if len(parts) >= 2:
                            pad = "=" * ((4 - len(parts[0]) % 4) % 4)
                            hdr = _json.loads(base64.urlsafe_b64decode(parts[0] + pad))
                            if hdr.get("alg", "").lower() == "none":
                                derived_markers.append("alg: none accepted")
                            if "kid" in hdr:
                                kid = str(hdr["kid"])
                                if "../" in kid or "..\\" in kid:
                                    derived_markers.append("kid path traversal")
                                elif "'" in kid or "union" in kid.lower():
                                    derived_markers.append("kid sqli")
                    except Exception:
                        pass

                # Mass assignment: privileged field echoed in response body
                for ma_marker in ('"is_admin":true', '"is_admin": true',
                                  '"role":"admin"', '"role": "admin"',
                                  '"is_staff":true', '"superuser":true',
                                  '"verified":true'):
                    if ma_marker in body:
                        derived_markers.append("role=admin echoed")
                        break

                # Prototype pollution / __proto__ reflected
                if "__proto__" in body or "constructor.prototype" in body:
                    derived_markers.append("__proto__")

                # HPP: duplicate parameter name in the captured query
                if parameter and detail.get("url"):
                    url_str = str(detail["url"])
                    if url_str.count(f"{parameter}=") >= 2:
                        derived_markers.append("duplicate parameter accepted")

                # Deserialization: stack-trace fingerprints
                for de_marker in ("java.io.objectinputstream", "readobject",
                                  "yaml.load", "marshal", "phar://",
                                  "pickle", "ysoserial", "commons-collections"):
                    if de_marker in body:
                        derived_markers.append(de_marker)

                # GraphQL: introspection / suggestion proof
                for gql_marker in ("__schema", "__typename", "did you mean",
                                   "_service", "_entities"):
                    if gql_marker in body:
                        derived_markers.append(gql_marker)

                # SAML: NameID / Assertion / signature artefacts
                if "<saml:assertion" in body or "<samlp:response" in body:
                    derived_markers.append("nameid")

                # File upload: stored-as / accepted-with marker
                if any(u in body for u in ("uploaded", "saved as", "stored at",
                                            "file accepted", "/uploads/",
                                            "/static/uploads/")):
                    derived_markers.append("uploaded file accepted")

                # Cache poisoning: X-Cache: HIT after a known unkeyed-header injection
                if "x-cache: hit" in header_blob:
                    derived_markers.append("x-cache: hit after poison")
                if "age:" in header_blob and "x-forwarded-host" in body:
                    derived_markers.append("x-forwarded-host reflected in cached")

                # Auth bypass: 401/403 → 200 transition
                if status == "200" and (parameter or "x-original-url" in req_blob
                                        or "x-rewrite-url" in req_blob):
                    derived_markers.append("auth bypass confirmed")

                # Race: concurrent success indicator
                if "race_synchronised=true" in body or "double_spend" in body:
                    derived_markers.append("race confirmed")

                # Cloud-metadata extra (more services)
                for cloud_marker in ("doctl.io", "aliyun-meta", "/latest/meta-data",
                                     "/computemetadata/v1", "fabric.cloud.azure",
                                     "imdsv2-required", "/iam/security-credentials"):
                    if cloud_marker in body:
                        derived_markers.append(cloud_marker)
        except Exception:
            pass

    if derived_markers:
        evidence_lower = (evidence_lower + " | derived: " + " ".join(derived_markers)).strip()

    # ── Apply active program policy overrides (Rule 17 dynamic) ──
    # set_program_policy persists a per-engagement override; merge it on
    # top of the hardcoded defaults so programs that DO pay
    # tabnabbing/user_enum aren't auto-killed.
    try:
        from burpsuite_mcp.tools.intel import load_active_program_policy
        program = load_active_program_policy()
    except Exception:
        program = {}
    for k in program.get("never_submit_remove", []) or []:
        never_submit_types.pop(k, None)
    for k in program.get("never_submit_add", []) or []:
        never_submit_types.setdefault(
            k, f"Program-specific NEVER SUBMIT override ({k})"
        )
    program_confidence_floor = float(program.get("confidence_floor", 0.0) or 0.0)

    # Q1: Scope. SKIP on transient extension errors (R17). Only DO NOT
    # REPORT when the extension explicitly says out-of-scope.
    #
    # Domain resolution: prefer explicit `domain`, otherwise derive from a
    # full-URL endpoint. A bare path-only endpoint with no domain still SKIPs
    # — the advisor cannot verify scope without a host.
    effective_domain = domain
    if not effective_domain and "://" in endpoint:
        try:
            from urllib.parse import urlparse
            effective_domain = urlparse(endpoint).hostname or ""
        except Exception:
            effective_domain = ""

    if "q1_scope" in override_set:
        issues.append("Q1 OVERRIDE: scope check bypassed by operator")
    elif effective_domain:
        try:
            scope_resp = await client.post(
                "/api/scope/check",
                json={"url": endpoint if "://" in endpoint else f"https://{effective_domain}{endpoint}"},
            )
            if "error" in scope_resp:
                # Transient — extension unreachable / 500 / etc. Skip not Fail.
                issues.append(f"Q1 SKIP: scope check unavailable ({scope_resp['error'][:60]})")
            elif not scope_resp.get("in_scope", False):
                issues.append(f"Q1 FAIL: endpoint {endpoint} is OUT OF SCOPE — do not report")
                verdict = "DO NOT REPORT"
        except Exception as e:
            issues.append(f"Q1 SKIP: scope check raised ({type(e).__name__})")
    else:
        issues.append("Q1 SKIP: pass `domain=...` (or full URL endpoint) to enable scope verification")

    # Q2: Reproducible — AUTH_STATE_DEPENDENT lives in advisor_kb.
    q2_class_root = vuln_lower
    for sep in ("_blind", "_time", "_stored", "_reflected"):
        if q2_class_root.endswith(sep):
            q2_class_root = q2_class_root[: -len(sep)]
    if "q2_repro" in override_set:
        issues.append("Q2 OVERRIDE: reproducibility check bypassed")
    elif q2_class_root in AUTH_STATE_DEPENDENT:
        issues.append(
            f"Q2 EXEMPT: '{vuln_type}' is auth-state-dependent — same-session "
            "reproduction is correct (re-auth would lose the state being tested)"
        )
    elif any(w in evidence_lower for w in ("once", "intermittent", "one time", "non-reproducible", "could not reproduce")):
        issues.append("Q2 FAIL: evidence suggests non-reproducible — re-test 3+ times from clean state")

    # Q6: NEVER SUBMIT type match — word-boundary so `xss_filter_bypass`
    # doesn't mis-fire on `self_xss`, and `idor_via_csrf_logout` doesn't
    # trip `csrf_logout`. Conditional classes pass through if chain_with
    # is non-empty OR if the endpoint matches sensitive patterns (auth,
    # reset, OTP, payment) for the rate_limit_missing case.
    chain_provided = bool(chain_with)
    endpoint_lower = (endpoint or "").lower()
    endpoint_is_sensitive = any(p in endpoint_lower for p in sensitive_endpoint_patterns)

    if "q6_never_submit" in override_set:
        issues.append("Q6 OVERRIDE: NEVER SUBMIT bypass — must include chain_with[] in save_finding")
    else:
        # Hard NEVER SUBMIT — these never report standalone
        for ns_key, ns_reason in never_submit_types.items():
            if re.search(rf"(?<![a-z]){re.escape(ns_key)}(?![a-z])", vuln_lower):
                if chain_provided:
                    issues.append(
                        f"Q6 NEVER SUBMIT (chained): {ns_reason}. chain_with={chain_with} — "
                        f"will pass save_finding if anchors are confirmed and not stale."
                    )
                else:
                    issues.append(f"Q6 NEVER SUBMIT: {ns_reason}")
                    verdict = "DO NOT REPORT"
                break

        # Conditional NEVER SUBMIT — pass through with chain or sensitive endpoint
        if verdict == "REPORT":
            # Classes that flip from NEVER SUBMIT to reportable when the
            # endpoint matches the sensitive-pattern set: rate_limit,
            # clickjacking, csrf_logout, host_header_no_cache, options_method.
            # cors_no_creds, version_disclosure flip via chain only.
            ENDPOINT_GATED_KEYS = (
                "rate_limit", "clickjacking", "csrf_logout",
                "host_header_no_cache", "options_method",
            )
            for ns_key, ns_reason in conditional_never_submit_types.items():
                if not re.search(rf"(?<![a-z]){re.escape(ns_key)}(?![a-z])", vuln_lower):
                    continue
                if chain_provided:
                    issues.append(
                        f"Q6 CONDITIONAL (chained): {ns_reason}. chain_with={chain_with}."
                    )
                    break
                if any(ns_key.startswith(prefix) for prefix in ENDPOINT_GATED_KEYS) and endpoint_is_sensitive:
                    issues.append(
                        f"Q6 CONDITIONAL PASS: '{ns_key}' on sensitive endpoint ({endpoint}) "
                        "— reportable; sensitive-flow impact applies."
                    )
                    break
                issues.append(f"Q6 NEVER SUBMIT: {ns_reason}")
                verdict = "DO NOT REPORT"
                break

    # Q6: NEVER SUBMIT evidence-keyword match — skip when the keyword
    # appears in a NEGATED context. Hunters often write "not a stack
    # trace, the fingerprint is..." — that's a contrast, not a self-flag.
    # Heuristic: ignore the match if "not", "isn't", "no ", "without",
    # "instead of", "ruled out" appears within 24 chars BEFORE the keyword.
    if verdict == "REPORT" and "q6_never_submit" not in override_set:
        negation_window = 24
        negators = (" not ", " no ", "isn't ", "is not", "without ", "instead of", "ruled out", "not a ", "not just")
        for ns_key, ns_reason in never_submit_keywords.items():
            pattern = re.compile(rf"(?<![a-z]){re.escape(ns_key)}(?![a-z])")
            m = pattern.search(evidence_lower)
            if not m:
                continue
            # Look back up to negation_window chars
            lookback = evidence_lower[max(0, m.start() - negation_window):m.start()]
            if any(neg in lookback for neg in negators):
                continue  # negated — not actually a NEVER SUBMIT signal
            if chain_provided:
                issues.append(f"Q6 NEVER SUBMIT (chained): {ns_reason}. chain_with={chain_with}.")
                break
            issues.append(f"Q6 NEVER SUBMIT: {ns_reason}")
            verdict = "DO NOT REPORT"
            break

    # ── Q3 / Q5: Impact + evidence quality per vuln class ──────────
    # R2: expanded keyword lists; unknown vuln_type SKIPS Q5 (default REPORT
    # rather than weak). R19: human_verified bypasses Q5 entirely.
    weak_evidence = False


    q5_class = Q5_ALIASES.get(vuln_lower, vuln_lower)

    if human_verified:
        issues.append("Q5 SKIP: human_verified=True (operator confirmed in Burp UI/browser)")
        audit_overrides.append("q5_evidence:human_verified")
    elif "q5_evidence" in override_set:
        issues.append("Q5 OVERRIDE: evidence gate bypassed by operator")
    elif q5_class in Q5_KEYWORDS:
        keywords = Q5_KEYWORDS[q5_class]
        strong = any(k in evidence_lower for k in keywords)
        if strong and derived_markers:
            # Surface that auto-derivation contributed (R17)
            issues.append(
                f"Q5 SATISFIED: auto-derived markers from logger_index={logger_index} "
                f"({', '.join(derived_markers[:4])}{', ...' if len(derived_markers) > 4 else ''})"
            )
        if not strong:
            issues.append(
                f"Q5 WEAK EVIDENCE: {q5_class} needs at least one of: "
                f"{', '.join(keywords[:6])}, ... ({len(keywords)} accepted markers). "
                f"Pass logger_index=<N> to auto-derive, or human_verified=True if confirmed in UI."
            )
            weak_evidence = True
    else:
        # Unknown vuln_type — be cautious. Previously defaulted to REPORT,
        # which let labelled-as-{cors,jwt,graphql,mass_assignment,...}
        # bypass Q5 entirely. Now we mark weak so the operator must either
        # use a known label, supply human_verified=True, or pass
        # overrides=["q5_evidence:..."].
        issues.append(
            f"Q5 UNKNOWN VULN TYPE: '{vuln_type}' has no class-specific keyword set. "
            f"Available classes: {', '.join(sorted(Q5_KEYWORDS.keys()))}. "
            f"Either retag, pass human_verified=True, or overrides=['q5_evidence:<reason>']."
        )
        weak_evidence = True

    # ── R3: Timing-based requires 3x reproductions (TIMING_VULN_TYPES
    # lives in advisor_kb).
    if vuln_lower in TIMING_VULN_TYPES and "q5_evidence" not in override_set and not human_verified:
        # Accept either (a) >=3 entries in reproductions[] array or (b) keyword text
        replay_count = len(reproductions or [])
        has_replays = (
            replay_count >= 3
            or any(
                w in evidence_lower
                for w in ("3x", "three iterations", "3/3", "3 consistent",
                          "consistent across", "confirmed 3", "3 repeats", "repeated 3")
            )
        )
        if has_replays and replay_count >= 3:
            issues.append(
                f"Q5 TIMING SATISFIED: reproductions[] has {replay_count} entries "
                f"({sum(1 for r in reproductions if isinstance(r, dict) and 'logger_index' in r)} with logger_index)"
            )
        if not has_replays:
            issues.append(
                "Q5 TIMING RULE: timing/blind vuln types require 3+ consistent "
                "iterations — pass reproductions=[{logger_index, elapsed_ms, status_code}, ...] "
                "with len>=3, OR include '3/3' / 'confirmed 3' in evidence text"
            )
            weak_evidence = True

    # Q4: Duplicate check — read persisted findings if domain given.
    # Match must be on (endpoint, vuln_type root, parameter) tuple. Old
    # logic used substring `vuln_lower in f.get("vuln_type", "")` which
    # falsely deduped any `sqli` finding against any prior `sqli_blind`
    # / `sqli_time`, dropping legitimate distinct findings.
    if domain and verdict == "REPORT" and "q4_dedup" not in override_set:
        try:
            import re as _re
            sanitized = _re.sub(r'[^a-zA-Z0-9._-]', '_', domain)
            findings_path = Path.cwd() / ".burp-intel" / sanitized / "findings.json"
            if findings_path.exists():
                existing = json.loads(findings_path.read_text()).get("findings", [])
                new_root = vuln_root(vuln_lower)
                # R4: dedup ONLY when both new and existing have non-empty
                # parameter and they match. Empty parameter on either side
                # = treat as distinct, let through. Stops silent merging.
                for f in existing:
                    same_ep = f.get("endpoint", "") == endpoint
                    existing_root = vuln_root(f.get("vuln_type", ""))
                    same_type = (
                        new_root and existing_root and new_root == existing_root
                    )
                    existing_param = f.get("parameter", "") or ""
                    if not parameter or not existing_param:
                        same_param = False  # empty -> assume distinct
                    else:
                        same_param = existing_param == parameter
                    if same_ep and same_type and same_param:
                        issues.append(f"Q4 DUPLICATE: already saved as {f.get('id', '?')} — update instead of re-save")
                        verdict = "DO NOT REPORT"
                        break
        except (OSError, json.JSONDecodeError, ImportError):
            pass  # best-effort; no crash on missing intel

    # Q7: Triager-mass-report heuristic. If only weak-evidence flags and
    # a low-impact vuln class, the triager will mark informative — UNLESS
    # the finding is chained, in which case the chain provides the impact
    # context that elevates it above mass-report territory.
    # LOW_IMPACT_CLASSES lives in advisor_kb.
    if "q7_triager" in override_set:
        issues.append("Q7 OVERRIDE: triager-mass-report heuristic bypassed")
    elif chain_provided and vuln_lower in LOW_IMPACT_CLASSES:
        issues.append(
            f"Q7 SKIP: chain_with={chain_with} supplies impact context — "
            "low-impact root class is acceptable when chained"
        )
    elif verdict == "REPORT" and weak_evidence and vuln_lower in LOW_IMPACT_CLASSES:
        issues.append("Q7 TRIAGER TEST: low-impact class + weak evidence — likely marked informative. Chain with another finding first (pass chain_with=[<id>]).")
        verdict = "NEEDS MORE EVIDENCE"

    # Any weak-evidence flag alone downgrades from REPORT to NEEDS MORE EVIDENCE
    if verdict == "REPORT" and weak_evidence:
        verdict = "NEEDS MORE EVIDENCE"

    # ── Business Impact & Environment Scoring ──────────────────
    # Adjust severity based on what the target handles and where it runs.
    impact_boost = 0.0
    impact_notes = []

    biz = business_context.lower() if business_context else ""
    env = environment.lower() if environment else ""

    # High-value business contexts where same vuln has higher impact
    biz_multipliers = {
        "banking": ("financial data at risk", 0.10),
        "fintech": ("financial data at risk", 0.10),
        "healthcare": ("PHI/PII exposure — HIPAA implications", 0.10),
        "government": ("citizen data / national security", 0.08),
        "ecommerce": ("payment data / PCI scope", 0.08),
        "payment": ("payment data / PCI scope", 0.08),
        "saas": ("multi-tenant data leakage risk", 0.06),
        "social": ("user PII / account takeover risk", 0.05),
        "crypto": ("financial loss / wallet compromise", 0.10),
    }
    for biz_key, (reason, boost) in biz_multipliers.items():
        if biz_key in biz:
            impact_boost += boost
            impact_notes.append(f"Business context ({biz_key}): {reason} (+{boost:.0%})")
            break

    # Environment context
    if "production" in env or "prod" in env:
        impact_boost += 0.05
        impact_notes.append("Production environment: live user impact (+5%)")
    elif "internal" in env:
        impact_boost -= 0.05
        impact_notes.append("Internal environment: reduced external exposure (-5%)")

    # Vuln-class × business-context amplifiers
    high_impact_combos = {
        ("sqli", "banking"): "SQL injection on banking app = direct financial data access",
        ("sqli", "healthcare"): "SQL injection on healthcare = PHI breach",
        ("idor", "saas"): "IDOR on multi-tenant SaaS = cross-tenant data leak",
        ("idor", "ecommerce"): "IDOR on ecommerce = other users orders/payment data",
        ("ssrf", "cloud"): "SSRF on cloud-hosted = metadata credential theft",
        ("xss", "banking"): "XSS on banking = session hijack for financial access",
        ("auth_bypass", "payment"): "Auth bypass on payment = unauthorized transactions",
        ("rce", "production"): "RCE on production = full system compromise",
    }

    # ── Rule 28: Grey-box mode boost when session is authenticated ──
    # If session_name is provided, look it up via /api/session/list and
    # check whether it carries cookies or an Authorization header. An
    # authenticated session paired with an auth-state-dependent vuln
    # class deserves higher impact (cross-tenant, privilege escalation).
    grey_box_active = False
    if session_name:
        try:
            sess_list = await client.get("/api/session/list")
            if isinstance(sess_list, dict) and "error" not in sess_list:
                for s in sess_list.get("sessions", []) or []:
                    if not isinstance(s, dict):
                        continue
                    if s.get("name") != session_name:
                        continue
                    cookie_count = s.get("cookie_count", 0) or 0
                    has_auth = bool(s.get("has_auth_header") or s.get("auth_header"))
                    if cookie_count > 0 or has_auth:
                        grey_box_active = True
                    break
        except Exception:
            pass

    if grey_box_active and q2_class_root in AUTH_STATE_DEPENDENT:
        impact_boost += 0.10
        impact_notes.append(
            f"Grey-box mode (session='{session_name}' authenticated): "
            f"{q2_class_root} carries cross-tenant / privilege-escalation impact (+10%)"
        )

    # Predictable/sequential-ID escalator — independent of business context.
    # This is the "fuzz IDs to dump the table" class. High impact when the
    # endpoint returns PII or when the same ID space is shared across
    # ecosystem apps (see hunting Rule 6 — this is authz, NOT credential
    # brute-force).
    id_enum_signals = ("sequential", "predictable", "incrementing", "guessable",
                       "auto-increment", "id enumeration", "fuzz id", "enumerate id",
                       "same id space", "cross-app", "shared id")
    if any(s in evidence_lower for s in id_enum_signals):
        impact_boost += 0.08
        impact_notes.append(
            "Predictable/sequential ID exposure (+8%): ID range is fuzzable; "
            "full record set enumerable and likely reusable across apps in same ecosystem"
        )
    for (vtype, ctx), reason in high_impact_combos.items():
        if vtype in vuln_lower and (ctx in biz or ctx in env):
            impact_boost += 0.05
            impact_notes.append(f"High-impact combo: {reason}")
            break

    # Derive a suggested confidence in [0.0, 1.0]. Pass this straight to
    # save_finding(confidence=...). The thresholds line up with
    # ProxyHighlight's RED/ORANGE/YELLOW/GREEN mapping so the colour of
    # the proxy-history entry matches the gate's verdict.
    if verdict == "DO NOT REPORT":
        suggested_confidence = 0.05
    elif verdict == "NEEDS MORE EVIDENCE":
        # Weak evidence -> ORANGE-ish band. Each flag drags it down ~0.05,
        # floor at 0.40 so something survives to the hunter.
        penalty = max(0, len(issues) - 1) * 0.05
        suggested_confidence = max(0.40, 0.65 - penalty + impact_boost)
    elif not issues:
        # Verdict REPORT and zero gate issues — highest confidence.
        suggested_confidence = min(1.0, 0.92 + impact_boost)
    else:
        # REPORT with some non-fatal issues (e.g. Q1 skipped because no
        # domain passed). Slightly lower than the clean-pass case.
        suggested_confidence = min(1.0, 0.80 + impact_boost)

    # Apply program-policy confidence floor — emit a clearly distinct
    # "PROGRAM POLICY ENFORCED" banner so Claude does not mistake this
    # for a substantive evidence problem.
    if verdict == "REPORT" and program_confidence_floor > 0:
        if suggested_confidence < program_confidence_floor:
            issues.append(
                f"PROGRAM POLICY ENFORCED: program '{program.get('slug', '?')}' "
                f"sets confidence_floor={program_confidence_floor:.2f}; "
                f"current confidence is {suggested_confidence:.2f}. "
                f"This is a POLICY downgrade, not an evidence problem — "
                f"either strengthen evidence to meet the floor, OR override "
                f"with set_program_policy() if the floor itself is wrong."
            )
            verdict = "NEEDS MORE EVIDENCE"

    # ── R5: Surface program policy at top of output ──
    program_banner = (
        f"PROGRAM: {program.get('slug')}"
        if program.get("slug")
        else "PROGRAM: DEFAULT (no policy set; consider set_program_policy)"
    )

    # ── R8: Decouple color from confidence ──
    # severity_color encodes severity. confidence is a separate number.
    # Tools that consume this output must NOT use color as a confidence
    # signal. Both shown explicitly.
    sev_to_color = {
        "CRITICAL": "RED",
        "HIGH": "RED",
        "MEDIUM": "ORANGE",
        "LOW": "YELLOW",
        "INFO": "GRAY",
    }
    # Severity is inferred when not explicitly set: REPORT+strong → MEDIUM
    # by default; weak_evidence → LOW; DO NOT REPORT → INFO.
    if verdict == "DO NOT REPORT":
        inferred_severity = "INFO"
    elif weak_evidence:
        inferred_severity = "LOW"
    else:
        inferred_severity = "MEDIUM"
    severity_color = sev_to_color.get(inferred_severity, "YELLOW")

    # Derived markers surfaced for transparency (R1)
    derived_str = ""
    if derived_markers:
        derived_str = f"\n  Auto-derived markers: {', '.join(derived_markers[:8])}"

    override_audit = ""
    if audit_overrides:
        override_audit = f"\n  Operator overrides: {'; '.join(audit_overrides)}"

    # Build impact context string
    impact_str = ""
    if impact_notes:
        impact_str = "\n  Impact context:\n" + "\n".join(f"    + {n}" for n in impact_notes)

    if not issues:
        return (
            f"VERDICT: {verdict}\n"
            f"  {program_banner}\n"
            f"  Type: {vuln_type}\n"
            f"  Endpoint: {endpoint}\n"
            f"  Severity (inferred): {inferred_severity} [color={severity_color}]\n"
            f"  Confidence (separate from color): {suggested_confidence:.2f}\n"
            f"  All 7 questions PASS. Proceed with save_finding(confidence={suggested_confidence:.2f})."
            f"{derived_str}"
            f"{override_audit}"
            f"{impact_str}"
        )

    lines = [f"VERDICT: {verdict}"]
    lines.append(f"  {program_banner}")
    lines.append(f"  Type: {vuln_type}")
    lines.append(f"  Endpoint: {endpoint}")
    if parameter:
        lines.append(f"  Parameter: {parameter}")
    lines.append(f"  Severity (inferred): {inferred_severity} [color={severity_color}]")
    lines.append(f"  Confidence (separate from color): {suggested_confidence:.2f}")
    if derived_markers:
        lines.append(f"  Auto-derived markers: {', '.join(derived_markers[:8])}")
    if audit_overrides:
        lines.append(f"  Operator overrides: {'; '.join(audit_overrides)}")
    if impact_notes:
        lines.append(f"\n  Impact context:")
        for n in impact_notes:
            lines.append(f"    + {n}")
    lines.append(f"\n  Gate issues ({len(issues)}):")
    for issue in issues:
        lines.append(f"    - {issue}")

    if verdict == "DO NOT REPORT":
        lines.append(f"\n  Action: Do not report. Move to next target/parameter.")
    elif verdict == "NEEDS MORE EVIDENCE":
        lines.append(
            f"\n  Action: Strengthen the flagged evidence items, then re-assess before save_finding."
            f"\n  Fast path: pass logger_index=<N> to auto-derive evidence, "
            f"or human_verified=True if confirmed in Burp UI."
        )
    else:
        lines.append(f"\n  Action: Address the issues above, then save_finding(confidence={suggested_confidence:.2f}).")

    return "\n".join(lines)
