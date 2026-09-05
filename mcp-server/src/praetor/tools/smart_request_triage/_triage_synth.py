"""Attack-plan synthesiser for smart_request_triage."""

from __future__ import annotations

from typing import Any

from ._triage_markers import _DEBUG_HEADERS, _OPEN_REDIRECT_PARAMS  # noqa: F401
from ._triage_scan import _canary


def _synthesise(triage: dict[str, Any]) -> list[dict[str, Any]]:
    """Build the priority-ordered attack plan from triage signals."""
    plan: list[dict[str, Any]] = []
    canary = _canary()
    url = triage["url"]
    idx = triage["index"]
    method = triage["method"]
    status = triage["status_code"]
    req_params_query = triage["request_params"]["query"]
    req_params_body = triage["request_params"]["body"]
    has_auth = triage["has_auth_header"]
    ct = triage["content_type"]
    body_signals = triage["response_signals"]

    # P0 — error markers in response confirm a class. Direct confirm_ tools.
    err = body_signals.get("error_class")
    if err == "sqli":
        plan.append({
            "priority": 0, "vuln_class": "sqli",
            "target_url": url, "parameter": "(see request_params)",
            "canary": canary,
            "suggested_tool": "confirm_sqli",
            "suggested_call": (
                f"confirm_sqli(endpoint={url!r}, "
                f"parameter='<top candidate from request_params>', method={method!r})"
            ),
            "rationale": "SQL error marker in response body — confirm with benign payload.",
        })
    if err == "ssti":
        plan.append({
            "priority": 0, "vuln_class": "ssti",
            "target_url": url, "parameter": "(see request_params)",
            "canary": canary,
            "suggested_tool": "confirm_ssti",
            "suggested_call": (
                f"confirm_ssti(endpoint={url!r}, "
                f"parameter='<top candidate>', method={method!r})"
            ),
            "rationale": "Template-engine error marker in response — confirm with math expression.",
        })
    if err == "rce":
        plan.append({
            "priority": 0, "vuln_class": "rce",
            "target_url": url, "parameter": "(see request_params)",
            "canary": canary,
            "suggested_tool": "confirm_rce",
            "suggested_call": (
                f"confirm_rce(endpoint={url!r}, parameter='<top candidate>', "
                f"command='id', method={method!r})"
            ),
            "rationale": "Command-output marker in response — confirm with `id`.",
        })

    # P0 — RSC response (text/x-component) — direct ammo for React2Shell
    if body_signals.get("rsc_response"):
        plan.append({
            "priority": 0, "vuln_class": "react_server_components",
            "target_url": url, "parameter": "Next-Action header",
            "canary": canary,
            "suggested_tool": "probe_cve_with_variants",
            "suggested_call": (
                f"probe_cve_with_variants(cve_id='CVE-2025-55182', "
                f"target_url={url!r}, max_variants=12)  "
                f"# harvest action_id via smart_js_analyze on /_next/static/chunks/"
            ),
            "rationale": "RSC Flight response confirmed — App Router with Server Actions enabled.",
        })

    # P1 — content-type aware routing
    if "javascript" in ct or url.endswith(".js"):
        plan.append({
            "priority": 1, "vuln_class": "js_bundle_analysis",
            "target_url": url, "parameter": "(static)",
            "canary": canary,
            "suggested_tool": "smart_js_analyze",
            "suggested_call": (
                f"smart_js_analyze(index={idx}, target_base_url='<app root>')"
            ),
            "rationale": "JS bundle — synthesise attack plan from static extraction.",
        })

    if body_signals.get("graphql_response"):
        plan.append({
            "priority": 1, "vuln_class": "graphql",
            "target_url": url, "parameter": "query",
            "canary": canary,
            "suggested_tool": "test_graphql",
            "suggested_call": (
                f"test_graphql(url={url!r}, test_introspection=True, "
                f"test_batching=True)"
            ),
            "rationale": "GraphQL response detected — introspect + batch-abuse.",
        })

    if "xml" in ct and method in ("POST", "PUT", "PATCH"):
        plan.append({
            "priority": 1, "vuln_class": "xxe",
            "target_url": url, "parameter": "(XML body)",
            "canary": canary,
            "suggested_tool": "test_xxe",
            "suggested_call": f"test_xxe(url={url!r}, method={method!r})",
            "rationale": "XML request body — XXE candidate.",
        })

    if "text/html" in ct and body_signals.get("has_forms"):
        plan.append({
            "priority": 1, "vuln_class": "csrf",
            "target_url": url, "parameter": "(form action)",
            "canary": canary,
            "suggested_tool": "test_csrf",
            "suggested_call": f"test_csrf(url={url!r})",
            "rationale": (
                f"HTML form found ({len(body_signals['form_inputs'])} input(s)) — "
                f"CSRF token + state-change audit."
            ),
        })
        plan.append({
            "priority": 2, "vuln_class": "dom_xss",
            "target_url": url, "parameter": "(form inputs)",
            "canary": canary,
            "suggested_tool": "test_dom_sinks",
            "suggested_call": f"test_dom_sinks(url={url!r})",
            "rationale": "HTML response — DOM sink probe on form-reflective paths.",
        })

    # P1 — status-driven
    if status in (401, 403):
        plan.append({
            "priority": 1, "vuln_class": "auth_bypass",
            "target_url": url, "parameter": "(headers/cookies)",
            "canary": canary,
            "suggested_tool": "test_auth_matrix",
            "suggested_call": (
                f"test_auth_matrix(url={url!r})  "
                f"# tests anonymous / wrong-role / role-X access"
            ),
            "rationale": f"Status {status} — authz boundary present; matrix-test roles.",
        })
        if "www-authenticate" in triage["response_headers"]:
            plan.append({
                "priority": 1, "vuln_class": "enterprise_auth",
                "target_url": url, "parameter": "(WWW-Authenticate)",
                "canary": canary,
                "suggested_tool": "probe_kerberos_spnego_auth",
                "suggested_call": f"probe_kerberos_spnego_auth(target_url={url!r})",
                "rationale": "WWW-Authenticate present — fingerprint Negotiate/Kerberos/NTLM.",
            })

    if status in (301, 302, 303, 307, 308):
        # Open redirect candidate if a redirect-named param exists
        redir_params = [p for p in (req_params_query + req_params_body)
                        if p.lower() in _OPEN_REDIRECT_PARAMS]
        if redir_params:
            plan.append({
                "priority": 1, "vuln_class": "open_redirect",
                "target_url": url, "parameter": redir_params[0],
                "canary": canary,
                "suggested_tool": "test_open_redirect",
                "suggested_call": (
                    f"test_open_redirect(url={url!r}, "
                    f"parameter={redir_params[0]!r})"
                ),
                "rationale": (
                    f"{status} redirect + redirect-named param {redir_params[0]!r} "
                    "in request — open-redirect candidate."
                ),
            })

    # P2 — JSON API with auth → auto_probe + test_auth_matrix
    if "application/json" in ct and method != "GET":
        if has_auth:
            plan.append({
                "priority": 2, "vuln_class": "idor_bola",
                "target_url": url, "parameter": "(JSON body)",
                "canary": canary,
                "suggested_tool": "test_auth_matrix",
                "suggested_call": f"test_auth_matrix(url={url!r}, method={method!r})",
                "rationale": "Authenticated JSON API — IDOR/BOLA via role matrix.",
            })
        plan.append({
            "priority": 2, "vuln_class": "unknown",
            "target_url": url, "parameter": "(JSON body)",
            "canary": canary,
            "suggested_tool": "auto_probe",
            "suggested_call": f"auto_probe(url={url!r}, session='hunt')",
            "rationale": "JSON API endpoint — KB-driven sweep across applicable classes.",
        })

    # P3 — debug headers / Set-Cookie audit
    debug_present = [h for h in triage["response_headers"]
                     if h in _DEBUG_HEADERS]
    if debug_present:
        plan.append({
            "priority": 3, "vuln_class": "info_disclosure",
            "target_url": url, "parameter": ",".join(debug_present),
            "canary": "",
            "suggested_tool": "annotate_request",
            "suggested_call": (
                f"annotate_request(index={idx}, color='YELLOW', "
                f"comment='debug/version headers: {','.join(debug_present)[:60]}')  "
                f"# NEVER_SUBMIT alone — chain"
            ),
            "rationale": f"Debug/version headers leaked: {debug_present}.",
        })

    # P3 — Secrets in response body
    for sec in body_signals.get("secrets", [])[:5]:
        plan.append({
            "priority": 3, "vuln_class": "info_disclosure",
            "target_url": url, "parameter": f"(secret: {sec['type']})",
            "canary": "",
            "suggested_tool": "save_finding",
            "suggested_call": (
                f"save_finding(vuln_type='info_disclosure', endpoint={url!r}, "
                f"title='Secret leaked: {sec['type']}', severity='medium', "
                f"evidence={{'logger_index': {idx}, 'match': {sec['match'][:60]!r}}}, "
                f"chain_with=[<linked finding>])  "
                f"# NEVER_SUBMIT alone — Rule 17"
            ),
            "rationale": f"Secret {sec['type']!r} exposed in response body.",
        })

    # Stack trace alone (no class marker) is still useful intel
    if body_signals.get("stack_trace") and err is None:
        plan.append({
            "priority": 3, "vuln_class": "info_disclosure",
            "target_url": url, "parameter": "(response body)",
            "canary": "",
            "suggested_tool": "annotate_request",
            "suggested_call": (
                f"annotate_request(index={idx}, color='ORANGE', "
                f"comment='stack-trace leaked — fingerprint stack and probe injection')"
            ),
            "rationale": "Stack trace exposed — fingerprints stack; chase for upstream injection.",
        })

    plan.sort(key=lambda x: (x["priority"], x["vuln_class"]))
    return plan


# ----- Registration ---------------------------------------------------------
