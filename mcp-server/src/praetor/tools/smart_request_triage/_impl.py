"""W30-c — `smart_request_triage`.

Audit (W30 research wave): 106/340 tools return verbose strings; operator
chains get_request_detail → extract_* → smart_analyze → reason → pick next
probe = 5 LLM-mediated steps per captured request. Token burn at every step.

This tool collapses that loop. Input: ONE proxy/logger index. Output:
structured triage dict + priority-ordered attack_plan with concrete
suggested_call lines per W30-b synthesiser pattern.

Routing matrix (content-type + signal driven):
  text/x-component         -> probe_cve_with_variants (CVE-2025-55182)
  application/javascript   -> smart_js_analyze
  application/graphql+json -> test_graphql(test_introspection=True)
  text/html w/ forms       -> test_csrf + test_dom_sinks
  application/json + auth  -> test_auth_matrix + auto_probe
  application/xml          -> test_xxe
  5xx + stack-trace        -> confirm_sqli / confirm_ssti / confirm_rce
  302 + Location           -> test_open_redirect
  401/403                  -> test_auth_matrix + probe_kerberos_spnego_auth

Zero deps. Static regex + content-type sniff; no extra Burp roundtrips beyond
the single proxy-detail fetch.
"""

from __future__ import annotations

import re
import secrets
from typing import Any

from mcp.server.fastmcp import FastMCP

from praetor import client


# ----- Error-marker regexes for inline class detection ----------------------

_SQLI_MARKERS = (
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"\bpg_query\b", re.I),
    re.compile(r"\bSQLSTATE\[", re.I),
    re.compile(r"ORA-\d{5}"),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"\bpsycopg2\b", re.I),
    re.compile(r"\bMySQLSyntaxError", re.I),
)
_SSTI_MARKERS = (
    re.compile(r"jinja2\.exceptions"),
    re.compile(r"TemplateSyntaxError"),
    re.compile(r"freemarker\.core\."),
    re.compile(r"velocity\.exception"),
    re.compile(r"twig.error"),
)
_RCE_MARKERS = (
    re.compile(r"uid=\d+\(.+?\)\s+gid=\d+"),
    re.compile(r"\b(root|nobody|www-data|apache)\b.+\b(bash|sh|nologin)\b"),
)
_STACK_MARKERS = (
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"\bat\s+[\w.$]+\.[\w$]+\([\w.]+\.java:\d+\)"),
    re.compile(r"\bWhitelabel Error Page\b"),
    re.compile(r"\bServletException\b"),
    re.compile(r"NoMethodError|NameError|ReferenceError"),
    re.compile(r"Error: Cannot find module"),
    re.compile(r"FATAL:.*panic"),
)
_RSC_MARKERS = (
    re.compile(r"text/x-component", re.I),
    re.compile(r"\$\d+@"),
    re.compile(r"createServerReference"),
)
_OPEN_REDIRECT_PARAMS = {
    "url", "next", "redirect", "return", "returnTo", "return_url", "target",
    "dest", "destination", "redir", "redirect_uri", "callback", "u",
    "continue", "back", "rurl", "redirect_url",
}
_SECRET_PATTERNS = (
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA|AGPA)[A-Z0-9]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{30,45}\b")),
    ("stripe_live_secret", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    ("github_pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("jwt_token", re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("private_key_pem",
     re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----")),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b")),
)

_DEBUG_HEADERS = {
    "x-debug-token", "x-debug", "x-powered-by", "x-aspnet-version",
    "x-aspnetmvc-version", "x-runtime", "x-version", "server",
    "x-django-debug", "x-rack-cache", "x-symfony-cache",
}
_AUTH_HEADERS = {"authorization", "x-api-key", "x-auth-token",
                 "x-access-token", "cookie", "x-csrf-token", "x-xsrf-token"}
_FORM_RE = re.compile(r"<form[^>]*>", re.I)
_HTML_INPUT_RE = re.compile(
    r'<input[^>]+name=["\']([^"\']+)["\']', re.I)


# ----- Helpers --------------------------------------------------------------

def _canary() -> str:
    return "PRAETOR-" + secrets.token_hex(4).upper()


def _hkv(headers: Any) -> dict[str, str]:
    """Normalise headers to lower-case-key dict."""
    out: dict[str, str] = {}
    if isinstance(headers, list):
        for h in headers:
            if isinstance(h, dict):
                k = (h.get("name") or h.get("key") or "").lower()
                v = h.get("value") or ""
                if k:
                    out[k] = str(v)
    elif isinstance(headers, dict):
        for k, v in headers.items():
            out[str(k).lower()] = str(v)
    elif isinstance(headers, str):
        for line in headers.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                out[k.strip().lower()] = v.strip()
    return out


def _parse_query(url: str) -> list[str]:
    if "?" not in url:
        return []
    qs = url.split("?", 1)[1]
    return [p.split("=", 1)[0] for p in qs.split("&") if p]


def _parse_form_body(body: str, ct: str) -> list[str]:
    if "x-www-form-urlencoded" not in ct.lower():
        return []
    return [p.split("=", 1)[0] for p in body.split("&") if p and "=" in p]


def _scan_secrets(body: str) -> list[dict[str, str]]:
    out = []
    for name, pat in _SECRET_PATTERNS:
        for m in pat.finditer(body):
            out.append({"type": name, "match": m.group(0)[:80]})
            if len(out) >= 20:
                return out
    return out


def _classify_body(body: str, content_type: str) -> dict[str, Any]:
    """Return per-body signals: form_inputs, has_stack_trace, error_class, etc."""
    sample = body[:200_000]
    ct = content_type.lower()
    out: dict[str, Any] = {
        "has_forms": False,
        "form_inputs": [],
        "stack_trace": False,
        "error_class": None,
        "rsc_response": False,
        "graphql_response": False,
        "secrets": [],
    }
    if "text/html" in ct:
        out["has_forms"] = bool(_FORM_RE.search(sample))
        out["form_inputs"] = list({m.group(1) for m in
                                   _HTML_INPUT_RE.finditer(sample)})[:30]
    if "text/x-component" in ct or any(p.search(sample) for p in _RSC_MARKERS):
        out["rsc_response"] = True
    if "graphql" in ct or '"data":' in sample[:200] and '"errors":' in sample[:500]:
        out["graphql_response"] = True
    for p in _STACK_MARKERS:
        if p.search(sample):
            out["stack_trace"] = True
            break
    for p in _SQLI_MARKERS:
        if p.search(sample):
            out["error_class"] = "sqli"
            break
    if out["error_class"] is None:
        for p in _SSTI_MARKERS:
            if p.search(sample):
                out["error_class"] = "ssti"
                break
    if out["error_class"] is None:
        for p in _RCE_MARKERS:
            if p.search(sample):
                out["error_class"] = "rce"
                break
    out["secrets"] = _scan_secrets(sample)
    return out


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
