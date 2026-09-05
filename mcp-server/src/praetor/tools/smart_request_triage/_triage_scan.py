"""Request/response parsing + body-classification helpers for triage."""

from __future__ import annotations

import re
import secrets
from typing import Any

from ._triage_markers import *  # noqa: F401,F403
from ._triage_markers import (_SECRET_PATTERNS, _STACK_MARKERS, _RSC_MARKERS,
                               _FORM_RE, _HTML_INPUT_RE)  # noqa: F401


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


