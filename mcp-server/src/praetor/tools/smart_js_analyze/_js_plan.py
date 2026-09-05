"""W30-b — `smart_js_analyze`.

Operator gap (2026-06-11): "analyze js file isn't smart enough — gets stuck
and burns tokens crafting payloads".

Existing extract_js_secrets / extract_api_endpoints / smart_analyze dump
raw findings (endpoints, secrets, params). Operator then LLM-reasons which
payloads to fire against what. Token burn.

This tool reads JS once (by proxy index OR URL OR batch of URLs), runs ALL
relevant regexes, and SYNTHESISES an ordered, fire-ready attack plan:

  attack_plan: list[{
      target_url, parameter, vuln_class, suggested_tool,
      suggested_call, canary, priority
  }]

Each entry is a concrete next tool call. No more "extract → think → pick →
fire" three-step LLM loop — read this tool's output, dispatch the top N
suggested_call lines directly.

Zero deps. Static-only regex synthesis (no JS engine). All HTTP routes
through Burp.
"""

from __future__ import annotations

import re
import secrets
from typing import Any

from mcp.server.fastmcp import FastMCP

from praetor import client


# ----- Extraction regexes ---------------------------------------------------
# Each compiled once at import. Greedy patterns kept SHORT to bound matching
# cost on big bundles (some chunks are >2 MB after minification).


from ._js_patterns import *  # noqa: F401,F403


def _canary() -> str:
    return "PRAETOR-" + secrets.token_hex(4).upper()


def _synthesise_plan(analyses: list[dict[str, Any]], target_base: str,
                     max_targets: int) -> list[dict[str, Any]]:
    """Walk findings, emit ordered attack plan. Higher-impact classes first."""
    plan: list[dict[str, Any]] = []
    canary = _canary()
    seen: set[tuple[str, str, str]] = set()

    # Pass 1 — RSC Server Action IDs are CRITICAL ammo (CVE-2025-55182)
    rsc_ids = set()
    for a in analyses:
        rsc_ids.update(a["findings"].get("rsc_action_ids", []))
    if rsc_ids:
        for aid in sorted(rsc_ids)[:3]:
            url = target_base or "https://TARGET/api/action"
            plan.append({
                "priority": 0,
                "vuln_class": "react_server_components",
                "target_url": url,
                "parameter": "Next-Action header",
                "canary": canary,
                "suggested_tool": "probe_cve_with_variants",
                "suggested_call": (
                    f"probe_cve_with_variants(cve_id='CVE-2025-55182', "
                    f"target_url={url!r}, action_id={aid!r}, max_variants=12)"
                ),
                "rationale": (
                    f"RSC Server Action ID harvested from bundle: {aid}. "
                    f"Direct ammo for React2Shell — Next-Action header "
                    f"invocation with bounded variant sweep."
                ),
            })

    # Pass 2 — GraphQL surface (introspection + injection)
    gql_endpoints = set()
    for a in analyses:
        gql_endpoints.update(a["findings"].get("graphql_endpoints", []))
    for ep in sorted(gql_endpoints)[:2]:
        url = (target_base.rstrip("/") + ep) if target_base else ep
        key = ("graphql", url, "")
        if key in seen:
            continue
        seen.add(key)
        plan.append({
            "priority": 1,
            "vuln_class": "graphql",
            "target_url": url,
            "parameter": "query",
            "canary": canary,
            "suggested_tool": "test_graphql",
            "suggested_call": f"test_graphql(url={url!r}, test_introspection=True)",
            "rationale": "GraphQL endpoint found in JS — test introspection + batching abuse.",
        })

    # Pass 3 — WebSocket attack surface
    ws_urls = set()
    for a in analyses:
        ws_urls.update(a["findings"].get("websocket_urls", []))
    for ws in sorted(ws_urls)[:2]:
        full = ws if ws.startswith("ws") else (
            target_base.replace("https://", "wss://").replace("http://", "ws://")
            + ws if target_base else ws
        )
        key = ("ws", full, "")
        if key in seen:
            continue
        seen.add(key)
        plan.append({
            "priority": 1,
            "vuln_class": "websocket",
            "target_url": full,
            "parameter": "(message frame)",
            "canary": canary,
            "suggested_tool": "test_websocket",
            "suggested_call": f"test_websocket(url={full!r})",
            "rationale": "WebSocket constructor in JS — test message AuthN/AuthZ + injection.",
        })

    # Pass 4 — DOM XSS sinks
    dom_priority = ["dangerouslySetInnerHTML", "innerHTML", "outerHTML",
                    "document.write", "eval", "Function_ctor",
                    "setTimeout_string", "setInterval_string",
                    "location_href", "location_replace", "postMessage_recv"]
    sink_seen: set[str] = set()
    for a in analyses:
        for sink in dom_priority:
            hits = a["findings"].get("dom_sinks", {}).get(sink, [])
            if hits and sink not in sink_seen:
                sink_seen.add(sink)
                src = a.get("source", "")
                if sink == "postMessage_recv":
                    plan.append({
                        "priority": 2,
                        "vuln_class": "postmessage_xss",
                        "target_url": target_base or src,
                        "parameter": "window.postMessage",
                        "canary": canary,
                        "suggested_tool": "probe_postmessage_listeners",
                        "suggested_call": (
                            f"probe_postmessage_listeners(target_url={target_base or src!r})"
                        ),
                        "rationale": f"postMessage listener found in {src!r}.",
                    })
                else:
                    plan.append({
                        "priority": 2,
                        "vuln_class": "dom_xss",
                        "target_url": target_base or src,
                        "parameter": f"sink={sink}",
                        "canary": canary,
                        "suggested_tool": "test_dom_sinks",
                        "suggested_call": (
                            f"test_dom_sinks(url={target_base or src!r}, "
                            f"focus_sink={sink!r})"
                        ),
                        "rationale": (
                            f"DOM sink {sink!r} found in {src!r}. "
                            f"Sample arg: {hits[0][:60]!r}"
                        ),
                    })

    # Pass 5 — auto_probe over discovered endpoints (bounded)
    all_endpoints: set[str] = set()
    for a in analyses:
        for ep in a["findings"].get("endpoints", []):
            # Skip static / framework paths
            if any(s in ep for s in ("/_next/", "/static/", "/__nextjs",
                                     ".woff", ".css", ".svg", ".png")):
                continue
            all_endpoints.add(ep)
    # Limit endpoint sweep by max_targets minus already-added
    remaining = max(0, max_targets - len(plan))
    for ep in sorted(all_endpoints)[:remaining]:
        full = (target_base.rstrip("/") + ep) if target_base else ep
        key = ("autoprobe", full, "")
        if key in seen:
            continue
        seen.add(key)
        plan.append({
            "priority": 3,
            "vuln_class": "unknown",
            "target_url": full,
            "parameter": "(auto-discovered)",
            "canary": canary,
            "suggested_tool": "auto_probe",
            "suggested_call": (
                f"auto_probe(url={full!r}, session='hunt')"
            ),
            "rationale": "Endpoint extracted from JS — knowledge-base sweep.",
        })

    # Pass 6 — Secrets (no payload — informational, drives chain)
    for a in analyses:
        for sec in a["findings"].get("secrets", [])[:5]:
            plan.append({
                "priority": 4,
                "vuln_class": "info_disclosure",
                "target_url": a.get("source", ""),
                "parameter": "(secret in JS bundle)",
                "canary": "",
                "suggested_tool": "save_finding",
                "suggested_call": (
                    f"save_finding(vuln_type='info_disclosure', "
                    f"endpoint={a.get('source', '')!r}, "
                    f"title='Secret leaked in JS: {sec['type']}', "
                    f"severity='medium', "
                    f"evidence={{'logger_index': '<from extract>', 'match': {sec['match'][:60]!r}}}, "
                    f"chain_with=[<linked finding>])  # NEVER_SUBMIT alone — needs chain"
                ),
                "rationale": (
                    f"Secret {sec['type']} found in {a.get('source', '')!r}. "
                    f"Cannot report alone (NEVER_SUBMIT) — chain with downstream impact."
                ),
            })

    # Pass 7 — Source maps exposed
    for a in analyses:
        for sm in a["findings"].get("sourcemaps", []):
            sm_full = sm if sm.startswith("http") else (
                a.get("source", "").rsplit("/", 1)[0] + "/" + sm.lstrip("/")
            )
            plan.append({
                "priority": 4,
                "vuln_class": "source_code_exposure",
                "target_url": sm_full,
                "parameter": "(source map)",
                "canary": "",
                "suggested_tool": "curl_request",
                "suggested_call": f"curl_request(url={sm_full!r})  # confirm map exposed",
                "rationale": "//# sourceMappingURL declared — likely leaks original source.",
            })

    # Sort by priority, then leave insertion order
    plan.sort(key=lambda x: (x["priority"], x["vuln_class"]))
    return plan[:max_targets * 2]  # priority-5/6 informational allowed past cap


# ----- Registration ---------------------------------------------------------

