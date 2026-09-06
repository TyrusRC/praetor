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


async def _fetch_index(idx: int) -> tuple[str, str, str]:
    """Returns (body, url, status_str)."""
    resp = await client.get(f"/api/proxy/history/{int(idx)}")
    if isinstance(resp, dict) and "error" in resp:
        return ("", "", f"ERROR: {resp['error']}")
    body = resp.get("response_body", "") or ""
    url = resp.get("url", "") or resp.get("request_url", "") or ""
    status = str(resp.get("status_code", "?"))
    return (body, url, status)


async def _fetch_url(url: str, session: str) -> tuple[str, str, str]:
    if session:
        resp = await client.post("/api/session/request", json={
            "session": session, "method": "GET", "path": url,
        })
    else:
        resp = await client.post("/api/http/curl", json={
            "method": "GET", "url": url, "timeout": 20,
        })
    if isinstance(resp, dict) and "error" in resp:
        return ("", url, f"ERROR: {resp['error']}")
    body = resp.get("response_body", "") or ""
    status = str(resp.get("status_code", "?"))
    return (body, url, status)


# ----- Static analysis ------------------------------------------------------

def _analyze_body(body: str, source_url: str) -> dict[str, Any]:
    """Run every regex pack over the body and return findings."""
    if not body:
        return {"source": source_url, "size": 0, "findings": {}, "frameworks": []}

    sample = body[:2_000_000]  # 2 MB hard cap — bigger bundles get truncated

    # Frameworks
    frameworks: list[tuple[str, int]] = []
    for name, (pat, weight) in _FRAMEWORKS.items():
        if pat.search(sample):
            frameworks.append((name, weight))
    frameworks.sort(key=lambda x: -x[1])

    # Endpoints — dedupe + cap
    endpoints: set[str] = set()
    for m in _RE_ENDPOINT.finditer(sample):
        endpoints.add(m.group(1))
    for m in _RE_FETCH.finditer(sample):
        candidate = m.group(1)
        if candidate.startswith(("/", "http")):
            endpoints.add(candidate)
    endpoints_list = sorted(endpoints)[:100]

    # WebSocket
    ws_urls = sorted({m.group(1) for m in _RE_WEBSOCKET.finditer(sample)})[:20]

    # GraphQL
    gql_endpoints = sorted({m.group(1) for m in _RE_GRAPHQL_ENDPOINT.finditer(sample)})[:10]
    gql_ops = []
    for m in _RE_GRAPHQL_OP.finditer(sample):
        gql_ops.append({"type": m.group(1), "name": m.group(2)})
        if len(gql_ops) >= 30:
            break

    # RSC Server Action IDs — CVE-2025-55182 direct ammo
    rsc_action_ids = set()
    for m in _RE_RSC_ACTION.finditer(sample):
        rsc_action_ids.add(m.group(1))
    for m in _RE_RSC_ACTION_ALT.finditer(sample):
        rsc_action_ids.add(m.group(1))
    rsc_action_ids_list = sorted(rsc_action_ids)[:20]

    # Auth header names
    auth_headers = sorted({m.group(1) for m in _RE_AUTH_HEADER.finditer(sample)})

    # DOM XSS sinks — name + line context (one sample per sink)
    sinks_hits: dict[str, list[str]] = {}
    for name, pat in _DOM_SINKS.items():
        hits = []
        for m in pat.finditer(sample):
            arg = m.group(1).strip()[:80] if m.groups() else ""
            hits.append(arg)
            if len(hits) >= 3:
                break
        if hits:
            sinks_hits[name] = hits

    # Secrets
    secrets_hits: list[dict[str, str]] = []
    for name, pat in _SECRETS.items():
        for m in pat.finditer(sample):
            secrets_hits.append({
                "type": name,
                "match": m.group(0)[:120],
                "offset": m.start(),
            })
            if len(secrets_hits) >= 50:
                break
        if len(secrets_hits) >= 50:
            break

    # Source maps
    sourcemaps = [m.group(1) for m in _RE_SOURCEMAP.finditer(sample)][:5]

    return {
        "source": source_url,
        "size": len(body),
        "truncated": len(body) > 2_000_000,
        "frameworks": [f for f, _ in frameworks],
        "findings": {
            "endpoints": endpoints_list,
            "websocket_urls": ws_urls,
            "graphql_endpoints": gql_endpoints,
            "graphql_operations": gql_ops,
            "rsc_action_ids": rsc_action_ids_list,
            "auth_headers": auth_headers,
            "dom_sinks": sinks_hits,
            "secrets": secrets_hits,
            "sourcemaps": sourcemaps,
        },
    }


# ----- Synthesiser → attack plan -------------------------------------------


from ._js_plan import _canary, _synthesise_plan  # noqa: F401 (re-export)
