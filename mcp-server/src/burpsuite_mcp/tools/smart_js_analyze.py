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

from burpsuite_mcp import client


# ----- Extraction regexes ---------------------------------------------------
# Each compiled once at import. Greedy patterns kept SHORT to bound matching
# cost on big bundles (some chunks are >2 MB after minification).

_RE_ENDPOINT = re.compile(
    r'["\'`](/(api|v\d+|graphql|gql|trpc|rest)/[A-Za-z0-9/_\-\.\?\&\=\{\}\$]{2,200})["\'`]'
)
_RE_FETCH = re.compile(
    r'(?:fetch|axios(?:\.\w+)?|XMLHttpRequest|\$\.\w+)\s*\(\s*["\'`]([^"\'`\s]{4,300})["\'`]'
)
_RE_WEBSOCKET = re.compile(
    r'new\s+WebSocket\s*\(\s*["\'`](wss?://[^"\'`\s]+|/[^"\'`\s]+)["\'`]'
)
_RE_GRAPHQL_OP = re.compile(
    r'\b(query|mutation|subscription)\s+(\w+)\s*[\(\{]'
)
_RE_GRAPHQL_ENDPOINT = re.compile(
    r'["\'`](/[A-Za-z0-9/_\-]*graphql[A-Za-z0-9/_\-]*)["\'`]'
)

# React Server Components — Server Action IDs (CVE-2025-55182 direct ammo)
_RE_RSC_ACTION = re.compile(
    r'createServerReference\(\s*["\']([0-9a-f]{40,64})["\']'
)
_RE_RSC_ACTION_ALT = re.compile(
    r'["\']\$ACTION_ID_([0-9a-f]{40,64})["\']'
)

# Auth surface
_RE_AUTH_HEADER = re.compile(
    r'["\'`](Authorization|X-API-?Key|X-Auth-Token|X-CSRF-Token|X-XSRF-Token|'
    r'X-Access-Token|Bearer|Cookie)["\'`]\s*[,:]'
)

# DOM XSS sinks — name + capture group for arg context
_DOM_SINKS = {
    "innerHTML": re.compile(r'\.innerHTML\s*=\s*([^;]+)'),
    "outerHTML": re.compile(r'\.outerHTML\s*=\s*([^;]+)'),
    "dangerouslySetInnerHTML": re.compile(r'dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*([^}]+)'),
    "document.write": re.compile(r'document\.write(?:ln)?\s*\(\s*([^)]+)\)'),
    "eval": re.compile(r'\beval\s*\(\s*([^)]+)\)'),
    "Function_ctor": re.compile(r'new\s+Function\s*\(\s*([^)]+)\)'),
    "setTimeout_string": re.compile(r'setTimeout\s*\(\s*["\'`]([^"\'`]+)["\'`]'),
    "setInterval_string": re.compile(r'setInterval\s*\(\s*["\'`]([^"\'`]+)["\'`]'),
    "location_href": re.compile(r'location\.href\s*=\s*([^;]+)'),
    "location_replace": re.compile(r'location\.replace\s*\(\s*([^)]+)\)'),
    "postMessage_recv": re.compile(r'addEventListener\s*\(\s*["\']message["\']'),
}

# Secrets — standard set, tight patterns to avoid false positives
_SECRETS = {
    "aws_access_key": re.compile(r'\b(AKIA|ASIA|AGPA)[A-Z0-9]{16}\b'),
    "aws_secret_key": re.compile(r'(?i)aws[_\-\.]?secret[_\-\.]?key[\'"\s:=]{1,5}[A-Za-z0-9/+=]{40}'),
    "google_api_key": re.compile(r'\bAIza[0-9A-Za-z\-_]{30,45}\b'),
    "google_oauth": re.compile(r'\bya29\.[0-9A-Za-z\-_]+\b'),
    "stripe_live_secret": re.compile(r'\bsk_live_[A-Za-z0-9]{20,}\b'),
    "stripe_test_secret": re.compile(r'\bsk_test_[A-Za-z0-9]{20,}\b'),
    "stripe_publishable": re.compile(r'\bpk_(live|test)_[A-Za-z0-9]{20,}\b'),
    "github_pat": re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'),
    "slack_token": re.compile(r'\bxox[abprs]-[A-Za-z0-9\-]{10,}\b'),
    "jwt": re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'),
    "private_key_pem": re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----'),
    "supabase_anon": re.compile(r'\bsbp_[A-Za-z0-9]{40,}\b'),
    "openai_api_key": re.compile(r'\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b'),
    "anthropic_api_key": re.compile(r'\bsk-ant-[A-Za-z0-9_\-]{20,}\b'),
}

# Source maps — leaked .map files often expose original source
_RE_SOURCEMAP = re.compile(r'//[#@]\s*sourceMappingURL=([^\s\'"]+)')

# Framework fingerprints — drives synthesiser
_FRAMEWORKS = {
    "nextjs": (re.compile(r'__NEXT_DATA__|next/dist|next-route-announcer|self\.__next_'), 90),
    "nuxt": (re.compile(r'__NUXT__|window\.\$nuxt'), 80),
    "remix": (re.compile(r'__remix|@remix-run'), 80),
    "react": (re.compile(r'react\.production|react-dom|createElement|useState'), 50),
    "vue": (re.compile(r'__VUE__|Vue\.component|createApp\('), 60),
    "angular": (re.compile(r'@angular|ng-version|platformBrowserDynamic'), 70),
    "svelte": (re.compile(r'svelte/internal|__sveltekit'), 70),
    "apollo": (re.compile(r'@apollo/client|ApolloProvider|gql`'), 70),
    "relay": (re.compile(r'relay-runtime|RelayEnvironment'), 70),
    "trpc": (re.compile(r'@trpc/client|trpc\.useQuery'), 80),
    "swr": (re.compile(r'\buseSWR\(|\bswr/'), 50),
    "tanstack_query": (re.compile(r'useQuery|@tanstack/react-query'), 50),
}


# ----- Fetch helpers --------------------------------------------------------

async def _fetch_index(idx: int) -> tuple[str, str, str]:
    """Returns (body, url, status_str)."""
    resp = await client.post("/api/proxy/request-detail", json={"index": idx})
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

def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def smart_js_analyze(
        index: int = -1,
        url: str = "",
        urls: list[str] | None = None,
        target_base_url: str = "",
        max_targets: int = 10,
        session: str = "",
    ) -> dict:
        """Read JS file(s), synthesise a fire-ready attack plan — replaces the extract->reason->pick->fire loop with one call.

        Args:
            index: Proxy index of a captured JS response. Exclusive with url/urls.
            url: JS URL to fetch via Burp and analyse. Exclusive with index/urls.
            urls: Batch of JS URLs; plan synthesised over the union.
            target_base_url: Base URL of the running app; resolves relative paths, anchors RSC/GraphQL/WS. Falls back to JS source URL.
            max_targets: Cap on attack_plan length. Default 10.
            session: Burp session name (auth-aware fetches).

        Returns dict: sources, summary counts, attack_plan[{priority, vuln_class, target_url, parameter, canary, suggested_tool, suggested_call, rationale}], human_summary.
        """
        # Resolve sources
        if index >= 0 and (url or urls):
            return {"error": "pass index OR url OR urls — not multiple"}
        sources: list[tuple[str, str, str]] = []
        if index >= 0:
            sources.append(await _fetch_index(index))
        elif url:
            sources.append(await _fetch_url(url, session))
        elif urls:
            for u in urls[:25]:  # hard cap on batch size
                sources.append(await _fetch_url(u, session))
        else:
            return {"error": "smart_js_analyze requires index OR url OR urls"}

        # Analyse each
        analyses = [_analyze_body(body, src) for (body, src, _status) in sources]

        # Synthesise plan
        plan = _synthesise_plan(analyses, target_base_url, max_targets)

        # Summary counts
        summary = {
            "endpoints": sum(len(a["findings"].get("endpoints", []))
                             for a in analyses),
            "rsc_action_ids": sum(len(a["findings"].get("rsc_action_ids", []))
                                  for a in analyses),
            "graphql": sum(len(a["findings"].get("graphql_endpoints", []))
                           for a in analyses),
            "websocket": sum(len(a["findings"].get("websocket_urls", []))
                             for a in analyses),
            "secrets": sum(len(a["findings"].get("secrets", []))
                           for a in analyses),
            "dom_sinks": sum(len(a["findings"].get("dom_sinks", {}))
                             for a in analyses),
            "frameworks": sorted({f for a in analyses for f in a["frameworks"]}),
        }

        # Human summary
        lines = [
            f"smart_js_analyze: {len(analyses)} source(s), "
            f"frameworks={summary['frameworks']}",
            f"  endpoints={summary['endpoints']} "
            f"rsc_actions={summary['rsc_action_ids']} "
            f"graphql={summary['graphql']} "
            f"websocket={summary['websocket']} "
            f"secrets={summary['secrets']} "
            f"dom_sinks={summary['dom_sinks']}",
            "",
            f"Attack plan ({len(plan)} entries) — dispatch top N directly:",
        ]
        for i, p in enumerate(plan[:max_targets * 2], 1):
            lines.append(f"  [{i}] P{p['priority']} {p['vuln_class']:<25} "
                         f"{p['suggested_tool']}")
            lines.append(f"       call: {p['suggested_call']}")
            lines.append(f"       why : {p['rationale'][:140]}")
        if not plan:
            lines.append("  (no actionable targets — JS likely framework runtime only)")

        return {
            "sources": [{
                "source": a["source"],
                "size": a["size"],
                "truncated": a.get("truncated", False),
                "frameworks": a["frameworks"],
            } for a in analyses],
            "summary": summary,
            "attack_plan": plan,
            "human_summary": "\n".join(lines),
        }
