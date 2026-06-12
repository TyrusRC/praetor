"""build_api_dag + find_rre_chains — DEF CON 33 Recursive Request Exploits (Karimi).

RRE attack model: a low-trust API endpoint returns values an attacker did not
know. Some of those values are accepted as inputs by higher-trust endpoints
that return sensitive data. Walking the response→request graph surfaces
unauthorised data paths the operator never tested directly.

build_api_dag: walks endpoints.json + proxy history. For each captured
response, extracts JSON keys/values. For each captured request, extracts
input parameter names + values. Edges are added when a response value
collides with a request parameter value, or when a response key name
matches an input parameter name.

find_rre_chains: walks the DAG. Returns paths (low_trust → high_trust)
where the low end is publicly reachable and the high end returns sensitive
data (per harvest_identifiers / extract_js_secrets-style markers).

Both tools read existing intel only — NO new HTTP fire.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.notes._helpers import _intel_dir, _sanitized


_SENSITIVE_RESPONSE_FIELDS = (
    "email", "phone", "ssn", "password", "token", "secret", "api_key",
    "access_token", "refresh_token", "credit_card", "card_number", "iban",
    "address", "date_of_birth", "dob", "passport", "license", "session_id",
)

_HIGH_VALUE_INPUT_PARAMS = (
    "id", "user_id", "account_id", "order_id", "tenant_id", "org_id",
    "customer_id", "session", "token", "key", "secret",
)

_PUBLIC_TRUST_MARKERS = (
    "/public/", "/api/v1/info", "/health", "/status",
    "/auth/csrf", "/oauth/token", "/.well-known/",
    "/v1/discover", "/api/oembed", "/api/public",
)

_AUTH_HEADERS_RE = re.compile(r"\b(authorization|cookie|x-api-key)\s*:",
                              re.IGNORECASE)
_JSON_KEY_RE = re.compile(r'"([A-Za-z_][A-Za-z0-9_]{1,40})"\s*:')


async def _build_dag_impl(
    domain: str, max_history_entries: int, host_filter: str,
) -> dict:
    """Shared DAG builder — used by both build_api_dag tool + find_rre_chains."""
    history = await _load_proxy_history(max_history_entries, host_filter)
    if not history:
        return {
            "domain": domain,
            "endpoints": [],
            "edges": [],
            "endpoint_meta": {},
            "summary": "no proxy history available — browse the target first",
        }

    # Phase 1: per-endpoint feature extraction
    meta: dict[str, dict] = {}
    for entry in history:
        url = entry.get("url") or ""
        if not url:
            continue
        if host_filter and host_filter not in url:
            continue
        ep = _normalise_endpoint(url)
        slot = meta.setdefault(ep, {
            "trust": _classify_trust(ep, entry),
            "response_keys": set(),
            "response_sensitive_fields": set(),
            "response_values_seen": set(),
            "input_params": set(),
            "input_values_seen": set(),
            "samples": [],
        })
        slot["samples"].append(entry.get("index", -1))

        body = entry.get("response_body") or ""
        if body:
            for m in _JSON_KEY_RE.finditer(body[:200000]):
                k = m.group(1).lower()
                slot["response_keys"].add(k)
                if k in _SENSITIVE_RESPONSE_FIELDS:
                    slot["response_sensitive_fields"].add(k)
            # Harvest atomic string values from JSON for value-collision
            for v in _harvest_atomic_values(body[:80000]):
                if 6 <= len(v) <= 64:
                    slot["response_values_seen"].add(v)

        for p in (entry.get("params") or []):
            if isinstance(p, dict):
                pname = (p.get("name") or "").lower()
                pval = p.get("value") or ""
                if pname:
                    slot["input_params"].add(pname)
                if isinstance(pval, str) and 6 <= len(pval) <= 64:
                    slot["input_values_seen"].add(pval)

    # Phase 2: build edges
    edges: list[dict] = []
    endpoints = list(meta.keys())

    # 2a. name match: response key K on A === input param K on B
    key_to_consumers: dict[str, list[str]] = defaultdict(list)
    for ep, slot in meta.items():
        for p in slot["input_params"]:
            key_to_consumers[p].append(ep)
    for src, src_slot in meta.items():
        for k in src_slot["response_keys"]:
            if k in _HIGH_VALUE_INPUT_PARAMS or k.endswith("_id"):
                for dst in key_to_consumers.get(k, []):
                    if dst != src:
                        edges.append({
                            "from": src, "to": dst,
                            "via": k, "kind": "name_match",
                        })

    # 2b. value collision: a response value also appears as an input
    value_to_consumers: dict[str, list[str]] = defaultdict(list)
    for ep, slot in meta.items():
        for v in slot["input_values_seen"]:
            value_to_consumers[v].append(ep)
    for src, src_slot in meta.items():
        for v in src_slot["response_values_seen"]:
            for dst in value_to_consumers.get(v, []):
                if dst != src:
                    edges.append({
                        "from": src, "to": dst,
                        "via": v[:20], "kind": "value_collision",
                    })

    # Normalise meta sets → lists for JSON
    endpoint_meta = {}
    for ep, slot in meta.items():
        endpoint_meta[ep] = {
            "trust": slot["trust"],
            "response_keys": sorted(slot["response_keys"])[:60],
            "response_sensitive_fields": sorted(slot["response_sensitive_fields"]),
            "input_params": sorted(slot["input_params"])[:60],
            "sample_indices": slot["samples"][:5],
        }

    return {
        "domain": domain,
        "endpoints": endpoints,
        "edges": edges,
        "endpoint_meta": endpoint_meta,
        "summary": (
            f"DAG built: {len(endpoints)} endpoints, {len(edges)} edges. "
            f"{sum(1 for s in endpoint_meta.values() if s['trust'] == 'public')} "
            f"public-trust nodes."
        ),
    }


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def build_api_dag(
        domain: str,
        max_history_entries: int = 2000,
        host_filter: str = "",
    ) -> dict:
        """Build endpoint output→input directed graph (RRE precursor).

        Reads endpoints.json (path inventory) + proxy history (real
        captured req/resp pairs). Produces a DAG: edge from endpoint A
        to endpoint B when A's response carries a value or key that B
        accepts as an input parameter.

        Args:
            domain: target domain.
            max_history_entries: cap how many proxy entries to scan
                (default 2000 — covers most engagements without OOM).
            host_filter: optional host substring to restrict graph scope.

        Returns: DAG dict {endpoints, edges, endpoint_meta, summary}.
        """
        return await _build_dag_impl(domain, max_history_entries, host_filter)

    @mcp.tool()
    async def find_rre_chains(
        domain: str,
        max_depth: int = 3,
        min_trust_delta: int = 1,
        require_sensitive_sink: bool = True,
        host_filter: str = "",
    ) -> dict:
        """Find Recursive-Request-Exploit chains in the captured DAG.

        Walks paths starting from public-trust endpoints, following edges
        toward auth-required / high-trust endpoints whose responses contain
        sensitive fields. Returns ranked chains.

        Args:
            domain: target domain.
            max_depth: max chain length (default 3 — most RRE chains in
                published research are 2-3 hops).
            min_trust_delta: minimum trust-tier difference between chain
                start and end (default 1 — public→authed).
            require_sensitive_sink: only return chains whose sink endpoint
                returns sensitive fields (email/token/etc).
            host_filter: optional host substring scoping.

        Returns:
            {
              "domain": str,
              "chains": [
                {"path": [endpoint, ...], "via": [key_or_value, ...],
                 "trust_delta": int, "sensitive_fields": [str, ...],
                 "score": int}, ...
              ],
              "summary": str,
            }
        """
        dag = await _build_dag_impl(domain, 2000, host_filter)
        edges_by_src: dict[str, list[dict]] = defaultdict(list)
        for e in dag.get("edges", []):
            edges_by_src[e["from"]].append(e)
        meta = dag.get("endpoint_meta", {})

        chains: list[dict] = []
        public_starts = [ep for ep, s in meta.items() if s.get("trust") == "public"]
        if not public_starts:
            return {
                "domain": domain,
                "chains": [],
                "summary": "no public-trust endpoints in captured traffic — "
                           "browse public/unauth surface first",
            }

        for start in public_starts:
            for chain in _dfs_chains(start, edges_by_src, meta, max_depth):
                trust_path = [meta.get(ep, {}).get("trust", "unknown")
                              for ep in chain["path"]]
                trust_delta = _trust_delta(trust_path)
                if trust_delta < min_trust_delta:
                    continue
                sink = chain["path"][-1]
                sens = meta.get(sink, {}).get("response_sensitive_fields", [])
                if require_sensitive_sink and not sens:
                    continue
                score = trust_delta * 10 + len(sens) * 5 + len(chain["path"])
                chains.append({
                    "path": chain["path"],
                    "via": chain["via"],
                    "trust_path": trust_path,
                    "trust_delta": trust_delta,
                    "sensitive_fields": sens,
                    "score": score,
                })

        chains.sort(key=lambda c: c["score"], reverse=True)
        chains = chains[:50]

        return {
            "domain": domain,
            "chains": chains,
            "summary": (
                f"{len(chains)} RRE chain candidate(s). "
                f"Top score: {chains[0]['score'] if chains else 0}. "
                "Verify each by replaying the path: capture response from step N, "
                "feed value into step N+1, look for cross-trust data return."
            ),
        }


# ----- Helpers -------------------------------------------------------------


async def _load_proxy_history(limit: int, host_filter: str) -> list[dict]:
    params = {"limit": limit}
    if host_filter:
        params["host"] = host_filter
    data = await client.get("/api/proxy/history", params=params)
    if "error" in data:
        return []
    history = data.get("history") or data.get("entries") or []
    return history if isinstance(history, list) else []


def _normalise_endpoint(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    # Collapse numeric / uuid path segments for grouping
    path = re.sub(r"/\d+(?=/|$)", "/<id>", path)
    path = re.sub(
        r"/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(?=/|$)",
        "/<uuid>", path, flags=re.IGNORECASE,
    )
    return f"{parts.scheme}://{parts.netloc}{path}".rstrip("/") or url


def _classify_trust(endpoint: str, entry: dict) -> str:
    """Public / authed / privileged."""
    if any(m in endpoint for m in _PUBLIC_TRUST_MARKERS):
        return "public"
    req_headers = entry.get("request_headers") or ""
    if isinstance(req_headers, list):
        req_headers = "\n".join(
            f"{h.get('name','')}: {h.get('value','')}" if isinstance(h, dict) else str(h)
            for h in req_headers
        )
    if _AUTH_HEADERS_RE.search(req_headers or ""):
        # Privileged hint: admin / internal / sudo in path
        if any(p in endpoint.lower() for p in ("/admin", "/internal", "/sudo", "/superuser")):
            return "privileged"
        return "authed"
    return "public"


def _harvest_atomic_values(body: str) -> set[str]:
    """Pull short atomic JSON string values from a body for collision lookup."""
    out: set[str] = set()
    for m in re.finditer(r':\s*"([^"\\]{6,64})"', body):
        v = m.group(1)
        # Filter very common boilerplate
        if v.lower() in ("application/json", "text/plain", "ok", "success"):
            continue
        out.add(v)
        if len(out) > 500:
            break
    return out


_TRUST_RANK = {"public": 0, "authed": 1, "privileged": 2, "unknown": 0}


def _trust_delta(trust_path: list[str]) -> int:
    if not trust_path:
        return 0
    ranks = [_TRUST_RANK.get(t, 0) for t in trust_path]
    return max(ranks) - min(ranks)


def _dfs_chains(start: str, edges_by_src: dict, meta: dict, max_depth: int):
    """Yield {path, via} dicts up to max_depth."""
    stack = [(start, [start], [])]
    while stack:
        node, path, via = stack.pop()
        if len(path) > max_depth:
            continue
        if len(path) >= 2:
            yield {"path": list(path), "via": list(via)}
        for e in edges_by_src.get(node, []):
            if e["to"] in path:
                continue
            stack.append((e["to"], path + [e["to"]], via + [e["via"]]))
