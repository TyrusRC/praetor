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

import re
from collections import defaultdict
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP

from praetor import client

from ._rre_helpers import (
    _build_dag_impl,
    _load_proxy_history,
    _normalise_endpoint,
    _classify_trust,
    _harvest_atomic_values,
    _trust_delta,
    _dfs_chains,
    _SENSITIVE_RESPONSE_FIELDS,
    _HIGH_VALUE_INPUT_PARAMS,
    _PUBLIC_TRUST_MARKERS,
    _AUTH_HEADERS_RE,
    _JSON_KEY_RE,
    _TRUST_RANK,
)

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
