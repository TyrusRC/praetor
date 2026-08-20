"""smart_js_analyze — MCP tool (impl split into _impl.py)."""

from mcp.server.fastmcp import FastMCP
from ._impl import (
    _analyze_body,
    _fetch_index,
    _fetch_url,
    _synthesise_plan,
)


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


# Re-export _impl's module surface so tests and callers that reach these on the
# package path (e.g. <module>.client, <module>._scan_secrets, <module>._VERIFY_HINTS)
# keep resolving after the impl split. register() above is defined here, not in
# _impl, so it is never shadowed.
from . import _impl as _impl  # noqa: E402
globals().update({_k: getattr(_impl, _k) for _k in dir(_impl) if not _k.startswith("__")})
