"""smart_request_triage — MCP tool (impl split into _impl.py)."""

from mcp.server.fastmcp import FastMCP
from ._impl import (
    _AUTH_HEADERS,
    _classify_body,
    _hkv,
    _parse_form_body,
    _parse_query,
    _synthesise,
)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def smart_request_triage(index: int) -> dict:
        """Capture a proxy/logger index, output a fire-ready attack plan.

        Collapses get_request_detail->extract_*->smart_analyze->reason->pick into ONE call. Reads the captured request/response, applies content-type + signal-driven routing, and emits a priority-ordered attack_plan whose suggested_call lines are ready to dispatch.

        Args:
            index: Proxy history index of the captured entry.

        Returns dict: index/url/method/status_code/content_type, request_params, headers, has_auth_header, tech_hints, response_signals, attack_plan[{priority, vuln_class, target_url, parameter, canary, suggested_tool, suggested_call, rationale}], human_summary.
        """
        if index < 0:
            return {"error": "smart_request_triage requires a non-negative index"}

        resp = await client.get(f"/api/proxy/history/{index}")
        if isinstance(resp, dict) and "error" in resp:
            return {"error": str(resp["error"])}

        url = resp.get("url") or resp.get("request_url") or ""
        method = (resp.get("method") or "GET").upper()
        status = int(resp.get("status_code", 0) or 0)
        req_headers = _hkv(resp.get("request_headers"))
        rsp_headers = _hkv(resp.get("response_headers"))
        content_type = rsp_headers.get("content-type", "")
        req_body = resp.get("request_body", "") or ""
        rsp_body = resp.get("response_body", "") or ""

        # Parse request params
        query_params = _parse_query(url)
        body_params = _parse_form_body(
            req_body, req_headers.get("content-type", ""))
        cookie_names = []
        if "cookie" in req_headers:
            cookie_names = [c.split("=", 1)[0].strip()
                            for c in req_headers["cookie"].split(";") if "=" in c]

        # Auth surface
        has_auth = any(h in req_headers for h in _AUTH_HEADERS)

        # Tech hints from server/x-powered-by
        tech_hints = []
        for h in ("server", "x-powered-by", "x-aspnet-version", "x-runtime"):
            v = rsp_headers.get(h)
            if v:
                tech_hints.append(f"{h}: {v}")

        # Response classification
        body_signals = _classify_body(rsp_body, content_type)

        triage: dict[str, Any] = {
            "index": index,
            "url": url,
            "method": method,
            "status_code": status,
            "content_type": content_type,
            "request_params": {
                "query": query_params,
                "body": body_params,
                "cookies": cookie_names,
            },
            "request_headers": sorted(req_headers.keys()),
            "response_headers": sorted(rsp_headers.keys()),
            "has_auth_header": has_auth,
            "tech_hints": tech_hints,
            "response_size": len(rsp_body),
            "response_signals": body_signals,
        }

        plan = _synthesise(triage)
        triage["attack_plan"] = plan

        # Human summary
        lines = [
            f"smart_request_triage[{index}]: [{method}] {url} -> {status} ({content_type})",
            f"  params: query={query_params} body={body_params} cookies={cookie_names}",
            f"  auth_header={has_auth} tech={tech_hints} response_size={len(rsp_body)}",
        ]
        sig = body_signals
        if sig["error_class"]:
            lines.append(f"  !! error_marker: {sig['error_class']}")
        if sig["stack_trace"]:
            lines.append("  !! stack_trace detected")
        if sig["rsc_response"]:
            lines.append("  !! RSC Flight response (text/x-component)")
        if sig["graphql_response"]:
            lines.append("  !! GraphQL response shape")
        if sig["has_forms"]:
            lines.append(f"  forms: {len(sig['form_inputs'])} input(s)")
        if sig["secrets"]:
            lines.append(f"  !! secrets in body: {[s['type'] for s in sig['secrets']]}")
        lines.append("")
        lines.append(f"Attack plan ({len(plan)} entries):")
        for i, p in enumerate(plan, 1):
            lines.append(f"  [{i}] P{p['priority']} {p['vuln_class']:<28} "
                         f"{p['suggested_tool']}")
            lines.append(f"       call: {p['suggested_call']}")
            lines.append(f"       why : {p['rationale'][:140]}")
        if not plan:
            lines.append("  (no actionable signals — annotate + move on)")

        triage["human_summary"] = "\n".join(lines)
        return triage


# Re-export _impl's module surface so tests and callers that reach these on the
# package path (e.g. <module>.client, <module>._scan_secrets, <module>._VERIFY_HINTS)
# keep resolving after the impl split. register() above is defined here, not in
# _impl, so it is never shadowed.
from . import _impl as _impl  # noqa: E402
globals().update({_k: getattr(_impl, _k) for _k in dir(_impl) if not _k.startswith("__")})
