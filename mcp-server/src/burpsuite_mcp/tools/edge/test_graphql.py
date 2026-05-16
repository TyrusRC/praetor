"""Edge-case test: test_graphql with quick / deep depth modes.

Quick mode (4 tests): introspection, field suggestions, batch queries, GET CSRF.
Deep mode (6 tests): adds alias-DoS amplification + depth-limit testing on top of quick.
"""

import json

from burpsuite_mcp import client


async def _gql(session: str, path: str, query: str, as_array: bool = False) -> dict:
    body = [{"query": query}] if as_array else {"query": query}
    return await client.post("/api/session/request", json={
        "session": session, "method": "POST", "path": path,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    })


async def test_graphql_impl(
    session: str,
    path: str = "/graphql",
    depth: str = "quick",
) -> str:
    """Test GraphQL endpoint for introspection, field suggestions, batch, GET CSRF, and (deep) alias-DoS + depth limits.

    Args:
        session: Session name
        path: GraphQL endpoint path
        depth: 'quick' (4 tests) or 'deep' (6 tests including alias-DoS + depth limit)
    """
    lines = [f"GraphQL Security Test ({depth} mode): {path}\n"]
    risks: list[str] = []

    # Test 1: Introspection
    resp = await _gql(session, path, "{__schema{types{name,fields{name}}}}")
    if "error" in resp:
        return f"Error reaching GraphQL endpoint: {resp['error']}"
    body = resp.get("response_body", "")
    status = resp.get("status", 0)
    has_schema = "__schema" in body and "types" in body
    lines.append("Test 1 — Introspection:")
    if has_schema:
        risks.append("Introspection enabled — full schema exposed")
        if depth == "deep":
            try:
                gql_resp = json.loads(body)
                types = gql_resp.get("data", {}).get("__schema", {}).get("types", [])
                user_types = [t for t in types if not t.get("name", "").startswith("__")]
                lines.append(f"  EXPOSED — {len(user_types)} types found")
                for t in user_types[:15]:
                    fields = [f["name"] for f in (t.get("fields") or [])[:8]]
                    lines.append(f"    {t['name']}: {', '.join(fields) if fields else '(no fields)'}")
                if len(user_types) > 15:
                    lines.append(f"    ... and {len(user_types) - 15} more types")
            except (json.JSONDecodeError, KeyError):
                lines.append(f"  EXPOSED — schema in response (status {status})")
        else:
            lines.append(f"  [VULN] Introspection: ENABLED (schema leaked)")
    else:
        lines.append(f"  Blocked or not available (status {status})")

    # Test 2: Field suggestions
    resp2 = await _gql(session, path, "{__nonexistent_field_xyz}")
    body2 = resp2.get("response_body", "")
    lines.append("\nTest 2 — Field Suggestions:")
    if "did you mean" in body2.lower() or "suggestion" in body2.lower():
        risks.append("Field suggestions leak schema via error messages")
        lines.append(f"  EXPOSED — error reveals field suggestions")
        if depth == "deep":
            lines.append(f"  Snippet: {body2[:300].replace(chr(10), ' ')}")
    else:
        lines.append(f"  No suggestions leaked (status {resp2.get('status', '?')})")

    # Test 3: Batch query support
    batch_size = 10 if depth == "deep" else 3
    resp3 = await client.post("/api/session/request", json={
        "session": session, "method": "POST", "path": path,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps([{"query": "{__typename}"} for _ in range(batch_size)]),
    })
    body3 = resp3.get("response_body", "")
    status3 = resp3.get("status", 0)
    lines.append(f"\nTest 3 — Batch Query Abuse ({batch_size} queries):")
    if status3 == 200 and body3.strip().startswith("["):
        try:
            batch_resp = json.loads(body3)
            if isinstance(batch_resp, list) and len(batch_resp) >= batch_size:
                risks.append("Batch queries accepted — DoS / rate-limit bypass risk")
                lines.append(f"  VULNERABLE — {len(batch_resp)} responses returned")
            else:
                lines.append(f"  Partial — array with {len(batch_resp) if isinstance(batch_resp, list) else '?'} items")
        except json.JSONDecodeError:
            lines.append(f"  Array response but unparseable")
    else:
        lines.append(f"  Blocked or unsupported (status {status3})")

    # Test 4: GET-based query (CSRF)
    resp4 = await client.post("/api/session/request", json={
        "session": session, "method": "GET",
        "path": f"{path}?query={{__typename}}",
    })
    body4 = resp4.get("response_body", "")
    lines.append("\nTest 4 — GET-based queries (CSRF):")
    if "__typename" in body4.lower():
        risks.append("GET-based queries accepted — CSRF risk")
        lines.append(f"  [VULN] GET queries: ACCEPTED")
    else:
        lines.append(f"  Blocked (status {resp4.get('status', '?')})")

    # Deep-mode extras
    if depth == "deep":
        # Test 5: Alias-DoS amplification
        aliases = " ".join(f"a{i}:__typename" for i in range(100))
        resp5 = await _gql(session, path, "{" + aliases + "}")
        status5 = resp5.get("status", 0)
        body5 = resp5.get("response_body", "")
        lines.append("\nTest 5 — Alias-based DoS (100 aliases):")
        if status5 == 200 and "a99" in body5:
            risks.append("No alias limit — DoS via query amplification")
            lines.append(f"  VULNERABLE — all 100 aliases executed (status {status5})")
        elif status5 == 200:
            lines.append(f"  Partial — status 200 but aliases may be limited")
        else:
            lines.append(f"  Blocked or limited (status {status5})")

        # Test 6: Depth limit
        depth_query = "{user" + "{posts{comments{author" * 5 + "{name}" + "}" * 15 + "}"
        resp6 = await _gql(session, path, depth_query)
        status6 = resp6.get("status", 0)
        body6 = resp6.get("response_body", "")
        lines.append("\nTest 6 — Query Depth Limit:")
        has_depth_error = any(kw in body6.lower() for kw in ["depth", "complexity", "too deep", "max"])
        if has_depth_error:
            lines.append(f"  Protected — depth/complexity limit enforced (status {status6})")
        elif status6 == 200 and "error" not in body6.lower():
            risks.append("No query depth limit — DoS via deeply nested queries")
            lines.append(f"  NO LIMIT — deep query accepted (status {status6})")
        else:
            lines.append(f"  Query failed (status {status6}) — schema mismatch or limit")

    # Summary
    total = 6 if depth == "deep" else 4
    lines.append(f"\n--- Summary ---")
    lines.append(f"Risks found: {len(risks)}/{total} tests")
    if risks:
        for r in risks:
            lines.append(f"  [!] {r}")
    else:
        lines.append("No significant risks detected.")

    return "\n".join(lines)
