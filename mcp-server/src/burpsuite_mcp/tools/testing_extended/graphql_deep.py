"""test_graphql_deep — extended GraphQL testing (introspection, suggestions, alias DoS, batch, depth)."""

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_graphql_deep(session: str, path: str = "/graphql") -> str:
        """Extended GraphQL testing — introspection, field suggestions, alias DoS, batching,
        depth limits, and type enumeration.

        Example:
            test_graphql_deep(session="my_session", path="/graphql")

        Args:
            session: Session name for auth state
            path: GraphQL endpoint path (default /graphql)
        """
        results = []
        tests_passed = 0
        risks = []

        async def _gql(query: str, as_array: bool = False) -> dict:
            body = [{"query": query}] if as_array else {"query": query}
            return await client.post("/api/session/request", json={
                "session": session, "method": "POST", "path": path,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps(body),
            })

        # Test 1: Introspection
        resp = await _gql("{__schema{types{name,fields{name}}}}")
        if "error" in resp:
            return f"Error reaching GraphQL endpoint: {resp['error']}"

        body = resp.get("response_body", "")
        status = resp.get("status", 0)
        has_schema = "__schema" in body and "types" in body

        results.append("Test 1 — Introspection:")
        if has_schema:
            tests_passed += 1
            risks.append("Introspection enabled — full schema exposed")
            try:
                gql_resp = json.loads(body)
                types = gql_resp.get("data", {}).get("__schema", {}).get("types", [])
                user_types = [t for t in types if not t.get("name", "").startswith("__")]
                results.append(f"  EXPOSED — {len(user_types)} types found")
                for t in user_types[:15]:
                    fields = [f["name"] for f in (t.get("fields") or [])[:8]]
                    results.append(f"    {t['name']}: {', '.join(fields) if fields else '(no fields)'}")
                if len(user_types) > 15:
                    results.append(f"    ... and {len(user_types) - 15} more types")
            except (json.JSONDecodeError, KeyError):
                results.append(f"  EXPOSED — response contains schema data (status {status})")
        else:
            results.append(f"  Blocked or not available (status {status})")

        # Test 2: Field suggestions via malformed query
        resp2 = await _gql("{__nonexistent_field_xyz}")
        body2 = resp2.get("response_body", "")
        results.append("\nTest 2 — Field Suggestions (error leakage):")
        if "did you mean" in body2.lower() or "suggestion" in body2.lower():
            tests_passed += 1
            risks.append("Field suggestions in errors — enables schema enumeration without introspection")
            results.append(f"  EXPOSED — error reveals field suggestions")
            snippet = body2[:300].replace("\n", " ")
            results.append(f"  Snippet: {snippet}")
        else:
            results.append(f"  No suggestions leaked (status {resp2.get('status', '?')})")

        # Test 3: Alias-based DoS
        aliases = " ".join(f"a{i}:__typename" for i in range(100))
        resp3 = await _gql("{" + aliases + "}")
        status3 = resp3.get("status", 0)
        body3 = resp3.get("response_body", "")
        results.append("\nTest 3 — Alias-based DoS (100 aliases):")
        if status3 == 200 and "a99" in body3:
            tests_passed += 1
            risks.append("No alias limit — potential DoS via query amplification")
            results.append(f"  VULNERABLE — all 100 aliases executed (status {status3})")
        elif status3 == 200:
            results.append(f"  Partial — status 200 but aliases may be limited")
        else:
            results.append(f"  Blocked or limited (status {status3})")

        # Test 4: Batch query abuse
        resp4 = await client.post("/api/session/request", json={
            "session": session, "method": "POST", "path": path,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps([{"query": "{__typename}"} for _ in range(10)]),
        })
        status4 = resp4.get("status", 0)
        body4 = resp4.get("response_body", "")
        results.append("\nTest 4 — Batch Query Abuse (10 queries):")
        if status4 == 200 and body4.strip().startswith("["):
            try:
                batch_resp = json.loads(body4)
                if isinstance(batch_resp, list) and len(batch_resp) >= 10:
                    tests_passed += 1
                    risks.append("Batch queries accepted — enables rate limit bypass and DoS")
                    results.append(f"  VULNERABLE — {len(batch_resp)} responses returned")
                else:
                    results.append(f"  Partial — array response with {len(batch_resp) if isinstance(batch_resp, list) else '?'} items")
            except json.JSONDecodeError:
                results.append(f"  Array response but could not parse")
        else:
            results.append(f"  Blocked or unsupported (status {status4})")

        # Test 5: Depth limit testing
        depth_query = "{user" + "{posts{comments{author" * 5 + "{name}" + "}" * 15 + "}"
        resp5 = await _gql(depth_query)
        status5 = resp5.get("status", 0)
        body5 = resp5.get("response_body", "")
        results.append("\nTest 5 — Query Depth Limit:")
        has_depth_error = any(kw in body5.lower() for kw in ["depth", "complexity", "too deep", "max"])
        if has_depth_error:
            results.append(f"  Protected — depth/complexity limit enforced (status {status5})")
        elif status5 == 200 and "error" not in body5.lower():
            tests_passed += 1
            risks.append("No query depth limit — potential DoS via deeply nested queries")
            results.append(f"  NO LIMIT — deep query accepted (status {status5})")
        else:
            results.append(f"  Query failed (status {status5}) — may have schema mismatch or limit")

        # Test 6: __typename enumeration
        resp6 = await _gql("{__typename}")
        body6 = resp6.get("response_body", "")
        results.append("\nTest 6 — __typename Enumeration:")
        try:
            typename_resp = json.loads(body6)
            typename = typename_resp.get("data", {}).get("__typename", "")
            if typename:
                results.append(f"  Root type: {typename}")
            else:
                results.append(f"  __typename not exposed")
        except (json.JSONDecodeError, AttributeError):
            results.append(f"  Could not parse response")

        results.append(f"\n--- Summary ---")
        results.append(f"Tests with findings: {tests_passed}/6")
        if risks:
            results.append("Risks:")
            for r in risks:
                results.append(f"  [!] {r}")
        else:
            results.append("No significant risks detected.")

        return "\n".join(results)
