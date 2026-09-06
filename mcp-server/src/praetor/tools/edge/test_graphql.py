"""Edge-case test: test_graphql (quick / deep / introspection_fuzz). GraphQL
helpers live in _graphql_helpers; this is the impl.
"""

import json

from praetor import client

from ._graphql_helpers import _gql, _introspection_fuzz  # noqa: F401


async def test_graphql_impl(
    session: str,
    path: str = "/graphql",
    depth: str = "quick",
) -> dict:
    """Test GraphQL endpoint for introspection, field suggestions, batch, GET CSRF, alias-DoS, depth limits, and introspection-driven field-by-field fuzz.

    Args:
        session: Session name
        path: GraphQL endpoint path
        depth: 'quick' (4 tests) | 'deep' (6 tests) | 'introspection_fuzz' (deep + per-field probe across whole schema)
    """
    lines = [f"GraphQL Security Test ({depth} mode): {path}\n"]
    risks: list[str] = []

    # Test 1: Introspection
    resp = await _gql(session, path, "{__schema{types{name,fields{name}}}}")
    if "error" in resp:
        from praetor.tools.testing._verdict import error_verdict
        return error_verdict(
            f"GraphQL endpoint unreachable: {resp['error']}",
            vuln_type="graphql",
        )
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
            lines.append("  [VULN] Introspection: ENABLED (schema leaked)")
    else:
        lines.append(f"  Blocked or not available (status {status})")

    # Test 2: Field suggestions
    resp2 = await _gql(session, path, "{__nonexistent_field_xyz}")
    body2 = resp2.get("response_body", "")
    lines.append("\nTest 2 — Field Suggestions:")
    if "did you mean" in body2.lower() or "suggestion" in body2.lower():
        risks.append("Field suggestions leak schema via error messages")
        lines.append("  EXPOSED — error reveals field suggestions")
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
            lines.append("  Array response but unparseable")
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
        lines.append("  [VULN] GET queries: ACCEPTED")
    else:
        lines.append(f"  Blocked (status {resp4.get('status', '?')})")

    # Deep-mode extras (and introspection_fuzz runs deep first)
    if depth in ("deep", "introspection_fuzz"):
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
            lines.append("  Partial — status 200 but aliases may be limited")
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

    # Introspection-fuzz mode: walk every field
    if depth == "introspection_fuzz":
        fuzz_lines = await _introspection_fuzz(session, path)
        lines.extend(fuzz_lines)

    # Summary
    total = {"quick": 4, "deep": 6, "introspection_fuzz": 6}.get(depth, 4)
    lines.append("\n--- Summary ---")
    lines.append(f"Risks found: {len(risks)}/{total} tests")
    if risks:
        for r in risks:
            lines.append(f"  [!] {r}")
    else:
        lines.append("No significant risks detected.")

    human = "\n".join(lines)
    from praetor.tools.testing._verdict import make_verdict
    crit_keywords = ("introspection enabled", "batch", "alias-dos", "no depth limit")
    crit_hits = sum(1 for r in risks if any(k in r.lower() for k in crit_keywords))
    if crit_hits >= 2:
        verdict, confidence = "CONFIRMED", 0.8
        ev = f"GraphQL: {crit_hits} critical risks of {len(risks)} total ({depth} mode)"
    elif risks:
        verdict, confidence = "SUSPECTED", 0.55
        ev = f"GraphQL: {len(risks)} risk(s) flagged — operator review per item"
    else:
        verdict, confidence = "FAILED", 0.1
        ev = "GraphQL hardened — no significant risks across enabled tests"

    return make_verdict(
        verdict, confidence, ev,
        vuln_type="graphql",
        details={"path": path, "depth": depth, "risks": risks},
        summary=human,
    )
