"""Edge-case test: test_graphql with quick / deep / introspection_fuzz modes.

Quick mode (4 tests): introspection, field suggestions, batch queries, GET CSRF.
Deep mode (6 tests): adds alias-DoS amplification + depth-limit testing on top of quick.
introspection_fuzz mode: pulls __schema, walks every Query/Mutation field, builds a
  type-correct call per field, and fires each — surfaces ABAC / IDOR / hidden mutation
  surface that quick/deep don't reach.
"""

import json
from typing import Any

from burpsuite_mcp import client


async def _gql(session: str, path: str, query: str, as_array: bool = False) -> dict:
    body = [{"query": query}] if as_array else {"query": query}
    return await client.post("/api/session/request", json={
        "session": session, "method": "POST", "path": path,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    })


# ── Introspection-driven fuzzer ──

_INTROSPECTION_QUERY = """
{ __schema {
  queryType { name }
  mutationType { name }
  types {
    name kind
    fields { name args { name type { kind name ofType { kind name ofType { kind name } } } type { kind name ofType { kind name } } }
  }
}}
""".strip()


def _resolve_type(t: dict) -> tuple[str, bool]:
    """Walk wrapped types (NON_NULL/LIST) to the inner name. Returns (name, is_list)."""
    is_list = False
    cur = t
    while cur and cur.get("kind") in ("NON_NULL", "LIST"):
        if cur.get("kind") == "LIST":
            is_list = True
        cur = cur.get("ofType") or {}
    return (cur.get("name") or "Unknown"), is_list


def _stub_value(type_name: str, is_list: bool) -> Any:
    """Generate a plausible value for a scalar of given name."""
    base: Any
    if type_name in ("Int", "Long", "Float"):
        base = 1
    elif type_name == "Boolean":
        base = True
    elif type_name == "ID":
        base = "1"
    elif type_name == "String":
        base = "swkProbe"
    elif type_name == "DateTime":
        base = "2026-01-01T00:00:00Z"
    elif type_name == "JSON":
        base = {"probe": True}
    else:
        # Unknown / custom scalar / enum / input object — use string fallback
        base = "swkProbe"
    return [base] if is_list else base


def _format_value(v: Any) -> str:
    """Format a value for inline GraphQL argument literal."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v)  # quoted
    if isinstance(v, list):
        return "[" + ", ".join(_format_value(x) for x in v) + "]"
    if isinstance(v, dict):
        parts = [f"{k}: {_format_value(v2)}" for k, v2 in v.items()]
        return "{" + ", ".join(parts) + "}"
    return "null"


def _build_field_query(operation: str, field_name: str, args: list[dict]) -> str:
    """Build a minimal `{ field(args) { __typename } }` invocation."""
    arg_parts = []
    for a in args:
        type_name, is_list = _resolve_type(a.get("type", {}))
        val = _stub_value(type_name, is_list)
        arg_parts.append(f"{a['name']}: {_format_value(val)}")
    arg_str = f"({', '.join(arg_parts)})" if arg_parts else ""
    op_keyword = "mutation" if operation == "Mutation" else ""
    return f"{op_keyword} {{ {field_name}{arg_str} {{ __typename }} }}".strip()


async def _introspection_fuzz(session: str, path: str, max_per_op: int = 30) -> list[str]:
    """Walk the schema's Query+Mutation fields and probe each. Returns log lines."""
    lines = ["", "--- Introspection-driven fuzz ---"]
    resp = await _gql(session, path, _INTROSPECTION_QUERY)
    if "error" in resp:
        lines.append(f"  introspection request failed: {resp['error']}")
        return lines
    body = resp.get("response_body", "")
    try:
        schema = json.loads(body).get("data", {}).get("__schema", {})
    except (json.JSONDecodeError, AttributeError):
        lines.append("  introspection response not parseable (schema may be locked down)")
        return lines

    types = {t["name"]: t for t in schema.get("types", []) if t.get("name")}
    query_name = (schema.get("queryType") or {}).get("name") or "Query"
    mutation_name = (schema.get("mutationType") or {}).get("name") or ""

    findings = {
        "auth_bypass": [],
        "idor_candidate": [],
        "info_disclosure": [],
        "errors": [],
    }

    for op_label, type_name in [("Query", query_name), ("Mutation", mutation_name)]:
        if not type_name or type_name not in types:
            continue
        op_type = types[type_name]
        fields = op_type.get("fields") or []
        lines.append(f"\n  {op_label}: {type_name} ({len(fields)} fields)")
        for fi, field in enumerate(fields[:max_per_op]):
            fname = field.get("name", "")
            args = field.get("args") or []
            query = _build_field_query(op_label, fname, args)
            r = await _gql(session, path, query)
            if "error" in r:
                continue
            r_body = r.get("response_body", "")
            r_status = r.get("status", 0)
            # Classify
            try:
                rj = json.loads(r_body)
            except json.JSONDecodeError:
                rj = {}
            has_data = bool(rj.get("data"))
            errs = rj.get("errors", []) if isinstance(rj, dict) else []
            err_str = json.dumps(errs)[:120] if errs else ""

            tags = []
            # Look for known authz-error patterns to distinguish "no auth" vs "200 OK with data"
            if has_data and rj.get("data", {}).get(fname) is not None and 200 <= r_status < 300 and not errs:
                tags.append("DATA_RETURNED")
                lower_q = query.lower()
                if "delete" in fname.lower() or "remove" in fname.lower() or "destroy" in fname.lower():
                    findings["auth_bypass"].append(f"{op_label}.{fname}")
                elif any(k in fname.lower() for k in ("admin", "internal", "private", "secret", "audit", "log")):
                    findings["info_disclosure"].append(f"{op_label}.{fname}")
                elif "id:" in query and op_label == "Query":
                    findings["idor_candidate"].append(f"{op_label}.{fname}")
            elif errs:
                err_text = err_str.lower()
                if "unauthor" in err_text or "forbidden" in err_text or "denied" in err_text or "permission" in err_text:
                    tags.append("AUTHZ_REJECTED")
                elif "field" in err_text and "not found" in err_text:
                    tags.append("UNKNOWN_FIELD")  # schema shifted under us
                else:
                    tags.append("OTHER_ERROR")

            tag_str = " ".join(f"[{t}]" for t in tags) if tags else ""
            qpreview = query[:90] + ("..." if len(query) > 90 else "")
            lines.append(f"    {fname}({len(args)} args) -> status={r_status} {tag_str} {qpreview}")
            if err_str and tags == ["OTHER_ERROR"]:
                lines.append(f"      err: {err_str}")

    lines.append("")
    lines.append("  --- Introspection-fuzz summary ---")
    for k, v in findings.items():
        if v:
            lines.append(f"  {k}: {len(v)} -> {v[:10]}")
    if not any(findings.values()):
        lines.append("  No data-returning fields found via stub-value probing. Either all require valid input or AuthN is enforced uniformly.")
    return lines


async def test_graphql_impl(
    session: str,
    path: str = "/graphql",
    depth: str = "quick",
) -> str:
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

    # Introspection-fuzz mode: walk every field
    if depth == "introspection_fuzz":
        fuzz_lines = await _introspection_fuzz(session, path)
        lines.extend(fuzz_lines)

    # Summary
    total = {"quick": 4, "deep": 6, "introspection_fuzz": 6}.get(depth, 4)
    lines.append(f"\n--- Summary ---")
    lines.append(f"Risks found: {len(risks)}/{total} tests")
    if risks:
        for r in risks:
            lines.append(f"  [!] {r}")
    else:
        lines.append("No significant risks detected.")

    return "\n".join(lines)
