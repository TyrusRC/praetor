"""GraphQL introspection/query helpers for test_graphql."""

import json
from typing import Any

from praetor import client


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
