"""HTTPQL — small DSL over Burp proxy history.

Supports SQL-like filtering with operators: =, !=, ~ (substring), >, <, in.
Fields: method, status, url, host, path, type (request|response), body, header.

Example:
    status >= 400 AND host = api.x.test AND url ~ /admin
    method = POST AND header ~ Authorization
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


_TOKEN = re.compile(r"\s*(\(|\)|AND|OR|NOT|[!<>=~]+|\".*?\"|'.*?'|\S+)", re.IGNORECASE)


def _tokenise(q: str) -> list[str]:
    out = []
    pos = 0
    while pos < len(q):
        m = _TOKEN.match(q, pos)
        if not m:
            break
        tok = m.group(1)
        out.append(tok)
        pos = m.end()
    return out


def _eval_clause(field: str, op: str, val: str, entry: dict) -> bool:
    fv = ""
    if field == "method":
        fv = (entry.get("method") or "").upper()
        val = val.upper()
    elif field == "status":
        fv = entry.get("status_code") or entry.get("status") or 0
        try: fv = int(fv); val = int(val)
        except (TypeError, ValueError): pass
    elif field == "url":
        fv = entry.get("url") or ""
    elif field == "host":
        fv = urlparse(entry.get("url") or "").hostname or ""
    elif field == "path":
        fv = urlparse(entry.get("url") or "").path or ""
    elif field == "body":
        fv = (entry.get("request_body") or "") + " " + (entry.get("response_body") or "")
    elif field == "header":
        flat = []
        for h in (entry.get("request_headers") or []) + (entry.get("response_headers") or []):
            if isinstance(h, dict):
                flat.append(f"{h.get('name','')}: {h.get('value','')}")
        fv = "\n".join(flat)
    elif field == "length":
        fv = len(entry.get("response_body") or "")
        try: val = int(val)
        except ValueError: pass
    else:
        return False

    if op == "=":
        return fv == val
    if op == "!=":
        return fv != val
    if op == "~":
        return str(val) in str(fv)
    if op in (">", "<", ">=", "<="):
        try:
            a, b = float(fv), float(val)
        except (TypeError, ValueError):
            return False
        return {">": a > b, "<": a < b, ">=": a >= b, "<=": a <= b}[op]
    return False


def _eval_query(query: str, entry: dict) -> bool:
    """Tiny recursive-descent over (clause [AND|OR clause]*) — no parens nesting."""
    tokens = _tokenise(query)
    if not tokens:
        return True
    i = 0
    result: bool | None = None
    pending_op = "AND"
    while i < len(tokens):
        if i + 2 >= len(tokens):
            break
        field = tokens[i].strip("\"'").lower()
        op = tokens[i + 1]
        val = tokens[i + 2].strip("\"'")
        i += 3
        clause_val = _eval_clause(field, op, val, entry)
        if result is None:
            result = clause_val
        elif pending_op.upper() == "AND":
            result = result and clause_val
        elif pending_op.upper() == "OR":
            result = result or clause_val
        if i < len(tokens) and tokens[i].upper() in ("AND", "OR"):
            pending_op = tokens[i]
            i += 1
    return bool(result)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def query_history_dsl(
        query: str,
        limit: int = 100,
        offset: int = 0,
    ) -> str:
        """Filter proxy history with HTTPQL-style DSL.

        Fields: method, status, url, host, path, body, header, length.
        Operators: =, !=, ~ (substring), >, <, >=, <=.
        Combiners: AND, OR. No parens.

        Examples:
            status >= 400 AND host = api.x.test
            method = POST AND body ~ token
            url ~ /admin AND status = 200
        """
        data = await client.get(f"/api/proxy?limit={max(limit, offset + limit) + 50}")
        if "error" in data:
            return f"Error: {data['error']}"
        entries = data.get("entries") or data.get("history") or []
        hits = [e for e in entries if _eval_query(query, e)]
        sliced = hits[offset:offset + limit]
        lines = [
            f"# query_history_dsl — {query!r}",
            f"Matches: {len(hits)} (showing {len(sliced)}, offset={offset})",
            "",
        ]
        for e in sliced:
            lines.append(
                f"  [{e.get('index','?')}]  {e.get('method','?')} "
                f"{e.get('status_code') or e.get('status','?')} "
                f"len={len(e.get('response_body') or '')}  {e.get('url','')[:120]}"
            )
        return "\n".join(lines)
