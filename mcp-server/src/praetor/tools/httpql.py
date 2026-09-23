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

from praetor import client
from praetor.tools.read._noise import classify, is_noise


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
        rl = entry.get("response_length")
        fv = rl if rl is not None else len(entry.get("response_body") or "")
        try: val = int(val)
        except ValueError: pass
    elif field == "noise":
        # noise = true/false (CDN/ads/analytics/telemetry/static), or a category:
        # noise = ads / noise ~ analytics.
        cat = classify(entry.get("url") or "", entry.get("mime_type") or "")
        lv = str(val).lower()
        if lv in ("true", "1", "yes"):
            return bool(cat)
        if lv in ("false", "0", "no"):
            return not cat
        return lv in cat if op == "~" else cat == lv
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
        drop_noise: bool = True,
    ) -> str:
        """Filter proxy history with HTTPQL-style DSL — noise dropped by default.

        Fields: method, status, url, host, path, body, header, length, noise.
        Operators: =, !=, ~ (substring), >, <, >=, <=.
        Combiners: AND, OR. No parens.

        `drop_noise=True` (default) hides third-party CDN / ads / analytics /
        telemetry / static-media rows — the beacon/asset flood a real browser
        session captures — so a lookup over thousands of rows returns just the
        target's app + API traffic and costs a fraction of the tokens. The footer
        reports how many were hidden; pass `drop_noise=False` to include them, or
        query the `noise` field directly (`noise = true`, `noise ~ ads`) to inspect
        what's being classed as noise. JS/CSS/JSON/source-maps are never noise.

        Examples:
            status >= 400 AND host = api.x.test
            method = POST AND body ~ token
            url ~ /oidc/callback              # find that one request, noise gone
            noise = true                      # inspect what's being dropped
        """
        data = await client.get(f"/api/proxy/history?limit={max(limit, offset + limit) + 50}")
        if "error" in data:
            return f"Error: {data['error']}"
        entries = data.get("items") or []
        # drop_noise is a no-op when the caller filters on `noise` explicitly — the
        # query owns the decision then.
        hidden = 0
        if drop_noise and not re.search(r"\bnoise\b", query, re.I):
            # A host the query filters on is a deliberate target — exempt it from the
            # noise deny-list so testing an extension/CDN host still works.
            keep = tuple(re.findall(r"\bhost\s*[=~]\s*[\"']?([^\s\"']+)", query, re.I))
            kept = [e for e in entries if not is_noise(e, keep)]
            hidden = len(entries) - len(kept)
            entries = kept
        # The list view omits request/response bodies and headers; fetch detail
        # per entry only when the query actually references them.
        if re.search(r"\b(body|header)\b", query, re.I):
            enriched = []
            for e in entries:
                idx = e.get("index")
                if idx is not None:
                    d = await client.get(f"/api/proxy/history/{int(idx)}")
                    if isinstance(d, dict) and "error" not in d:
                        e = {**e, **d}
                enriched.append(e)
            entries = enriched
        hits = [e for e in entries if _eval_query(query, e)]
        sliced = hits[offset:offset + limit]
        noise_note = f"  |  hid {hidden} noise rows (drop_noise=False to include)" if hidden else ""
        lines = [
            f"# query_history_dsl — {query!r}",
            f"Matches: {len(hits)} (showing {len(sliced)}, offset={offset}){noise_note}",
            "",
        ]
        for e in sliced:
            lines.append(
                f"  [{e.get('index','?')}]  {e.get('method','?')} "
                f"{e.get('status_code') or e.get('status','?')} "
                f"len={e.get('response_length', 0)}  {e.get('url','')[:120]}"
            )
        return "\n".join(lines)
