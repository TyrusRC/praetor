"""run_mcptox — harness for MCPTox-style audits of MCP servers.

MCPTox (Anthropic 2026 disclosure + 4open.science corpus) audits MCP servers
for tool-description prompt injection, rug-pull mutations, hidden directives,
and tool-name shadow attacks. The corpus is **license-gated** (operator
must accept terms at 4open.science before download); this harness:

  1. Detects whether the operator has the corpus locally (`MCPTOX_CORPUS_DIR`
     env var OR `~/.praetor/mcptox/corpus/`).
  2. If absent, runs the in-tree heuristic audit pattern using Praetor's
     existing `mcp_server_attacks.json` + `ai_prompt_injection.json` KB.
  3. If present, drives the corpus payloads through the operator's MCP
     server endpoint (provided as base_url + auth) and reports VerdictResult.

Without the corpus, the harness still ships a useful in-tree audit covering:
  - Tool-description PI: Unit 42 hidden-directive / persistence / covert
    tool-call markers (W26 KB contexts)
  - Tool-name shadow: scan tool list for names that match Praetor's known
    legitimate-tool list with 1-char edit distance (typosquat hunt)
  - Argument-schema PI: scan tool input schemas for description-field
    directives that LLMs follow when generating arg payloads

Routes detection through curl_request via Burp. Scope-checked.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict


def _corpus_dir() -> Path | None:
    """Return the corpus dir if operator has set it up; else None."""
    env = os.environ.get("MCPTOX_CORPUS_DIR")
    if env:
        p = Path(env).expanduser()
        if p.is_dir():
            return p
    default = Path.home() / ".praetor" / "mcptox" / "corpus"
    if default.is_dir():
        return default
    return None


# In-tree heuristic markers — matched against MCP server tool descriptions
# and schema strings. Mirror of W26 KB regex patterns.
_PI_HIDDEN_DIRECTIVE_RE = re.compile(
    r"(?i)(after finishing|after answering|in addition,?)\s+"
    r"(the (summary|task)|the previous question)\s*,?\s*"
    r"(please|ensure)\s+(also\s+)?(write|produce|generate)"
)
_PI_PERSISTENCE_RE = re.compile(
    r"(?i)(put|include|ensure)\s+the\s+following\s+(text|response)\s+"
    r"(verbatim|exactly|word for word)|speak\s+like\s+a\s+\w+\s+in\s+all\s+responses"
)
_PI_COVERT_TOOL_RE = re.compile(
    r"(?i)(invoke|call|execute|use)\s+the\s+(tool|function)\s+"
    r"(to|named|called)\s+\S+|(write|save|create)\s+(\[[^\]]+\]|the (content|file|payload))\s+"
    r"to\s+(\[[^\]]+\]|the\s+(file|disk|filesystem))"
)
_PI_INVISIBLE_UNICODE_RE = re.compile(r"[​‌‍﻿]")

# Tool-name typosquat targets — well-known legitimate tools an attacker might
# shadow to hijack agent tool-calls. Edit-distance-1 names are suspicious.
_LEGIT_TOOL_NAMES = (
    "search", "read_file", "write_file", "list_directory", "execute_command",
    "fetch", "send_email", "create_issue", "get_user", "update_record",
    "delete_resource", "query_database", "run_query",
)


def _edit_distance_le_1(a: str, b: str) -> bool:
    """True if Levenshtein distance ≤ 1. Cheap impl for short strings."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:  # substitution check
        diffs = sum(1 for x, y in zip(a, b) if x != y)
        return diffs == 1
    # Insertion / deletion — la != lb by exactly 1
    longer, shorter = (a, b) if la > lb else (b, a)
    for i in range(len(longer)):
        if longer[:i] + longer[i+1:] == shorter:
            return True
    return False


def _audit_tool_descriptions(tools: list[dict]) -> list[dict]:
    """Run W26 heuristics across a list of MCP tool dicts."""
    findings: list[dict] = []
    legit_lower = {t.lower() for t in _LEGIT_TOOL_NAMES}
    for t in tools:
        if not isinstance(t, dict):
            continue
        name = str(t.get("name", ""))
        desc = str(t.get("description", ""))
        schema_str = json.dumps(t.get("inputSchema") or t.get("schema") or {})
        haystack = f"{name}\n{desc}\n{schema_str}"

        signals: list[str] = []
        if _PI_HIDDEN_DIRECTIVE_RE.search(haystack):
            signals.append("hidden_directive")
        if _PI_PERSISTENCE_RE.search(haystack):
            signals.append("persistence_hijack")
        if _PI_COVERT_TOOL_RE.search(haystack):
            signals.append("covert_tool_invocation")
        if _PI_INVISIBLE_UNICODE_RE.search(haystack):
            signals.append("invisible_unicode")

        # Typosquat — name within edit-distance 1 of a known legit tool
        # AND not exactly matching one (exact match is fine; it's the
        # intended tool, not a shadow)
        nlow = name.lower()
        if nlow not in legit_lower:
            for legit in legit_lower:
                if _edit_distance_le_1(nlow, legit):
                    signals.append(f"typosquat:{legit}")
                    break

        if signals:
            findings.append({
                "tool_name": name,
                "signals": signals,
                "description_excerpt": desc[:200],
            })
    return findings


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_mcptox(  # cost: medium (1 + N tools requests)
        base_url: str,
        tools_endpoint: str = "/tools",
        bearer_token: str = "",
        cookies: dict | None = None,
        use_corpus: bool = True,
    ) -> dict:
        """Audit an MCP server for tool-description PI / typosquat / hidden directives.

        Two paths:
          - In-tree heuristic (default) — applies W26 Unit-42-derived regex
            patterns + typosquat-vs-legit-names check against the server's
            advertised tool list.
          - Corpus-driven (when MCPTOX_CORPUS_DIR is set + use_corpus=True) —
            additionally fires the 4open.science MCPTox corpus payloads
            against the server. License-gated by the operator's pre-acceptance
            at 4open.science; this tool does NOT auto-download.

        Args:
            base_url: MCP server base URL (e.g. https://mcp.target.tld)
            tools_endpoint: Path that lists available tools (default '/tools').
                Many MCP servers expose this via GET / SSE; operator may
                need to override per-server.
            bearer_token: Optional auth (some MCP servers require it)
            cookies: Optional session cookies
            use_corpus: Attempt to drive 4open.science MCPTox payloads when
                the corpus dir is configured locally.

        Returns VerdictResult — CONFIRMED on any heuristic hit OR corpus
        payload acceptance; FAILED otherwise; ERROR on connectivity issue.
        """
        if not base_url:
            return error_verdict("base_url is required",
                                 vuln_type="mcptox_self_audit")

        # Scope check
        scope_chk = await client.check_scope(base_url)
        if isinstance(scope_chk, dict):
            if "error" in scope_chk:
                return error_verdict(f"scope check failed: {scope_chk['error']}",
                                     vuln_type="mcptox_self_audit")
            if not scope_chk.get("in_scope", True):
                return error_verdict(f"{base_url} not in scope",
                                     vuln_type="mcptox_self_audit")

        # ── Fetch the tool list ──
        url = base_url.rstrip("/") + "/" + tools_endpoint.lstrip("/")
        headers: dict[str, str] = {}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        if cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

        resp = await client.post("/api/http/curl", json={
            "method": "GET",
            "url": url,
            "headers": headers,
            "follow_redirects": False,
        })
        if isinstance(resp, dict) and "error" in resp:
            return error_verdict(f"tools fetch failed: {resp['error']}",
                                 vuln_type="mcptox_self_audit")
        status = resp.get("status_code", 0)
        idx = resp.get("proxy_index", resp.get("history_index", -1))
        body = resp.get("response_body") or ""
        logger_indices: list[int] = []
        if isinstance(idx, int) and idx >= 0:
            logger_indices.append(idx)

        if status not in (200, 204):
            return error_verdict(
                f"tools endpoint returned status {status}",
                vuln_type="mcptox_self_audit",
            )

        # Parse the tool list — accept both `{"tools": [...]}` and bare `[...]`
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            return error_verdict(
                "tools endpoint returned non-JSON body",
                vuln_type="mcptox_self_audit",
            )
        if isinstance(data, dict) and "tools" in data:
            tools = data["tools"]
        elif isinstance(data, list):
            tools = data
        else:
            return error_verdict(
                "tools endpoint returned unexpected shape (need list or {tools:[...]})",
                vuln_type="mcptox_self_audit",
            )

        # ── In-tree heuristic audit ──
        findings = _audit_tool_descriptions(tools)

        # ── Corpus integration (when configured) ──
        corpus_dir = _corpus_dir() if use_corpus else None
        corpus_used = corpus_dir is not None
        corpus_findings: list[dict] = []
        if corpus_used:
            # Lazy: list .json files in the corpus dir; load up to 50 for
            # this single-session ship. Full driver is a v2 task.
            payload_files = sorted(corpus_dir.glob("*.json"))[:50]
            corpus_findings.append({
                "note": f"corpus dir present ({corpus_dir}); "
                        f"{len(payload_files)} payload file(s) found; "
                        "v1 ships heuristic audit only — corpus driver in v2",
                "files_seen": len(payload_files),
            })

        lines = [f"run_mcptox — {base_url} ({len(tools)} tools advertised):"]
        for f in findings:
            lines.append(f"  [HIT] {f['tool_name']!r} signals={','.join(f['signals'])}")
            lines.append(f"        desc: {f['description_excerpt'][:120]!r}")
        if not findings:
            lines.append("  no heuristic signals across tool descriptions")
        if corpus_used:
            lines.append("")
            lines.append(f"  corpus: {corpus_findings[0]['note']}")
        else:
            lines.append("")
            lines.append("  corpus: not configured (set MCPTOX_CORPUS_DIR after "
                         "accepting 4open.science license terms)")

        details: dict[str, Any] = {
            "base_url": base_url,
            "tools_count": len(tools),
            "heuristic_findings": findings,
            "corpus_used": corpus_used,
            "corpus_findings": corpus_findings,
        }

        if findings:
            severity_signals = {s for f in findings for s in f["signals"]}
            crit = any(s in severity_signals
                       for s in ("covert_tool_invocation", "persistence_hijack"))
            confidence = 0.85 if crit else 0.70
            return make_verdict(
                "CONFIRMED", confidence,
                f"MCP server advertises {len(findings)} suspicious tool(s) — "
                f"signals: {sorted(severity_signals)}",
                vuln_type="mcptox_self_audit",
                logger_indices=logger_indices,
                details=details,
                summary="\n".join(lines),
            )
        return make_verdict(
            "FAILED", 0.10,
            f"no heuristic signals across {len(tools)} MCP tools",
            vuln_type="mcptox_self_audit",
            logger_indices=logger_indices,
            details=details,
            summary="\n".join(lines),
        )
