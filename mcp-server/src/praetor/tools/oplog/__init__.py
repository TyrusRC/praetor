"""Operation ledger: what the tool layer actually did, recorded by the tool layer.

Claude narrates its own actions, and narration is not evidence. This module
records every call that reaches Burp at the point it happens — in
`client.get/post/delete` — so a claim ("I sent that payload", "see entry 118")
can be checked against a record the model never wrote.

Two tools:
  get_operation_log     — filter and read the ledger
  verify_operation_log  — reconcile it against Burp's own history

Disable with PRAETOR_OPLOG=off.
"""

from __future__ import annotations

import functools
import inspect
from contextvars import ContextVar

from mcp.server.fastmcp import FastMCP

from . import _verify
from ._store import oplog_path, read_entries

# Name of the MCP tool currently executing. Set by instrument_tools(), read by
# client._log_operation so each ledger line says which tool caused it.
current_tool: ContextVar[str] = ContextVar("praetor_current_tool", default="")


def instrument_tools(mcp: FastMCP) -> int:
    """Tag every registered tool so its Burp calls carry the tool's name.

    Applied once after registration rather than as a per-tool decorator: a
    decorator each author has to remember is a decorator that gets forgotten on
    the tool where the attribution mattered.
    """
    count = 0
    for tool in mcp._tool_manager.list_tools():
        fn = getattr(tool, "fn", None)
        if fn is None or getattr(fn, "_praetor_oplog_wrapped", False):
            continue
        name = tool.name

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def wrapper(*a, __fn=fn, __name=name, **kw):
                token = current_tool.set(__name)
                try:
                    return await __fn(*a, **kw)
                finally:
                    current_tool.reset(token)
        else:
            @functools.wraps(fn)
            def wrapper(*a, __fn=fn, __name=name, **kw):
                token = current_tool.set(__name)
                try:
                    return __fn(*a, **kw)
                finally:
                    current_tool.reset(token)

        wrapper._praetor_oplog_wrapped = True
        tool.fn = wrapper
        count += 1
    return count


def register(mcp: FastMCP):

    @mcp.tool()
    async def get_operation_log(
        host: str = "",
        tool: str = "",
        api: str = "",
        status: int = 0,
        outcome: str = "",
        since_seq: int = 0,
        sent_only: bool = True,
        limit: int = 50,
    ) -> dict:
        """Read the operation ledger — what the tool layer actually sent, in order.

        The ledger is written server-side at the point each call reaches Burp,
        so it records operations that happened rather than operations that were
        described. Use it to answer "did that request actually go out?" and
        "which tool produced this traffic?".

        Metadata only: method, URL (credential query values redacted), status,
        byte count, elapsed. Bodies are never stored here.

        Args:
            host: Filter by target host substring.
            tool: Filter by MCP tool name substring (e.g. 'curl_request').
            api: Filter by Burp API path substring (e.g. '/api/http/curl').
            status: Filter by exact HTTP status of the target response.
            outcome: 'ok' or 'error'.
            since_seq: Only entries after this sequence number — cheap tailing.
            sent_only: Only operations that hit a target URL, skipping reads of
                Burp's own state. Default True.
            limit: Max entries returned, newest last (1-500).
        """
        limit = max(1, min(500, int(limit or 50)))
        entries = read_entries(
            host=host, tool=tool, api=api, status=status,
            outcome=outcome, since_seq=since_seq, sent_only=sent_only,
        )
        total = len(entries)
        page = entries[-limit:]

        if not page:
            return {
                "total": 0, "returned": 0, "entries": [], "ledger": str(oplog_path()),
                "human_summary": "No operations match. An empty ledger with traffic in "
                                 "Burp means the traffic did not come from a tool call.",
            }

        lines = [f"Operations {total - len(page) + 1}-{total} of {total}:"]
        for e in page:
            lines.append(
                f"  #{e.get('seq')} [{e.get('tool') or '?'}] "
                f"{e.get('method') or ''} {e.get('url') or e.get('api')} "
                f"-> {e.get('status', e.get('outcome'))} "
                f"({e.get('bytes', '?')}B, {e.get('elapsed_ms', '?')}ms)"
            )
        return {
            "total": total,
            "returned": len(page),
            "last_seq": page[-1].get("seq"),
            "entries": page,
            "ledger": str(oplog_path()),
            "human_summary": "\n".join(lines),
        }

    @mcp.tool()
    async def verify_operation_log(host: str = "", limit: int = 500) -> dict:
        """Reconcile the operation ledger against Burp's history. Run before reporting.

        Returns counts plus the three disagreements worth acting on:
          unmatched_operations — a logged send with no Burp entry to show for it;
          unmatched_history    — Burp traffic no tool call accounts for (browser,
                                 external tool, hand-run script);
          status_conflicts     — a match whose Burp status differs from the one
                                 recorded at send time, i.e. a citation that
                                 resolves to a different outcome than claimed.

        Args:
            host: Restrict to one target host.
            limit: Max Burp history entries to reconcile against.
        """
        result = await _verify.reconcile(host=host, limit=limit)
        if "error" in result:
            return result

        lines = [
            f"Operation ledger vs Burp history for {result['host']}:",
            f"  ledger operations : {result['ledger_operations']}",
            f"  burp entries      : {result['burp_entries']}",
            f"  matched           : {result['matched']}",
        ]
        if result["unmatched_operations"]:
            lines.append(
                f"  UNBACKED sends    : {len(result['unmatched_operations'])} "
                "— logged but absent from Burp; do not cite these as evidence"
            )
            for e in result["unmatched_operations"][:10]:
                lines.append(f"      #{e.get('seq')} [{e.get('tool')}] {e.get('url')}")
        if result["status_conflicts"]:
            lines.append(
                f"  STATUS CONFLICTS  : {len(result['status_conflicts'])} "
                "— the cited entry resolves to a different response than recorded"
            )
            for m in result["status_conflicts"][:10]:
                lines.append(
                    f"      #{m['seq']} {m['url']} ledger={m['ledger_status']} "
                    f"burp={m['burp_status']} (index {m['burp_index']})"
                )
        if result["unmatched_history"]:
            lines.append(
                f"  unattributed burp : {len(result['unmatched_history'])} "
                "— not tied to a direct-send call (browser, external tool, or a "
                "scan tool whose probes the ledger does not enumerate)"
            )
        if not (result["unmatched_operations"] or result["status_conflicts"]):
            lines.append("  Every logged send is backed by a Burp entry with a matching status.")

        result["human_summary"] = "\n".join(lines)
        return result
