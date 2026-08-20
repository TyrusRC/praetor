"""MCP tools: forward Praetor evidence into Ghostwriter (central hub).

  ghostwriter_status  - is it configured, and what would forward
  sync_to_ghostwriter - push unsynced operator-log entries + findings
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import _ghostwriter


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def ghostwriter_status(domain: str = "") -> str:
        """Report Ghostwriter forwarding config + what is pending for a domain.

        Args:
            domain: optional engagement key — show unsynced counts for it.
        """
        if not _ghostwriter.is_configured():
            return (
                "Ghostwriter: NOT configured. Set GHOSTWRITER_URL, "
                "GHOSTWRITER_API_TOKEN (or GHOSTWRITER_ADMIN_SECRET), and "
                "GHOSTWRITER_OPLOG_ID. Local .burp-intel stores remain the "
                "source of truth; nothing is forwarded until configured."
            )
        from praetor import config
        lines = [
            f"Ghostwriter: configured -> {config.GHOSTWRITER_URL} "
            f"(oplog {config.GHOSTWRITER_OPLOG_ID})",
        ]
        if domain:
            from ._ghostwriter import _load_marker
            from ._oplog import read_oplog
            marker = _load_marker(domain)
            total_ops = len(read_oplog(domain))
            synced_ops = len(marker.get("oplog", []))
            lines.append(f"  {domain}: {total_ops} oplog entries, "
                         f"{synced_ops} synced, {total_ops - synced_ops} pending")
        return "\n".join(lines)

    @mcp.tool()
    async def sync_to_ghostwriter(domain: str, what: str = "all") -> str:
        """Forward evidence into Ghostwriter — the central engagement hub.

        Pushes both lanes onto Ghostwriter's oplog timeline: the network
        operator log AND web/Burp findings (findings ride the timeline tagged
        vuln:/severity:, with the Burp logger_index or operator-log id in
        comments for traceability). Idempotent — a per-domain marker skips
        already-synced entries.

        Args:
            domain: engagement key.
            what: 'all' (default), 'oplog' (operator log only), or 'findings'.
        """
        res = await _ghostwriter.sync(domain, what)
        if "error" in res:
            return f"Ghostwriter sync skipped: {res['error']}"
        pushed = res["pushed"]
        total = res["synced_total"]
        lines = [
            f"Ghostwriter sync ({domain}, what={what}):",
            f"  pushed: {pushed['oplog']} oplog entries, {pushed['findings']} findings",
            f"  total synced: {total['oplog']} oplog, {total['findings']} findings",
        ]
        if res.get("errors"):
            lines.append("  errors (stopped at first):")
            for e in res["errors"][:5]:
                lines.append(f"    {e}")
        return "\n".join(lines)
