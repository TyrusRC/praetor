"""Smart scope management with include/exclude patterns, auto-filtering, and engagement mode.

Modes:
- operator (default): warn-and-log. Out-of-scope requests append to .burp-intel/_audit.log
  and proceed. Trust model: operator owns authorization (private contract / SOW).
- strict: hard-block (current Rule 1). For public bounty programs whose scope is published.
"""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools import _scope_mode


def register(mcp: FastMCP):

    @mcp.tool()
    async def configure_scope(
        include: list[str],
        exclude: list[str] | None = None,
        auto_filter: bool = True,
        replace: bool = False,
        keep_in_scope: list[str] | None = None,
        mode: str = "operator",
    ) -> str:
        """Configure target scope. Entries must be full URLs with protocol.

        Args:
            include: Full URLs to include in scope
            exclude: Full URL patterns to exclude
            auto_filter: Auto-exclude tracker/ad/CDN noise domains
            replace: Clear existing scope before applying
            keep_in_scope: Substrings of auto-filter domains to KEEP in scope
            mode: 'operator' (default - warn-and-log, trust operator's authorization)
                  or 'strict' (hard-block - for public bounty programs)
        """
        try:
            _scope_mode.set_mode(mode)
        except ValueError as e:
            return f"Error: {e}"

        payload = {
            "include": include,
            "exclude": exclude or [],
            "auto_filter": auto_filter,
            "replace": replace,
            "keep_in_scope": keep_in_scope or [],
            "mode": mode,
        }
        data = await client.post("/api/scope/configure", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Scope configured (mode={mode}):"]
        lines.append(f"  Included: {data.get('included', 0)} rules")
        lines.append(f"  Excluded: {data.get('excluded', 0)} rules")
        if data.get("auto_filter_enabled"):
            lines.append(f"  Auto-filtered: {data.get('auto_filtered', 0)} noise domains")
        if data.get("kept_in_scope", 0):
            lines.append(f"  Kept in scope (override): {data.get('kept_in_scope', 0)} domains")
        if mode == "operator":
            lines.append("  Out-of-scope requests will be logged to .burp-intel/_audit.log and proceed.")
        else:
            lines.append("  Out-of-scope requests will be HARD-BLOCKED.")

        rules = data.get("include_rules", [])
        if rules:
            lines.append("\nInclude rules:")
            for r in rules:
                lines.append(f"  {r}")

        ex_rules = data.get("exclude_rules", [])
        if ex_rules:
            lines.append("\nExclude rules:")
            for r in ex_rules:
                lines.append(f"  {r}")

        return "\n".join(lines)
