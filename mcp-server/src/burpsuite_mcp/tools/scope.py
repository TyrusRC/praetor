"""Smart scope management with include/exclude patterns and auto-filtering."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def configure_scope(
        include: list[str],
        exclude: list[str] | None = None,
        auto_filter: bool = True,
        replace: bool = False,
    ) -> str:
        """Configure target scope with include/exclude patterns and auto noise filtering. Entries must be full URLs with protocol.

        Args:
            include: Full URLs to include in scope
            exclude: Full URL patterns to exclude
            auto_filter: Auto-exclude tracker/ad/CDN noise domains
            replace: Clear existing scope before applying
        """
        payload = {
            "include": include,
            "exclude": exclude or [],
            "auto_filter": auto_filter,
            "replace": replace,
        }
        data = await client.post("/api/scope/configure", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        lines = ["Scope configured:"]
        lines.append(f"  Included: {data.get('included', 0)} rules")
        lines.append(f"  Excluded: {data.get('excluded', 0)} rules")
        if data.get("auto_filter_enabled"):
            lines.append(f"  Auto-filtered: {data.get('auto_filtered', 0)} noise domains")

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
