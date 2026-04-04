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
        """Configure target scope with include/exclude patterns and smart noise filtering.
        One-call scope setup for bug bounty targets.

        When auto_filter is True (default), automatically excludes ~60 known noise domains:
        trackers (Google Analytics, Mixpanel, Hotjar), ad networks (DoubleClick, Criteo),
        CDNs (Cloudflare, Fastly, Akamai), fonts, social widgets, tag managers, error tracking.

        Args:
            include: URL patterns to include - domains ('*.target.com'), URLs ('https://api.target.com/v2/*')
            exclude: URL patterns to exclude - e.g. ['*/logout', '*/static/*']
            auto_filter: Auto-exclude tracker/ad/CDN noise domains (default True)
            replace: Clear existing scope before applying new rules (default False)
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
