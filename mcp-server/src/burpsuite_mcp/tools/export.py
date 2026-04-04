"""Tools for exporting sitemap as compact JSON or OpenAPI spec."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def export_sitemap(
        url_prefix: str = "",
        format: str = "json",
    ) -> str:
        """Export all discovered endpoints as a structured API map.
        Builds from proxy history — groups endpoints, deduplicates, infers parameter types.

        Formats:
        - json: Compact JSON optimized for LLM consumption (default)
          Shows each endpoint with methods, parameters (name, location, type, example), responses
        - openapi: OpenAPI 3.0 YAML spec for external tools (Swagger, Postman, etc.)

        Use the JSON format to quickly understand the full attack surface.
        Use OpenAPI format to import into other security tools.

        Args:
            url_prefix: Filter by URL prefix (e.g. 'https://target.com')
            format: Output format - 'json' or 'openapi'
        """
        params = {"format": format, "prefix": url_prefix}

        data = await client.get("/api/export/sitemap", params=params)
        if "error" in data:
            return f"Error: {data['error']}"

        if format == "openapi":
            return data.get("content", "No endpoints found.")

        # Format compact JSON for LLM
        endpoints = data.get("endpoints", [])
        if not endpoints:
            return "No endpoints found. Browse the target through Burp's proxy first."

        lines = [f"API Map for {data.get('base_url', 'target')} ({data.get('total_endpoints', 0)} endpoints):\n"]

        for ep in endpoints:
            methods = ", ".join(ep.get("methods", []))
            auth = " [AUTH]" if ep.get("auth_required") else ""
            lines.append(f"  [{methods}] {ep['path']}{auth}")

            params_list = ep.get("parameters", [])
            if params_list:
                for p in params_list:
                    ptype = p.get("type", "string")
                    location = p.get("in", "?")
                    example = p.get("example", "")
                    example_str = f' = "{example}"' if example else ""
                    lines.append(f"    {p['name']} ({location}, {ptype}){example_str}")

            responses = ep.get("responses", [])
            if responses:
                resp_str = ", ".join(f"{r['status']}" for r in responses)
                lines.append(f"    -> {resp_str}")
            lines.append("")

        return "\n".join(lines)
