"""Read-side notes tools: get_findings, export_report."""

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def get_findings(endpoint: str = "") -> dict:
        """Get all saved pentest findings, optionally filtered by endpoint URL.

        Returns structured dict: {total, findings: [...], human_summary} or {error}.

        Args:
            endpoint: Filter by endpoint URL substring (empty = all)
        """
        params = {}
        if endpoint:
            params["endpoint"] = endpoint

        data = await client.get("/api/notes/findings", params=params)
        if "error" in data:
            return {"error": data["error"]}

        findings = data.get("findings", [])
        total = data.get("total", 0)
        if not findings:
            return {"total": 0, "findings": [], "human_summary": "No findings saved yet."}

        lines = [f"Saved Findings ({total}):\n"]
        for f in findings:
            lines.append(f"[{f.get('severity')}] #{f.get('id')} - {f.get('title')}")
            if f.get("endpoint"):
                lines.append(f"  Endpoint: {f['endpoint']}")
            if f.get("description"):
                lines.append(f"  {f['description'][:200]}")
            lines.append("")

        return {"total": total, "findings": findings, "human_summary": "\n".join(lines)}

    @mcp.tool()
    async def export_report(format: str = "markdown") -> str:
        """Export all findings as a pentest report.

        Args:
            format: 'markdown' or 'json'
        """
        data = await client.get("/api/notes/export", params={"format": format})
        if "error" in data:
            return f"Error: {data['error']}"

        if format == "json":
            return json.dumps(data, indent=2, default=str)
        return data.get("content", "No findings to export.")
