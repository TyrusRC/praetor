"""Analyze: API endpoints, tech stack, JS secrets, unique endpoints."""

from mcp.server.fastmcp import FastMCP

from praetor import client
from ._helpers import _score_security_headers


def register(mcp: FastMCP):

    @mcp.tool()
    async def extract_api_endpoints(index: int) -> dict:
        """Extract API endpoints, JS fetch calls, and links from a response.

        Returns structured dict: {total_found, api_endpoints, js_endpoints, links,
        external_urls, human_summary} or {error}. Each list capped at 50.

        Args:
            index: Proxy history index
        """
        data = await client.post("/api/analysis/endpoints", json={"index": index})
        if "error" in data:
            return {"error": data["error"]}

        total = data.get("total_found", 0)
        lines = [f"Endpoint extraction (total: {total}):\n"]
        out: dict = {"total_found": total}

        for section, key in [
            ("API Endpoints", "api_endpoints"),
            ("JS Fetch/Ajax Calls", "js_endpoints"),
            ("Links", "links"),
            ("External URLs", "external_urls"),
        ]:
            items = data.get(key, [])
            out[key] = items[:50]
            if items:
                lines.append(f"--- {section} ({len(items)}) ---")
                for item in items[:50]:
                    lines.append(f"  {item}")
                if len(items) > 50:
                    lines.append(f"  ... and {len(items) - 50} more")
                lines.append("")

        out["human_summary"] = "\n".join(lines)
        return out

    @mcp.tool()
    async def detect_tech_stack(index: int) -> str:
        """Detect technology stack and audit security headers from a response.

        Args:
            index: Proxy history index
        """
        data = await client.post("/api/analysis/tech-stack", json={"index": index})
        if "error" in data:
            return f"Error: {data['error']}"

        lines = ["Technology Stack Detection:\n"]

        techs = data.get("technologies", [])
        if techs:
            lines.append("--- Technologies ---")
            for t in techs:
                lines.append(f"  - {t}")
            lines.append("")

        present = data.get("security_headers_present", [])
        if present:
            lines.append("--- Security Headers (Present) ---")
            for h in present:
                lines.append(f"  [OK] {h}")
            lines.append("")

        missing = data.get("security_headers_missing", [])
        if missing:
            lines.append("--- Security Headers (MISSING) ---")
            for h in missing:
                lines.append(f"  [!!] {h}")

        # Security header scoring
        result = "\n".join(lines)
        result += _score_security_headers(present, missing)

        return result

    @mcp.tool()
    async def extract_js_secrets(index: int) -> dict:
        """Extract secrets, API keys, tokens, and sensitive data from a response.

        Returns structured dict: {total_secrets, secrets: [...], human_summary} or {error}.

        Args:
            index: Proxy history index
        """
        data = await client.post("/api/analysis/js-secrets", json={"index": index})
        if "error" in data:
            return {"error": data["error"]}

        secrets = data.get("secrets", [])
        total = data.get("total_secrets", 0)

        if not secrets:
            return {
                "total_secrets": 0,
                "secrets": [],
                "human_summary": "No secrets or sensitive data found in this response.",
            }

        lines = [f"Secrets Found: {total}\n"]

        for s in secrets:
            severity = s.get("severity", "?")
            stype = s.get("type", "Unknown")
            match = s.get("match", "")
            context = s.get("context", "")

            lines.append(f"[{severity}] {stype}")
            lines.append(f"  Match: {match}")
            if context:
                lines.append(f"  Context: ...{context}...")
            lines.append("")

        return {
            "total_secrets": total,
            "secrets": secrets,
            "human_summary": "\n".join(lines),
        }

    @mcp.tool()
    async def get_unique_endpoints(url_prefix: str = "", limit: int = 30) -> str:
        """Get deduplicated endpoints from proxy history with parameter names.

        Args:
            url_prefix: Filter by URL prefix
            limit: Max endpoints to return
        """
        params = {"limit": limit}
        if url_prefix:
            params["prefix"] = url_prefix

        data = await client.get("/api/analysis/unique-endpoints", params=params)
        if "error" in data:
            return f"Error: {data['error']}"

        endpoints = data.get("endpoints", [])
        if not endpoints:
            return "No endpoints found. Browse the target first."

        lines = [f"Unique Endpoints ({data.get('total', 0)}):\n"]
        for ep in endpoints:
            status = ep.get("status_code", "")
            lines.append(f"[{status}] {ep['endpoint']}")
            params_list = ep.get("parameters", [])
            if params_list:
                lines.append(f"     Params: {', '.join(params_list)}")

        return "\n".join(lines)
