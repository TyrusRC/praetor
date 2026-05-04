"""test_auth_matrix — N endpoints x M auth states grid for IDOR/BAC."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

from ._format import fmt_size


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_auth_matrix(  # cost: medium (N endpoints × M auth states)
        endpoints: list[dict],
        auth_states: dict,
        base_url: str = "",
    ) -> str:
        """Test endpoints across multiple auth states to detect IDOR and broken access control.

        Args:
            endpoints: Endpoints to test
            auth_states: Auth configs keyed by role name
            base_url: Override base URL
        """
        if len(auth_states) < 2:
            return "Error: need at least 2 auth_states for matrix comparison"

        payload: dict = {"endpoints": endpoints, "auth_states": auth_states}
        if base_url:
            payload["base_url"] = base_url

        data = await client.post("/api/attack/auth-matrix", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Auth Matrix: {data['endpoints_tested']} endpoints x {data['auth_states_tested']} states = {data['total_requests']} requests\n"]

        # Build matrix table from results array
        for row in data.get("matrix", []):
            ep = f"{row['method']} {row['path']}"
            lines.append(f"  {ep}")
            results = row.get("results", [])
            if isinstance(results, list):
                for cell in results:
                    state = cell.get("auth_state", "?")
                    status = cell.get("status", "?")
                    length = cell.get("response_length", cell.get("length", 0))
                    idor = " *** IDOR ***" if cell.get("potential_idor") else ""
                    baseline = " (baseline)" if cell.get("baseline") else ""
                    sim = cell.get("similarity_to_baseline")
                    sim_str = f" [{int(sim*100)}% similar]" if sim is not None and not cell.get("baseline") else ""
                    lines.append(f"    {state}: {status} ({fmt_size(length)}){sim_str}{baseline}{idor}")
            lines.append("")

        issues = data.get("potential_issues", 0)
        if issues:
            lines.append(f"Potential IDOR issues: {issues}")

        return "\n".join(lines)
