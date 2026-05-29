"""test_auth_matrix — N endpoints x M auth states grid for IDOR/BAC."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

from ._format import fmt_size
from ._verdict import error_verdict, make_verdict


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_auth_matrix(  # cost: medium (N endpoints × M auth states × A actions)
        endpoints: list[dict],
        auth_states: dict,
        base_url: str = "",
        actions: list[str] | None = None,
    ) -> dict:
        """Test endpoints across multiple auth states to detect IDOR / BFLA / BAC.

        Returns a structured VerdictResult (W7 schema): {verdict, confidence,
        evidence_summary, logger_indices, vuln_type, details, human_summary}.

        Args:
            endpoints: Endpoints to test. Each may include a 'method' field — when present, that
                method is appended to the actions axis for that endpoint.
            auth_states: Auth configs keyed by role name (subject axis).
            base_url: Override base URL.
            actions: Optional method axis (e.g. ['GET','POST','PATCH','DELETE']). Subject × Object ×
                Action matrix runs each endpoint with each verb across each subject. Defaults
                to the endpoints' own methods.

        Subject × Object × Action coverage: same authorization concern fans out
        across verbs — read may be denied while write succeeds, or vice versa.
        """
        if len(auth_states) < 2:
            return error_verdict(
                "need at least 2 auth_states for matrix comparison",
                vuln_type="idor",
            )

        if actions:
            # Expand endpoints across action axis
            expanded: list[dict] = []
            for ep in endpoints:
                for verb in actions:
                    ep_copy = dict(ep)
                    ep_copy["method"] = verb
                    expanded.append(ep_copy)
            endpoints = expanded

        payload: dict = {"endpoints": endpoints, "auth_states": auth_states}
        if base_url:
            payload["base_url"] = base_url

        data = await client.post("/api/attack/auth-matrix", json=payload)
        if "error" in data:
            return error_verdict(str(data["error"]), vuln_type="idor")

        lines = [f"Auth Matrix: {data['endpoints_tested']} endpoints x {data['auth_states_tested']} states = {data['total_requests']} requests"]
        if actions:
            lines.append(f"Action axis: {actions}")
        lines.append("")

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

        human = "\n".join(lines)

        # Collect logger indices + auth_state breach signal.
        logger_indices: list[int] = []
        high_similarity_cross_state = False
        for row in data.get("matrix", []):
            for cell in row.get("results", []) or []:
                idx = cell.get("logger_index")
                if isinstance(idx, int) and idx >= 0:
                    logger_indices.append(idx)
                sim = cell.get("similarity_to_baseline")
                if sim is not None and not cell.get("baseline") and sim >= 0.85:
                    high_similarity_cross_state = True

        if issues >= 1:
            verdict, confidence = "CONFIRMED", min(0.85, 0.65 + 0.05 * issues)
            ev = f"auth matrix: {issues} potential IDOR/BFLA cell(s) — different principals get same data"
        elif high_similarity_cross_state:
            verdict, confidence = "SUSPECTED", 0.55
            ev = "cross-state similarity >=85% — auth state may not gate response"
        else:
            verdict, confidence = "FAILED", 0.10
            ev = "auth matrix differentiates principals correctly"

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="idor",
            logger_indices=logger_indices[:10],
            details={
                "endpoints_tested": data.get("endpoints_tested"),
                "auth_states_tested": data.get("auth_states_tested"),
                "total_requests": data.get("total_requests"),
                "potential_issues": issues,
                "high_similarity_cross_state": high_similarity_cross_state,
            },
            summary=human,
        )
