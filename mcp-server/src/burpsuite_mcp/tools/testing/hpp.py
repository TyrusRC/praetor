"""test_parameter_pollution — HPP across query, body, and mixed positions."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

from ._format import fmt_size
from ._verdict import error_verdict, make_verdict, verdict_from_tally


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_parameter_pollution(
        session: str,
        base_path: str,
        parameter: str,
        original_value: str,
        polluted_values: list[str],
        locations: list[str] | None = None,
    ) -> dict:
        """Test HTTP Parameter Pollution across query, body, and mixed positions.

        Returns VerdictResult (W7 schema).

        Args:
            session: Session name
            base_path: Target endpoint path
            parameter: Parameter name to pollute
            original_value: Original parameter value
            polluted_values: Pollution variants to test
            locations: Where to inject: 'query', 'body', 'both'
        """
        payload: dict = {
            "session": session,
            "base_path": base_path,
            "parameter": parameter,
            "original_value": original_value,
            "polluted_values": polluted_values,
            "locations": locations or ["query", "body", "both"],
        }
        data = await client.post("/api/attack/hpp", json=payload)
        if "error" in data:
            return error_verdict(str(data["error"]), vuln_type="hpp")

        lines = [f"HPP Test: {data['variants_tested']} variants"]
        lines.append(f"Baseline: {data['baseline_status']} ({fmt_size(data['baseline_length'])})\n")

        baseline_len = data['baseline_length']
        for r in data.get("results", []):
            length = r.get('response_length', r.get('length', 0))
            length_diff = abs(length - baseline_len)
            status_diff = r['status'] != data['baseline_status']
            anomaly = " *** ANOMALY ***" if status_diff or length_diff > baseline_len * 0.2 else ""
            payload = r.get('polluted_value', r.get('payload', '?'))
            lines.append(f"  [{r['location']}] {payload}")
            lines.append(f"    Status: {r['status']} | Length: {fmt_size(length)} | Length diff: {length_diff}{anomaly}")

        anomalies = data.get("anomalies_found", 0)
        if anomalies:
            lines.append(f"\n{anomalies} anomalies found — backend may parse polluted parameters differently")

        human = "\n".join(lines)
        verdict, confidence = verdict_from_tally(int(anomalies))
        ev = (f"HPP anomalies across {anomalies} polluted variant(s) — backend parses differently"
              if anomalies else "no HPP anomalies — backend parsing consistent across locations")

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="hpp",
            details={
                "base_path": base_path,
                "parameter": parameter,
                "variants_tested": data.get("variants_tested"),
                "anomalies_found": anomalies,
            },
            summary=human,
        )
