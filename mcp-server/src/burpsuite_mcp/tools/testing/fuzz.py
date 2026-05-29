"""fuzz_parameter — drive Burp's fuzz engine with payload lists or smart heuristics."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

from ._format import format_fuzz_results
from ._smart import get_smart_payloads
from ._verdict import error_verdict, make_verdict, verdict_from_tally


def register(mcp: FastMCP):

    @mcp.tool()
    async def fuzz_parameter(  # cost: medium (scales with payload list)
        index: int,
        parameters: list[dict] | None = None,
        parameter: str = "",
        payloads: list[str] | None = None,
        injection_point: str = "query",
        attack_type: str = "sniper",
        grep_match: list[str] | None = None,
        grep_extract: str = "",
        delay_ms: int = 0,
        smart_payloads: bool = False,
    ) -> dict:
        """Fuzz parameters with payloads and detect response anomalies.

        Returns VerdictResult (W7 schema).

        Args:
            index: Proxy history index of the base request
            parameters: Parameter configs with payloads per param
            parameter: Single parameter name (simple mode)
            payloads: Payload list for single parameter (simple mode)
            injection_point: Where to inject: query, body, header, path, cookie
            attack_type: sniper, battering_ram, pitchfork, or cluster_bomb
            grep_match: Strings to search for in responses
            grep_extract: Regex to extract from responses
            delay_ms: Delay between requests in ms
            smart_payloads: Auto-select payloads based on parameter name
        """
        if smart_payloads:
            if parameters:
                for p in parameters:
                    if not p.get("payloads"):
                        p["payloads"] = get_smart_payloads(p.get("name", ""))
            elif parameter:
                payloads = get_smart_payloads(parameter)

        payload: dict = {"index": index, "attack_type": attack_type}

        if parameters:
            payload["parameters"] = parameters
        elif parameter and payloads:
            payload["parameters"] = [{"name": parameter, "position": injection_point, "payloads": payloads}]
        else:
            return error_verdict(
                "provide 'parameters' list or 'parameter' + 'payloads'",
                vuln_type="fuzz",
            )

        if grep_match:
            payload["grep_match"] = grep_match
        if grep_extract:
            payload["grep_extract"] = grep_extract
        if delay_ms > 0:
            payload["delay_ms"] = delay_ms

        data = await client.post("/api/fuzz", json=payload)
        if "error" in data:
            return error_verdict(str(data["error"]), vuln_type="fuzz")

        human = format_fuzz_results(data)
        # Count anomalies — fuzz reports them in anomaly_summary or per-row flags.
        summary = data.get("anomaly_summary", {}) or {}
        anomaly_count = sum(int(v or 0) for v in summary.values())
        verdict, confidence = verdict_from_tally(anomaly_count)
        ev = (f"fuzz: {anomaly_count} anomalies across {data.get('total_requests', 0)} requests"
              if anomaly_count else "no anomalies across fuzz payloads")

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="fuzz",
            details={
                "total_requests": data.get("total_requests"),
                "anomaly_summary": summary,
                "baseline_status": data.get("baseline_status"),
                "baseline_length": data.get("baseline_length"),
            },
            summary=human,
        )
