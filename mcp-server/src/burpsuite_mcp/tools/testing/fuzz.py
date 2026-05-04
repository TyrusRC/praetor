"""fuzz_parameter — drive Burp's fuzz engine with payload lists or smart heuristics."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

from ._format import format_fuzz_results
from ._smart import get_smart_payloads


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
    ) -> str:
        """Fuzz parameters with payloads and detect response anomalies.

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
            return "Error: Provide 'parameters' list or 'parameter' + 'payloads'"

        if grep_match:
            payload["grep_match"] = grep_match
        if grep_extract:
            payload["grep_extract"] = grep_extract
        if delay_ms > 0:
            payload["delay_ms"] = delay_ms

        data = await client.post("/api/fuzz", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        return format_fuzz_results(data)
