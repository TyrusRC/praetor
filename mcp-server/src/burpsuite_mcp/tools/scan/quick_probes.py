"""quick_scan, probe_endpoint, batch_probe — single-shot probes."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def quick_scan(  # cost: cheap
        session: str, method: str, path: str,
        headers: dict | None = None, body: str = "", data: str = "",
        json_body: dict | None = None,
    ) -> str:
        """Send request and auto-analyze in ONE call without returning the response body.

        Args:
            session: Session name
            method: HTTP method
            path: Request path relative to session base_url
            headers: Additional headers
            body: Raw request body
            data: Form-encoded data
            json_body: JSON body dict
        """
        payload: dict = {"session": session, "method": method, "path": path, "analyze": True}
        if headers: payload["headers"] = headers
        if body: payload["body"] = body
        if data: payload["data"] = data
        if json_body is not None: payload["json_body"] = json_body

        resp = await client.post("/api/session/request", json=payload)
        if "error" in resp:
            return f"Error: {resp['error']}"

        lines = [f"Status: {resp.get('status')} | Length: {resp.get('response_length', 0)} bytes"]
        analysis = resp.get("analysis", {})
        if analysis:
            tech = analysis.get("tech_stack", {})
            techs = tech.get("technologies", [])
            if techs:
                lines.append(f"\nTech Stack: {', '.join(techs)}")
            missing = tech.get("security_headers_missing", [])
            if missing:
                lines.append(f"Missing Headers: {', '.join(missing)}")
            injection_block = analysis.get("injection_points", {})
            ij_list = injection_block.get("injection_points", []) if isinstance(injection_block, dict) else []
            high_risk = [ip for ip in ij_list if ip.get("risk_score", 0) >= 1]
            if high_risk:
                lines.append(f"\nInjection Points ({len(high_risk)}):")
                for ip in high_risk[:10]:
                    vulns = ip.get("potential_vulnerabilities", ip.get("types", []))
                    lines.append(f"  {ip.get('name', '?')} [{', '.join(vulns)}] risk={ip.get('risk_score', 0)}")
            params = analysis.get("parameters", {})
            collected_param_names: list[str] = []
            for loc, key in (("query", "query_parameters"),
                             ("body", "body_parameters"),
                             ("cookie", "cookie_parameters")):
                pl = params.get(key, [])
                if pl and isinstance(pl, list):
                    names = [p.get('name', '?') for p in pl]
                    collected_param_names.extend(names)
                    lines.append(f"Params ({loc}): {', '.join(names)}")

            tech_str = ",".join(techs[:3]) if techs else ""
            if collected_param_names:
                top_params = collected_param_names[:5]
                lines.append("\nSUGGESTED NEXT STEPS:")
                lines.append(
                    f"  1. auto_probe(session='{session}', targets=["
                    + ", ".join(
                        f"{{'method':'{method}','path':'{path}','parameter':'{p}','location':'query','baseline_value':'1'}}"
                        for p in top_params
                    )
                    + "], categories=['sqli','xss','ssrf'])"
                )
                lines.append(
                    f"  2. discover_attack_surface(session='{session}', max_pages=20)  "
                    f"# map full surface before deep probing"
                )
                if high_risk:
                    lines.append(
                        f"  3. test_auth_matrix(endpoints=[...], auth_states={{...}})  "
                        f"# {len(high_risk)} injection points need authz coverage"
                    )
            elif tech_str:
                lines.append("\nSUGGESTED NEXT STEPS:")
                lines.append(
                    f"  1. discover_attack_surface(session='{session}')  "
                    f"# tech={tech_str} but no params on this response"
                )
        return "\n".join(lines)

    @mcp.tool()
    async def probe_endpoint(
        session: str, method: str, path: str, parameter: str,
        baseline_value: str = "1", payload_value: str = "",
        injection_point: str = "query", test_payloads: list[str] | None = None,
    ) -> str:
        """Adaptive vulnerability probe with auto tech detection and payload selection.

        Args:
            session: Session name
            method: HTTP method
            path: Base endpoint path
            parameter: Parameter name to test
            baseline_value: Normal/safe value
            payload_value: Single attack payload (empty = auto-detect)
            injection_point: Where to inject: 'query' or 'body'
            test_payloads: Multiple payloads to test in one call
        """
        req: dict = {
            "session": session, "method": method, "path": path,
            "parameter": parameter, "baseline_value": baseline_value,
            "injection_point": injection_point,
        }
        if payload_value: req["payload_value"] = payload_value
        if test_payloads: req["test_payloads"] = test_payloads

        resp = await client.post("/api/session/probe", json=req)
        if "error" in resp:
            return f"Error: {resp['error']}"

        lines = [f"Probe: {parameter} on {path}"]
        tech = resp.get("detected_tech", [])
        if tech: lines.append(f"Tech: {', '.join(tech)}")
        lines.append(f"Baseline: {resp.get('baseline_status')} | {resp.get('baseline_length')}B | {resp.get('baseline_time_ms')}ms")
        lines.append(f"Payloads tested: {resp.get('payloads_tested', 0)}\n")

        for r in resp.get("results", []):
            score = r.get("score", 0)
            vuln = " ***" if score >= 30 else ""
            lines.append(f"  [{score:>3}] {r.get('payload', '?')}")
            lines.append(f"        {r.get('status', '?')} | {r.get('length', 0)}B | {r.get('time_ms', 0)}ms{vuln}")
            for f in r.get("findings", []):
                lines.append(f"        -> {f}")
            refl = r.get("reflection", {})
            if refl:
                ctx = refl.get("context", "")
                lines.append(f"        Reflected ({refl.get('type', '?')}{', ' + ctx if ctx else ''})")

        max_score = resp.get("max_vulnerability_score", 0)
        if resp.get("likely_vulnerable"):
            lines.append(f"\n*** LIKELY VULNERABLE (score: {max_score}/100) ***")
        else:
            lines.append(f"\nNo obvious vulnerability (score: {max_score}/100)")
        return "\n".join(lines)

    @mcp.tool()
    async def batch_probe(session: str, endpoints: list[dict]) -> str:  # cost: medium
        """Test multiple endpoints in ONE call with status, length, and timing.

        Args:
            session: Session name
            endpoints: List of endpoint specs with method and path
        """
        data = await client.post("/api/session/batch", json={"session": session, "endpoints": endpoints})
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Batch Probe: {data.get('total_endpoints')} endpoints in {data.get('total_time_ms')}ms\n"]
        dist = data.get("status_distribution", {})
        if dist:
            lines.append(f"Status: {', '.join(f'{s}x{c}' for s, c in dist.items())}\n")
        for r in data.get("results", []):
            title = f" [{r['title']}]" if r.get("title") else ""
            lines.append(f"  {r.get('method', '?'):6s} {r.get('path', '?'):<40s} {r['status']} | {r['length']:>6}B | {r['time_ms']:>4}ms{title}")
        return "\n".join(lines)
