"""discover_attack_surface + discover_hidden_parameters."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

from ._constants import _COMMON_PARAMS, _EXTENDED_PARAMS
from ._helpers import _classify_param_risk, _compact_targets


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def discover_attack_surface(  # cost: medium
        session: str,
        max_pages: int = 20,
    ) -> str:
        """Crawl target and map the entire attack surface in ONE call.

        Args:
            session: Session name with base_url configured
            max_pages: Max pages to crawl
        """
        data = await client.post("/api/session/discover", json={
            "session": session, "max_pages": max_pages,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Attack Surface: {data.get('pages_crawled', 0)} pages crawled\n"]

        tech = data.get("detected_tech", [])
        if tech:
            lines.append(f"Tech Stack: {', '.join(tech)}")

        lines.append(f"Parameters: {data.get('total_parameters', 0)} total, {data.get('high_risk_parameters', 0)} high-risk\n")

        endpoints_sorted = sorted(data.get("endpoints", []), key=lambda e: e.get("risk_score", 0), reverse=True)
        for ep in endpoints_sorted:
            params = ep.get("parameters", [])
            param_str = ""
            if params:
                names = [f"{p['name']}({'!' if p.get('risk') == 'high' else ''})" for p in params]
                param_str = f" [{', '.join(names)}]"
            risk = ep.get("risk_score", 0)
            priority = ep.get("priority", "low")
            marker = "***" if priority == "critical" else "**" if priority == "high" else "*" if priority == "medium" else ""
            lines.append(f"  [{risk:>2}] {ep.get('method', '?'):6s} {ep.get('path', '?'):<40s} {ep.get('status', '?')} {marker}{param_str}")

        forms = data.get("forms", [])
        if forms:
            lines.append(f"\nForms ({len(forms)}):")
            for form in forms:
                inputs = ", ".join(form.get("inputs", []))
                lines.append(f"  [{form.get('method', '?')}] {form.get('action', '?')} -> {inputs}")

        targets = data.get("targets", [])
        if targets:
            lines.append(f"\nReady-to-probe targets ({len(targets)}):")
            for t in targets:
                lines.append(f"  {t.get('method', '?'):6s} {t.get('path', '?')} -> {t.get('parameter', '?')} ({t.get('location', '?')})")
            lines.append(f"\nTo probe all: auto_probe(session=\"{session}\", targets={_compact_targets(targets)})")

        priorities = []
        for ep in endpoints_sorted:
            ep_risks = set()
            for p in ep.get("parameters", []):
                risks = _classify_param_risk(p.get("name", ""))
                ep_risks.update(risks)
            if ep_risks:
                priorities.append((ep, sorted(ep_risks)))

        if priorities:
            lines.append("\nATTACK PRIORITIES:")
            for i, (ep, risks) in enumerate(priorities[:10], 1):
                risk_str = ", ".join(risks)
                path = ep.get("path", "?")
                method = ep.get("method", "?")
                lines.append(f"  {i}. {method} {path} -> {risk_str}")

        return "\n".join(lines)

    @mcp.tool()
    async def discover_hidden_parameters(  # cost: medium
        session: str,
        method: str = "GET",
        path: str = "/",
        wordlist: str = "common",
        param_type: str = "query",
        baseline_value: str = "1",
    ) -> str:
        """Discover hidden parameters by brute-forcing names and detecting anomalies.

        Args:
            session: Session name
            method: HTTP method
            path: Endpoint path to test
            wordlist: 'common' (~60) or 'extended' (~150)
            param_type: Where to add: 'query', 'body', or 'json'
            baseline_value: Value for test parameters
        """
        candidates = _EXTENDED_PARAMS if wordlist == "extended" else _COMMON_PARAMS

        baseline_req: dict = {"session": session, "method": method, "path": path}
        if param_type == "body":
            baseline_req["body"] = ""
            baseline_req["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
        elif param_type == "json":
            baseline_req["json_body"] = {}
            baseline_req["headers"] = {"Content-Type": "application/json"}

        baseline_resp = await client.post("/api/session/request", json=baseline_req)
        if "error" in baseline_resp:
            return f"Error getting baseline: {baseline_resp['error']}"

        baseline_status = baseline_resp.get("status", 0)
        baseline_length = baseline_resp.get("response_length", 0)
        baseline_body = baseline_resp.get("response_body", "")[:4000]

        discovered = []
        tested = 0

        for param in candidates:
            tested += 1
            req: dict = {"session": session, "method": method}
            if param_type == "query":
                sep = "&" if "?" in path else "?"
                req["path"] = f"{path}{sep}{param}={baseline_value}"
            elif param_type == "body":
                req["path"] = path
                req["data"] = f"{param}={baseline_value}"
                req["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
            elif param_type == "json":
                req["path"] = path
                req["json_body"] = {param: baseline_value}
                req["headers"] = {"Content-Type": "application/json"}

            resp = await client.post("/api/session/request", json=req)
            if "error" in resp:
                continue

            status = resp.get("status", 0)
            length = resp.get("response_length", 0)
            body = resp.get("response_body", "")[:4000]

            reasons = []
            if status != baseline_status:
                reasons.append(f"status {baseline_status}->{status}")
            if baseline_length > 0:
                diff_pct = abs(length - baseline_length) / baseline_length * 100
                if diff_pct > 10:
                    sign = "+" if length > baseline_length else "-"
                    reasons.append(f"{sign}{diff_pct:.0f}% length")
            if param in body and param not in baseline_body:
                reasons.append("reflected")

            if reasons:
                discovered.append({"name": param, "status": status, "length": length, "reasons": reasons})

        lines = ["HIDDEN PARAMETER DISCOVERY"]
        lines.append(f"Target: {method} {path}")
        lines.append(f"Baseline: {baseline_status} ({baseline_length} bytes)")
        lines.append(f"Tested: {tested} parameters ({wordlist})\n")

        if discovered:
            lines.append(f"DISCOVERED ({len(discovered)}):")
            for d in discovered:
                reasons_str = ", ".join(d["reasons"])
                lines.append(f"  {d['name']:<20} -> {d['status']}, {d['length']}B ({reasons_str})")
        else:
            lines.append("No hidden parameters found.")

        lines.append(f"\nNO CHANGE: {tested - len(discovered)} parameters matched baseline")
        return "\n".join(lines)
