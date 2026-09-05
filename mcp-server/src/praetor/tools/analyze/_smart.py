"""Analyze: smart_analyze one-call attack-surface analysis."""

from mcp.server.fastmcp import FastMCP

from praetor import client
from ._helpers import _score_security_headers


def register(mcp: FastMCP):

    @mcp.tool()
    async def smart_analyze(index: int, summary_only: bool = False) -> str | dict:  # cost: cheap (single index, batched analysis)
        """Full attack surface analysis in ONE call: tech stack, injection points, params, forms, endpoints, secrets.

        Args:
            index: Proxy history index
            summary_only: Return compact dict (tech_stack, top-5 injection points,
                param counts, form count) — ≤1000 tokens. Use for triage; pass
                False to get the full multi-section narrative.
        """
        data = await client.post("/api/analysis/smart", json={"index": index})
        if "error" in data:
            return {"error": data["error"]} if summary_only else f"Error: {data['error']}"

        if summary_only:
            tech = data.get("tech_stack", {})
            params = data.get("parameters", {})
            injection_block = data.get("injection_points", {})
            injection_list = (
                injection_block.get("injection_points", [])
                if isinstance(injection_block, dict) else []
            )
            forms = data.get("forms", {})
            endpoints = data.get("endpoints", {})
            secrets = data.get("secrets", {})
            return {
                "method": data.get("method"),
                "url": data.get("url"),
                "tech_stack": tech.get("technologies", []),
                "missing_security_headers": tech.get("security_headers_missing", []),
                "param_counts": {
                    "query":  len(params.get("query_parameters", []) or []),
                    "body":   len(params.get("body_parameters", []) or []),
                    "cookie": len(params.get("cookie_parameters", []) or []),
                },
                "top_injection_points": [
                    {
                        "name": ip.get("name"),
                        "location": ip.get("location") or ip.get("type"),
                        "vulns": ip.get("potential_vulnerabilities") or ip.get("types") or [],
                        "risk_score": ip.get("risk_score", 0),
                    }
                    for ip in sorted(injection_list, key=lambda x: -x.get("risk_score", 0))[:5]
                ],
                "form_count": len(forms.get("forms", []) or []),
                "api_endpoint_count": len(endpoints.get("api_endpoints", []) or []),
                "secret_count": len(secrets.get("secrets", []) or []),
                "top_secrets": [
                    {"type": s.get("type"), "severity": s.get("severity"), "match": (s.get("match") or "")[:80]}
                    for s in (secrets.get("secrets") or [])[:3]
                ],
            }

        lines = [f"Smart Analysis: [{data.get('method')}] {data.get('url')}\n"]

        # Tech stack
        tech = data.get("tech_stack", {})
        techs = tech.get("technologies", [])
        if techs:
            lines.append(f"Tech Stack: {', '.join(techs)}")
        # TechStackDetector emits `security_headers_missing` as a list. Prior
        # code read `security_headers` as a bool-dict and always produced [].
        missing = tech.get("security_headers_missing", [])
        if missing:
            lines.append(f"Missing Security Headers: {', '.join(missing)}")
        present = tech.get("security_headers_present", [])
        if present:
            lines.append(f"Security Headers Present: {len(present)}")

        # Parameters. ParameterExtractor emits `query_parameters`,
        # `body_parameters`, `cookie_parameters` (NOT `query`/`body`/`cookie`).
        params = data.get("parameters", {})
        for location, server_key in (("query", "query_parameters"),
                                     ("body", "body_parameters"),
                                     ("cookie", "cookie_parameters")):
            param_list = params.get(server_key, [])
            if param_list:
                names = [p.get("name", "?") for p in param_list] if isinstance(param_list, list) else []
                if names:
                    lines.append(f"Params ({location}): {', '.join(names)}")

        # Injection points. InjectionPointDetector emits a flat list under
        # `injection_points` (already sorted by risk_score desc). There's no
        # `.high_risk` sub-key — prior code always produced empty output.
        injection_block = data.get("injection_points", {})
        injection_list = injection_block.get("injection_points", []) if isinstance(injection_block, dict) else []
        # Keep only the risky ones so low-signal cookies don't dominate output
        high_risk = [ip for ip in injection_list if ip.get("risk_score", 0) >= 1]
        if high_risk:
            lines.append(f"\nInjection Points ({len(high_risk)}):")
            for ip in high_risk[:10]:
                name = ip.get("name", "?")
                location = ip.get("location", ip.get("type", ""))
                types = ", ".join(ip.get("potential_vulnerabilities", ip.get("types", [])))
                score = ip.get("risk_score", 0)
                loc_str = f" ({location})" if location else ""
                lines.append(f"  {name}{loc_str} [{types}] (risk: {score})")

        # Forms
        forms = data.get("forms", {})
        form_list = forms.get("forms", [])
        if form_list:
            lines.append(f"\nForms ({len(form_list)}):")
            for f in form_list[:5]:
                action = f.get("action", "?")
                method = f.get("method", "GET")
                inputs = [i.get("name", "?") for i in f.get("inputs", [])]
                lines.append(f"  [{method}] {action} — inputs: {', '.join(inputs)}")

        # Endpoints
        endpoints = data.get("endpoints", {})
        api_paths = endpoints.get("api_endpoints", [])
        if api_paths:
            lines.append(f"\nAPI Endpoints ({len(api_paths)}):")
            for ep in api_paths[:10]:
                lines.append(f"  {ep}")

        # Secrets
        secrets = data.get("secrets", {})
        secret_list = secrets.get("secrets", [])
        if secret_list:
            lines.append(f"\nSecrets Found ({len(secret_list)}):")
            for s in secret_list[:5]:
                lines.append(f"  [{s.get('severity', '?')}] {s.get('type', '?')}: {s.get('match', '?')[:80]}")

        if len(lines) == 1:
            lines.append("No significant findings.")

        return "\n".join(lines)
