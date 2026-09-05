"""parse_api_schema — OpenAPI / Swagger / Postman v2.1 spec parsing with vuln test suggestions.

Accepts:
  - OpenAPI 3.x JSON
  - Swagger 2.0 JSON
  - Postman v2.1 Collection JSON (with optional environment JSON for {{var}} substitution)

Postman uses {{var}} templating across URL, headers, body — pass `postman_env`
(also JSON) to substitute values before extracting endpoints.
"""

import json
import re

from mcp.server.fastmcp import FastMCP

from praetor import client

from ._api_schema_helpers import (
    _postman_substitute,
    _postman_env_to_dict,
    _is_postman,
    _postman_walk_items,
    _INTERESTING_KEYWORDS,
    _POSTMAN_VAR_RE,
    _PARAM_VULN_MAP,
)

def register(mcp: FastMCP):

    @mcp.tool()
    async def parse_api_schema(
        url: str = "",
        schema_text: str = "",
        postman_env: str = "",
    ) -> str:
        """Parse OpenAPI / Swagger / Postman v2.1 spec and extract testable endpoints with vuln suggestions.

        Args:
            url: URL to fetch the spec from.
            schema_text: Raw schema JSON (alternative to url).
            postman_env: Optional Postman environment JSON (raw text). Substitutes {{var}} tokens
                in Postman collections before extraction. Pass either Postman export format
                (`{values:[{key,value,enabled},...]}`) or a flat `{key:value}` dict.
        """
        if not url and not schema_text:
            return "Error: Provide either 'url' to fetch spec or 'schema_text' with raw spec content"

        if url:
            resp = await client.post("/api/http/curl", json={"url": url, "method": "GET"})
            if "error" in resp:
                return f"Error fetching spec: {resp['error']}"
            schema_text = resp.get("response_body", resp.get("body", ""))
            if not schema_text:
                return "Error: Empty response from spec URL"

        try:
            spec = json.loads(schema_text)
        except json.JSONDecodeError:
            return "Error: Could not parse schema as JSON. Only JSON specs are supported."

        # ── Postman collection branch ──
        if _is_postman(spec):
            env: dict[str, str] = {}
            if postman_env:
                try:
                    env = _postman_env_to_dict(json.loads(postman_env))
                except json.JSONDecodeError:
                    return "Error: postman_env was provided but is not valid JSON"

            endpoints = _postman_walk_items(spec.get("item", []), env)
            lines = [
                "API Schema: Postman v2.1 Collection",
                f"Environment vars resolved: {len(env)}",
                f"Endpoints: {len(endpoints)}",
                "",
            ]
            interesting_endpoints = []
            for ep in endpoints:
                path = ep["url"]
                path_lower = path.lower()
                tags = []
                for tag, keywords in _INTERESTING_KEYWORDS.items():
                    if any(kw in path_lower for kw in keywords):
                        tags.append(tag)
                suggestions = []
                for p in ep["params"]:
                    pname = p["name"].lower()
                    for key, vuln in _PARAM_VULN_MAP.items():
                        if key == pname or (len(key) > 3 and key in pname):
                            suggestions.append(f"{p['name']} -> {vuln}")
                            break
                line = f"  {ep['method']} {ep['url']}"
                if ep["name"]:
                    line += f"  # {ep['name']}"
                lines.append(line)
                if tags:
                    interesting_endpoints.append(f"{ep['method']} {ep['url']} [{', '.join(tags)}]")
                    lines.append(f"    [!] Tags: {', '.join(tags)}")
                if ep["params"]:
                    param_strs = [f"{p['name']}({p['in']}/{p['type']})" for p in ep["params"]]
                    lines.append(f"    Params: {', '.join(param_strs)}")
                if ep["body_mode"]:
                    lines.append(f"    Body mode: {ep['body_mode']}")
                if suggestions:
                    lines.append(f"    Vuln tests: {', '.join(suggestions)}")
                # Flag unresolved {{vars}} as TODO
                unresolved = _POSTMAN_VAR_RE.findall(ep["url"]) + _POSTMAN_VAR_RE.findall(ep["body"])
                if unresolved:
                    lines.append(f"    [WARN] unresolved postman vars: {list(set(unresolved))}")
            if interesting_endpoints:
                lines.append(f"\n--- High-Interest Endpoints ({len(interesting_endpoints)}) ---")
                for ep in interesting_endpoints:
                    lines.append(f"  {ep}")
            if not env:
                lines.append("\nNote: no postman_env supplied. {{vars}} left literal. Provide environment JSON to resolve.")
            return "\n".join(lines)

        # ── OpenAPI / Swagger branch (existing) ──
        version = "unknown"
        if "openapi" in spec:
            version = f"OpenAPI {spec['openapi']}"
        elif "swagger" in spec:
            version = f"Swagger {spec['swagger']}"

        base_url = ""
        if spec.get("servers"):
            base_url = spec["servers"][0].get("url", "")
        elif "host" in spec:
            scheme = (spec.get("schemes") or ["https"])[0]
            base_path = spec.get("basePath", "")
            base_url = f"{scheme}://{spec['host']}{base_path}"

        paths = spec.get("paths", {})
        lines = [f"API Schema: {version}"]
        if base_url:
            lines.append(f"Base URL: {base_url}")
        lines.append(f"Endpoints: {len(paths)}\n")

        endpoint_count = 0
        interesting_endpoints = []

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                if method.startswith("x-") or method == "parameters":
                    continue
                if not isinstance(details, dict):
                    continue

                endpoint_count += 1
                summary = details.get("summary", details.get("operationId", ""))

                params = []
                all_params = details.get("parameters", []) + methods.get("parameters", [])
                for p in all_params:
                    if not isinstance(p, dict):
                        continue
                    params.append({
                        "name": p.get("name", "?"),
                        "in": p.get("in", "?"),
                        "required": p.get("required", False),
                        "type": p.get("schema", {}).get("type", p.get("type", "?")),
                    })

                req_body = details.get("requestBody", {})
                if isinstance(req_body, dict):
                    content = req_body.get("content", {})
                    for ctype, schema_info in content.items():
                        if not isinstance(schema_info, dict):
                            continue
                        props = schema_info.get("schema", {}).get("properties", {})
                        required = schema_info.get("schema", {}).get("required", [])
                        for pname, pinfo in props.items():
                            params.append({
                                "name": pname,
                                "in": "body",
                                "required": pname in required,
                                "type": pinfo.get("type", "?") if isinstance(pinfo, dict) else "?",
                            })

                path_lower = path.lower()
                tags = []
                for tag, keywords in _INTERESTING_KEYWORDS.items():
                    if any(kw in path_lower for kw in keywords):
                        tags.append(tag)

                suggestions = []
                for p in params:
                    pname = p["name"].lower()
                    for key, vuln in _PARAM_VULN_MAP.items():
                        if key == pname or (len(key) > 3 and key in pname):
                            suggestions.append(f"{p['name']} -> {vuln}")
                            break

                method_upper = method.upper()
                line = f"  {method_upper} {path}"
                if summary:
                    line += f"  # {summary}"
                lines.append(line)

                if tags:
                    interesting_endpoints.append(f"{method_upper} {path} [{', '.join(tags)}]")
                    lines.append(f"    [!] Tags: {', '.join(tags)}")

                if params:
                    param_strs = []
                    for p in params:
                        req = "*" if p["required"] else ""
                        param_strs.append(f"{p['name']}{req}({p['in']}/{p['type']})")
                    lines.append(f"    Params: {', '.join(param_strs)}")

                if suggestions:
                    lines.append(f"    Vuln tests: {', '.join(suggestions)}")

        lines.insert(3, f"Total operations: {endpoint_count}")
        if interesting_endpoints:
            lines.append(f"\n--- High-Interest Endpoints ({len(interesting_endpoints)}) ---")
            for ep in interesting_endpoints:
                lines.append(f"  {ep}")

        return "\n".join(lines)
