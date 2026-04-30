"""parse_api_schema — OpenAPI/Swagger spec parsing with vuln test suggestions."""

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


_INTERESTING_KEYWORDS = {
    "auth": ["login", "signin", "signup", "register", "auth", "oauth", "token", "password", "reset", "verify"],
    "file": ["upload", "download", "file", "attachment", "import", "export", "image", "media"],
    "admin": ["admin", "manage", "dashboard", "config", "setting", "internal"],
    "user_crud": ["user", "account", "profile", "member"],
    "payment": ["payment", "billing", "subscription", "checkout", "order", "invoice", "charge", "refund"],
}

_PARAM_VULN_MAP = {
    "id": "IDOR", "user_id": "IDOR", "account_id": "IDOR", "uid": "IDOR", "pid": "IDOR",
    "search": "XSS", "q": "XSS", "query": "XSS", "name": "XSS", "comment": "XSS",
    "file": "LFI", "filename": "LFI", "path": "LFI", "filepath": "LFI", "template": "SSTI",
    "url": "SSRF", "uri": "SSRF", "href": "SSRF", "callback": "SSRF", "redirect": "Open Redirect",
    "redirect_url": "Open Redirect", "next": "Open Redirect", "return_url": "Open Redirect",
    "cmd": "Command Injection", "command": "Command Injection", "exec": "Command Injection",
    "email": "Injection", "sort": "SQLi", "order": "SQLi", "filter": "SQLi/NoSQLi",
}


def register(mcp: FastMCP):

    @mcp.tool()
    async def parse_api_schema(url: str = "", schema_text: str = "") -> str:
        """Parse an OpenAPI/Swagger spec and extract testable endpoints with vuln suggestions.

        Args:
            url: URL to fetch the spec from
            schema_text: Raw schema JSON (alternative to url)
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

        version = "unknown"
        if "openapi" in spec:
            version = f"OpenAPI {spec['openapi']}"
        elif "swagger" in spec:
            version = f"Swagger {spec['swagger']}"

        base_url = ""
        if "servers" in spec and spec["servers"]:
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
