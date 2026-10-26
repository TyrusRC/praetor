"""fuzz_api_schema — auto-exercise every OpenAPI endpoint with type-aware payloads.

parse_api_schema extracts endpoints but does not test them. This tool walks
every operation in an OpenAPI 3.x / Swagger 2.0 spec, generates valid + malicious
requests per parameter type, sends them through Burp, and flags anomalies.

Acunetix / Invicti do this automatically. This closes the gap.
"""

from __future__ import annotations

import json
import re

from mcp.server.fastmcp import FastMCP

from praetor import client

# Type-aware injection payloads keyed by OpenAPI parameter type/format.
_TYPE_PAYLOADS: dict[str, list[str]] = {
    "string": ["' OR 1=1--", "<script>alert(1)</script>", "{{7*7}}", "${7*7}",
               "../../../etc/passwd", "admin", "null", "", "A" * 5000],
    "integer": ["0", "-1", "999999999", "1 OR 1=1", "NaN", "1.5", "null"],
    "number": ["0", "-1.0", "99999999.99", "NaN", "Infinity", "null"],
    "boolean": ["true", "false", "null", "1", "0", "yes"],
    "array": ["[]", '[{"$gt":""}]', '["__proto__"]', "[null]"],
    "object": ['{"$gt":""}', '{"__proto__":{"x":1}}', '{"constructor":{"prototype":{"x":1}}}'],
    "email": ["test@test.com", "' OR 1=1--@test.com", "<script>@x.com"],
    "uri": ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd", "javascript:alert(1)"],
    "uuid": ["00000000-0000-0000-0000-000000000000", "' OR 1=1--", "../admin"],
    "date": ["2025-01-01", "' OR 1=1--", "0000-00-00"],
    "date-time": ["2025-01-01T00:00:00Z", "' OR 1=1--"],
}

# Error markers that indicate a vulnerability or interesting behavior.
_ERROR_MARKERS = [
    "sql", "syntax", "mysql", "postgres", "sqlite", "oracle", "mssql",
    "exception", "traceback", "stack trace", "error in", "fatal",
    "undefined", "null reference", "cannot read property",
    "root:", "/bin/", "uid=", "gid=",
    "<script>", "alert(1)", "onerror",
    "49",  # SSTI math eval
    "jndi", "lookup",
    "169.254.169.254", "meta-data",
    "internal server error",
]


def _extract_operations(spec: dict) -> list[dict]:
    """Extract operations from OpenAPI 3.x or Swagger 2.0."""
    ops = []
    base_url = ""

    # OpenAPI 3.x
    if "openapi" in spec:
        servers = spec.get("servers", [])
        if servers:
            base_url = servers[0].get("url", "")
        paths = spec.get("paths", {})
    # Swagger 2.0
    elif "swagger" in spec:
        host = spec.get("host", "")
        base_path = spec.get("basePath", "")
        schemes = spec.get("schemes", ["https"])
        base_url = f"{schemes[0]}://{host}{base_path}" if host else ""
        paths = spec.get("paths", {})
    else:
        return []

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.startswith("x-") or method == "parameters":
                continue
            if not isinstance(op, dict):
                continue
            params = []
            # Path-level + operation-level parameters
            for p in (methods.get("parameters", []) or []) + (op.get("parameters", []) or []):
                if not isinstance(p, dict):
                    continue
                params.append({
                    "name": p.get("name", ""),
                    "in": p.get("in", "query"),
                    "type": _resolve_type(p, spec),
                    "required": p.get("required", False),
                })
            # Request body (OpenAPI 3.x)
            body = op.get("requestBody", {})
            if isinstance(body, dict):
                content = body.get("content", {})
                for ct, schema_obj in content.items():
                    if isinstance(schema_obj, dict) and "schema" in schema_obj:
                        body_props = _extract_properties(schema_obj["schema"], spec)
                        for name, ptype in body_props.items():
                            params.append({
                                "name": name, "in": "body",
                                "type": ptype, "required": True,
                            })
            ops.append({
                "method": method.upper(),
                "path": path,
                "base_url": base_url,
                "params": params,
                "operation_id": op.get("operationId", ""),
                "security": bool(op.get("security")),
            })
    return ops


def _resolve_type(param: dict, spec: dict) -> str:
    """Resolve parameter type from schema or direct type field."""
    schema = param.get("schema", param)
    if "$ref" in schema:
        return "string"
    fmt = schema.get("format", "")
    ptype = schema.get("type", "string")
    if fmt in ("email", "uri", "uuid", "date", "date-time"):
        return fmt
    return ptype


def _extract_properties(schema: dict, spec: dict) -> dict[str, str]:
    """Extract property name→type from a JSON Schema object."""
    if "$ref" in schema:
        ref_path = schema["$ref"].lstrip("#/").split("/")
        resolved = spec
        for part in ref_path:
            resolved = resolved.get(part, {})
        return _extract_properties(resolved, spec) if isinstance(resolved, dict) else {}
    props = schema.get("properties", {})
    result = {}
    for name, prop in props.items():
        if isinstance(prop, dict):
            result[name] = prop.get("format", prop.get("type", "string"))
    return result


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def fuzz_api_schema(
        spec_url: str = "",
        spec_text: str = "",
        base_url: str = "",
        cookie: str = "",
        bearer_token: str = "",
        max_operations: int = 50,
        payloads_per_param: int = 3,
    ) -> str:
        """Auto-exercise every OpenAPI endpoint with type-aware injection payloads.

        Walks operations in an OpenAPI 3.x / Swagger 2.0 spec, generates
        valid + malicious requests per parameter type, sends through Burp,
        and flags error signatures / anomalies.

        Args:
            spec_url: URL to fetch the OpenAPI/Swagger spec from.
            spec_text: Raw spec JSON (alternative to spec_url).
            base_url: Override the spec's server URL (e.g. http://localhost:8080).
            cookie: Cookie header for authenticated endpoints.
            bearer_token: Bearer token for Authorization header.
            max_operations: Max operations to test (default 50).
            payloads_per_param: Payloads per parameter per type (default 3).
        """
        if not spec_url and not spec_text:
            return "Error: provide spec_url or spec_text."

        if spec_url:
            resp = await client.post("/api/http/curl", json={
                "url": spec_url, "method": "GET",
            })
            if "error" in resp:
                return f"Error fetching spec: {resp['error']}"
            spec_text = resp.get("response_body", "")

        try:
            spec = json.loads(spec_text)
        except json.JSONDecodeError:
            return "Error: spec is not valid JSON."

        ops = _extract_operations(spec)
        if not ops:
            return "No operations found in spec."

        ops = ops[:max_operations]
        lines = [f"API Schema Fuzz: {len(ops)} operations\n"]
        total_requests = 0
        anomalies = []

        for op in ops:
            op_url = base_url.rstrip("/") if base_url else op["base_url"].rstrip("/")
            path = op["path"]
            method = op["method"]

            if not op["params"]:
                continue

            for param in op["params"]:
                ptype = param["type"]
                payloads = _TYPE_PAYLOADS.get(ptype, _TYPE_PAYLOADS["string"])
                payloads = payloads[:payloads_per_param]

                for payload in payloads:
                    # Build request
                    url = op_url + path
                    headers = {}
                    body = ""
                    if cookie:
                        headers["Cookie"] = cookie
                    if bearer_token:
                        headers["Authorization"] = f"Bearer {bearer_token}"

                    if param["in"] == "query":
                        sep = "&" if "?" in url else "?"
                        url = f"{url}{sep}{param['name']}={payload}"
                    elif param["in"] == "path":
                        url = url.replace(f"{{{param['name']}}}", str(payload))
                    elif param["in"] == "header":
                        headers[param["name"]] = str(payload)
                    elif param["in"] == "body":
                        body = json.dumps({param["name"]: payload})
                        headers["Content-Type"] = "application/json"

                    req = {"url": url, "method": method}
                    if headers:
                        req["headers"] = headers
                    if body:
                        req["body"] = body

                    resp = await client.post("/api/http/curl", json=req)
                    total_requests += 1

                    if "error" in resp:
                        continue

                    status = resp.get("status_code", 0)
                    resp_body = (resp.get("response_body", "") or "").lower()

                    # Check for anomalies
                    matched_markers = [
                        m for m in _ERROR_MARKERS if m in resp_body
                    ]
                    if matched_markers or status >= 500:
                        anomaly = {
                            "op": f"{method} {path}",
                            "param": param["name"],
                            "payload": payload,
                            "status": status,
                            "markers": matched_markers[:5],
                            "index": resp.get("history_index", -1),
                        }
                        anomalies.append(anomaly)

        lines.append(f"Requests sent: {total_requests}")
        lines.append(f"Anomalies: {len(anomalies)}\n")

        if anomalies:
            for a in anomalies[:20]:
                lines.append(
                    f"  [{a['status']}] {a['op']} param={a['param']} "
                    f"payload={a['payload']!r} markers={a['markers']} "
                    f"(#{a['index']})"
                )
            if len(anomalies) > 20:
                lines.append(f"  ... ({len(anomalies) - 20} more)")
            lines.append("")
            lines.append(
                "Anomalies are LEADS, not confirmed findings. "
                "Replay each with confirm_sqli/confirm_xss/confirm_ssti "
                "for verification."
            )
        else:
            lines.append("No anomalies detected in the tested operations.")

        return "\n".join(lines)
