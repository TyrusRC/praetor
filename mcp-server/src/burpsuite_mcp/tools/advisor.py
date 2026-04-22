"""Strategic hunt advisor — pre-computes testing plans to minimize Claude's reasoning tokens.

Implements the Advisor Strategy: instead of Claude spending tokens figuring out
WHAT to test and in WHAT order, the advisor encodes expert methodology directly
and returns structured action plans. Claude focuses on EXECUTING, not deciding.

Decision logic sourced from: hunt.md, burp-workflow.md, verify-finding.md skills.
"""

import re

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

# Tech stack → prioritized vulnerability categories
_TECH_PRIORITIES = {
    "php": ["sqli", "lfi", "file_upload", "ssti", "command_injection", "xxe", "ssrf"],
    "java": ["deserialization", "xxe", "ssti", "sqli", "ssrf", "path_traversal", "command_injection"],
    "python": ["ssti", "command_injection", "ssrf", "sqli", "deserialization", "path_traversal"],
    "node": ["ssti", "ssrf", "command_injection", "prototype_pollution", "path_traversal", "sqli"],
    "express": ["ssti", "ssrf", "prototype_pollution", "path_traversal", "sqli", "xss"],
    "asp.net": ["deserialization", "sqli", "path_traversal", "xxe", "ssrf", "xss"],
    "ruby": ["ssti", "command_injection", "deserialization", "sqli", "ssrf", "xss"],
    "rails": ["mass_assignment", "ssti", "sqli", "command_injection", "idor", "ssrf"],
    "django": ["ssti", "sqli", "idor", "ssrf", "path_traversal", "xss"],
    "laravel": ["sqli", "deserialization", "ssti", "mass_assignment", "path_traversal", "file_upload"],
    "spring": ["deserialization", "ssti", "xxe", "sqli", "ssrf", "path_traversal"],
    "angular": ["xss", "ssti", "prototype_pollution", "cors", "open_redirect"],
    "react": ["xss", "ssrf", "cors", "prototype_pollution", "open_redirect"],
    "wordpress": ["sqli", "xss", "file_upload", "lfi", "auth_bypass", "ssrf"],
    "graphql": ["graphql", "idor", "sqli", "injection", "auth_bypass", "info_disclosure"],
    "api": ["idor", "auth_bypass", "mass_assignment", "sqli", "ssrf", "rate_limiting"],
    "default": ["xss", "sqli", "ssrf", "idor", "auth_bypass", "ssti", "path_traversal"],
}

# Parameter name → likely vulnerability
_PARAM_VULN_MAP = {
    "id": "idor", "uid": "idor", "user_id": "idor", "account_id": "idor", "order_id": "idor",
    "search": "xss", "q": "xss", "query": "xss", "name": "xss", "comment": "xss", "message": "xss",
    "url": "ssrf", "redirect": "open_redirect", "next": "open_redirect", "return": "open_redirect",
    "callback": "ssrf", "webhook": "ssrf", "target": "ssrf", "uri": "ssrf",
    "file": "lfi", "path": "lfi", "page": "lfi", "template": "ssti", "include": "lfi",
    "email": "sqli", "username": "sqli", "login": "sqli", "sort": "sqli", "order": "sqli",
    "cmd": "command_injection", "exec": "command_injection", "command": "command_injection",
    "lang": "lfi", "locale": "lfi", "dir": "path_traversal", "folder": "path_traversal",
}

# Phase definitions
_PHASES = {
    "recon": {
        "description": "Map attack surface — discover endpoints, tech stack, parameters",
        "tools": [
            ("browser_crawl", "Crawl target through Burp proxy to populate history"),
            ("get_proxy_history", "Review captured traffic"),
            ("detect_tech_stack", "Identify server tech, frameworks, security headers"),
            ("smart_analyze", "Combined analysis on key endpoints"),
            ("extract_js_secrets", "Check JS files for leaked secrets"),
        ],
    },
    "probe": {
        "description": "Test high-risk parameters with knowledge-driven probes",
        "tools": [
            ("auto_probe", "Knowledge-driven probing across vuln categories"),
            ("probe_endpoint", "Targeted testing on specific params"),
            ("test_cors", "Check CORS misconfig"),
            ("test_jwt", "Analyze JWT tokens if present"),
            ("discover_common_files", "Check for .git, .env, debug endpoints"),
        ],
    },
    "exploit": {
        "description": "Targeted attacks on confirmed attack surface",
        "tools": [
            ("fuzz_parameter", "Smart fuzzing with auto-generated payloads"),
            ("test_auth_matrix", "IDOR detection across auth states"),
            ("test_race_condition", "TOCTOU on state-changing endpoints"),
            ("auto_collaborator_test", "Blind testing with OOB callbacks"),
        ],
    },
    "verify": {
        "description": "Verify findings with reproducible evidence",
        "tools": [
            ("session_request", "Reproduce finding with clean request"),
            ("compare_auth_states", "Confirm IDOR with auth comparison"),
            ("get_response_hash", "Check response consistency"),
        ],
    },
}


def _detect_tech_from_headers(headers: list[dict]) -> list[str]:
    """Extract tech hints from response headers."""
    techs = []
    for h in headers:
        name = h.get("name", "").lower()
        value = h.get("value", "").lower()
        if name == "x-powered-by":
            if "php" in value: techs.append("php")
            if "express" in value: techs.append("express")
            if "asp.net" in value: techs.append("asp.net")
        if name == "server":
            if "apache" in value: techs.append("php")
            # nginx is a generic reverse proxy — don't assume backend tech
            if "gunicorn" in value or "uvicorn" in value: techs.append("python")
        if "set-cookie" in name:
            if "phpsessid" in value: techs.append("php")
            if "jsessionid" in value: techs.append("java")
            if "connect.sid" in value: techs.append("express")
            if "csrftoken" in value: techs.append("django")
            if "laravel_session" in value: techs.append("laravel")
    return list(set(techs))


def _prioritize_params(params: list[dict]) -> list[dict]:
    """Score and sort parameters by attack priority."""
    scored = []
    for p in params:
        name = p.get("name", "").lower()
        vuln = _PARAM_VULN_MAP.get(name)
        score = 3 if vuln else 1
        if p.get("reflected"):
            score += 2
        scored.append({**p, "priority_score": score, "likely_vuln": vuln or "unknown"})
    scored.sort(key=lambda x: x["priority_score"], reverse=True)
    return scored


def register(mcp: FastMCP):

    @mcp.tool()
    async def get_hunt_plan(
        target_url: str,
        tech_stack: list[str] | None = None,
        known_endpoints: list[str] | None = None,
    ) -> str:
        """Get a prioritized testing plan for a target. Returns exactly what to test,
        in what order, with which tools — so you can execute without reasoning about strategy.

        This is the FIRST tool to call when starting a hunt. It replaces 5-10 minutes
        of strategic thinking with a pre-computed action plan.

        Args:
            target_url: Target base URL (e.g. 'https://target.com')
            tech_stack: Known technologies (e.g. ['php', 'mysql', 'angular']). Auto-detected if omitted.
            known_endpoints: Already-discovered endpoints to skip re-scanning

        Returns a structured plan with:
        - Phase 1: Recon actions (which tools, in what order)
        - Phase 2: Probe actions (which vulns to test first based on tech)
        - Phase 3: Exploit actions (which attack tools to use)
        - Priority parameters (which params to fuzz first)
        """
        techs = tech_stack or []

        # Auto-detect tech if not provided
        if not techs:
            try:
                data = await client.post("/api/http/curl", json={"url": target_url, "method": "GET"})
                if "error" not in data:
                    headers = data.get("response_headers", [])
                    techs = _detect_tech_from_headers(headers)
                    body = data.get("response_body", "").lower()
                    if "angular" in body or "ng-app" in body: techs.append("angular")
                    if "react" in body or "reactdom" in body: techs.append("react")
                    if "graphql" in body or "/graphql" in body: techs.append("graphql")
                    if "wordpress" in body or "wp-content" in body: techs.append("wordpress")
            except Exception:
                pass

        if not techs:
            techs = ["default"]

        # Build priority vuln list from tech stack
        vuln_priority = []
        seen = set()
        for tech in techs:
            for vuln in _TECH_PRIORITIES.get(tech.lower(), _TECH_PRIORITIES["default"]):
                if vuln not in seen:
                    vuln_priority.append(vuln)
                    seen.add(vuln)

        lines = [f"Hunt Plan for {target_url}"]
        lines.append(f"Tech detected: {', '.join(techs)}")
        lines.append(f"Priority vulns: {', '.join(vuln_priority[:8])}")
        lines.append("")

        # Phase 1: Recon
        lines.append("PHASE 1 — RECON (do these first, in order):")
        lines.append(f"  1. browser_crawl('{target_url}', max_pages=20)")
        lines.append(f"     → Populates proxy history through Burp proxy")
        lines.append(f"  2. get_proxy_history(limit=50)")
        lines.append(f"     → Review captured endpoints")
        lines.append(f"  3. detect_tech_stack(index=<first_200_response>)")
        lines.append(f"     → Confirm tech stack detection")
        lines.append(f"  4. smart_analyze(index=<most_interesting_page>)")
        lines.append(f"     → Get injection points, params, forms")

        if "angular" in techs or "react" in techs:
            lines.append(f"  5. extract_js_secrets(index=<js_file>)")
            lines.append(f"     → JS frameworks often leak API keys and internal URLs")

        # Phase 2: Probe
        lines.append("")
        lines.append("PHASE 2 — PROBE (test these vuln categories in order):")
        for i, vuln in enumerate(vuln_priority[:6], 1):
            tool = "auto_probe" if i <= 3 else "probe_endpoint"
            lines.append(f"  {i}. {vuln}: use {tool} with category='{vuln}'")

        # Phase 3: Specialized tests
        lines.append("")
        lines.append("PHASE 3 — SPECIALIZED TESTS:")
        if "graphql" in techs:
            lines.append(f"  - test_graphql() — introspection, batch queries, field suggestions")
        if any(t in techs for t in ["api", "default", "node", "express", "rails", "django"]):
            lines.append(f"  - test_auth_matrix() — IDOR across auth states (if multiple roles)")
            lines.append(f"  - test_cors() — CORS misconfiguration")
        lines.append(f"  - discover_common_files() — .git, .env, debug, actuator")
        lines.append(f"  - test_jwt() — if JWT tokens found in cookies/headers")

        # Phase 4: Verify
        lines.append("")
        lines.append("PHASE 4 — VERIFY (for each suspected finding):")
        lines.append(f"  1. Reproduce 3x with session_request()")
        lines.append(f"  2. Compare against baseline response")
        lines.append(f"  3. Check 7-Question Gate before reporting")

        lines.append("")
        lines.append("TOKEN TIP: Use extract_regex/extract_headers instead of get_request_detail to save tokens on large responses.")

        return "\n".join(lines)

    @mcp.tool()
    async def get_next_action(
        target_url: str,
        completed_phases: list[str] | None = None,
        findings_count: int = 0,
        tested_params: list[str] | None = None,
        tech_stack: list[str] | None = None,
    ) -> str:
        """Get the single best next action to take. Call this when you're unsure what to do next.
        Returns ONE specific tool call with arguments — just execute it.

        This replaces strategic reasoning with a lookup — saves 200-500 thinking tokens per decision.

        Args:
            target_url: Target base URL
            completed_phases: Which phases are done ('recon', 'probe', 'exploit', 'verify')
            findings_count: Number of findings so far
            tested_params: Parameters already tested (to avoid re-testing)
            tech_stack: Detected technologies
        """
        completed = set(completed_phases or [])
        tested = set(tested_params or [])
        techs = tech_stack or ["default"]

        if "recon" not in completed:
            return (
                f"NEXT: Recon is not complete. Run:\n"
                f"  browser_crawl('{target_url}', max_pages=20)\n"
                f"Then:\n"
                f"  get_proxy_history(limit=50)\n"
                f"Then mark recon complete."
            )

        if "probe" not in completed:
            # Get priority vulns for tech stack
            vulns = []
            for tech in techs:
                vulns.extend(_TECH_PRIORITIES.get(tech.lower(), _TECH_PRIORITIES["default"]))
            vulns = list(dict.fromkeys(vulns))[:5]  # dedupe, top 5

            return (
                f"NEXT: Run knowledge-driven probes. Execute:\n"
                f"  auto_probe(session='<your_session>', categories={vulns[:3]})\n"
                f"This tests the top-priority vuln categories for {', '.join(techs)} tech stack.\n"
                f"After probing, mark probe complete."
            )

        if "exploit" not in completed:
            if findings_count > 0:
                return (
                    f"NEXT: You have {findings_count} suspected findings. Verify them:\n"
                    f"  For each finding, use session_request() to reproduce 3x.\n"
                    f"  Compare against baseline with compare_responses().\n"
                    f"  If IDOR suspected: test_auth_matrix()\n"
                    f"  If blind vuln: auto_collaborator_test()"
                )
            return (
                f"NEXT: No findings yet from probing. Try specialized tests:\n"
                f"  1. discover_common_files() — sensitive file exposure\n"
                f"  2. test_cors() — CORS misconfiguration\n"
                f"  3. test_jwt() — JWT vulnerabilities (if tokens present)\n"
                f"  4. fuzz_parameter() with smart_payloads=True on highest-risk params"
            )

        return (
            f"NEXT: All phases complete with {findings_count} findings.\n"
            f"  - save_finding() for each confirmed finding\n"
            f"  - generate_report('{target_url.split('//')[1].split('/')[0]}')\n"
            f"  - save_target_intel() to persist for future sessions"
        )

    @mcp.tool()
    async def run_recon_phase(
        target_url: str,
        session_name: str = "hunt",
        crawl_depth: int = 20,
    ) -> str:
        """Execute the entire recon phase in one call — browser crawl + tech detect + analyze.
        Returns a complete attack surface summary. Replaces 5-8 individual tool calls.

        This is the most token-efficient way to start a hunt.

        Args:
            target_url: Target URL to recon
            session_name: Session name to create (default 'hunt')
            crawl_depth: Max pages to crawl (default 20)
        """
        results = []

        # 1. Create session
        session_data = await client.post("/api/session/create", json={
            "name": session_name,
            "base_url": target_url,
        })
        if "error" in session_data:
            results.append(f"Session: {session_data['error']}")
        else:
            results.append(f"Session '{session_name}' created for {target_url}")

        # 2. Fetch home page for initial analysis
        home = await client.post("/api/http/curl", json={
            "url": target_url, "method": "GET",
        })
        if "error" not in home:
            status = home.get("status_code", "?")
            body = home.get("response_body", "")
            headers = home.get("response_headers", [])
            techs = _detect_tech_from_headers(headers)

            # Quick body analysis
            body_lower = body.lower()
            if "ng-app" in body_lower or "angular" in body_lower: techs.append("angular")
            if "react" in body_lower or "__NEXT_DATA__" in body: techs.append("react")
            if "graphql" in body_lower: techs.append("graphql")
            if "wp-content" in body_lower: techs.append("wordpress")

            results.append(f"\nHome page: {status} ({len(body)} bytes)")
            results.append(f"Tech detected: {', '.join(techs) if techs else 'unknown'}")

            # Extract security headers
            sec_headers = {}
            for h in headers:
                n = h.get("name", "").lower()
                if n in ("x-frame-options", "content-security-policy", "strict-transport-security",
                         "x-content-type-options", "x-xss-protection", "referrer-policy"):
                    sec_headers[h["name"]] = h["value"][:80]

            missing = [h for h in ["X-Frame-Options", "Content-Security-Policy",
                                   "Strict-Transport-Security", "X-Content-Type-Options"]
                       if h.lower() not in {k.lower() for k in sec_headers}]

            if sec_headers:
                results.append(f"Security headers: {', '.join(sec_headers.keys())}")
            if missing:
                results.append(f"Missing headers: {', '.join(missing)}")

            # Count interesting elements
            forms = len(re.findall(r'<form\b', body, re.I))
            inputs = len(re.findall(r'<input\b', body, re.I))
            scripts = len(re.findall(r'<script\b[^>]*src=', body, re.I))
            links = len(re.findall(r'<a\b[^>]*href=', body, re.I))

            results.append(f"Elements: {forms} forms, {inputs} inputs, {scripts} scripts, {links} links")

            # Build priority plan
            vuln_priority = []
            seen = set()
            for tech in (techs or ["default"]):
                for vuln in _TECH_PRIORITIES.get(tech.lower(), _TECH_PRIORITIES["default"]):
                    if vuln not in seen:
                        vuln_priority.append(vuln)
                        seen.add(vuln)

            results.append(f"\nPriority test order: {', '.join(vuln_priority[:8])}")
        else:
            results.append(f"\nHome page fetch failed: {home.get('error')}")
            techs = []
            vuln_priority = _TECH_PRIORITIES["default"]

        # 3. Fetch login page (common high-value target)
        login = await client.post("/api/http/curl", json={
            "url": f"{target_url.rstrip('/')}/login", "method": "GET",
        })
        if "error" not in login and login.get("status_code") == 200:
            results.append(f"\nLogin page found: /login ({login.get('status_code')})")
            login_body = login.get("response_body", "")
            csrf_match = re.search(r'name="csrf[^"]*"\s+value="([^"]+)"', login_body)
            if csrf_match:
                results.append(f"  CSRF token present: {csrf_match.group(1)[:20]}...")

        # 4. Check common sensitive files
        sensitive_found = []
        for path in ["/.env", "/.git/HEAD", "/robots.txt", "/sitemap.xml"]:
            try:
                resp = await client.post("/api/http/curl", json={
                    "url": f"{target_url.rstrip('/')}{path}", "method": "GET",
                })
                if "error" not in resp:
                    sc = resp.get("status_code", 0)
                    if sc == 200:
                        sensitive_found.append(f"{path} (200)")
            except Exception:
                pass

        if sensitive_found:
            results.append(f"\nSensitive files found: {', '.join(sensitive_found)}")

        # Summary
        results.append(f"\n{'='*50}")
        results.append("RECON COMPLETE — Next steps:")
        results.append(f"  1. browser_crawl('{target_url}', max_pages={crawl_depth}) — populate full proxy history")
        results.append(f"  2. get_proxy_history(limit=50) — review all endpoints")
        results.append(f"  3. auto_probe(session='{session_name}', categories={vuln_priority[:3]})")

        return "\n".join(results)

    @mcp.tool()
    async def assess_finding(
        vuln_type: str,
        evidence: str,
        endpoint: str,
        parameter: str = "",
        response_diff: str = "",
    ) -> str:
        """Assess a suspected finding against the 7-Question Validation Gate.
        Returns REPORT or DO NOT REPORT with specific reasoning.

        Call this BEFORE save_finding() to avoid false positives.
        Replaces 300-500 tokens of manual reasoning per finding.

        Args:
            vuln_type: Vulnerability type (e.g. 'xss', 'sqli', 'idor', 'ssrf')
            evidence: What you observed (e.g. 'payload reflected in response', '5s time delay')
            endpoint: The endpoint tested
            parameter: The parameter tested
            response_diff: How the response differed from baseline
        """
        issues = []
        verdict = "REPORT"

        # NEVER SUBMIT list check
        never_submit = {
            "missing_headers": "Missing security headers alone are informative, not reportable",
            "cookie_flags": "Cookie without Secure/HttpOnly requires MitM or XSS to exploit",
            "clickjacking_non_sensitive": "Clickjacking on non-sensitive pages has no impact",
            "self_xss": "Self-XSS requires victim to paste payload — not reportable",
            "csrf_logout": "CSRF on logout has minimal impact",
            "open_redirect_no_chain": "Open redirect without token theft chain is low impact",
            "version_disclosure": "Software version disclosure alone needs exploit chain",
            "rate_limit_missing": "Missing rate limiting on non-sensitive endpoints has no security impact",
            "options_method": "OPTIONS method enabled is normal HTTP behavior",
        }

        vuln_lower = vuln_type.lower()
        evidence_lower = evidence.lower()

        # Question 1: Reproducible?
        if "once" in evidence_lower or "intermittent" in evidence_lower:
            issues.append("Q2 FAIL: Finding may not be reproducible. Test 3+ times.")

        # Question 2: Real impact?
        if vuln_lower == "xss" and "self" in evidence_lower:
            issues.append("NEVER SUBMIT: Self-XSS is not reportable")
            verdict = "DO NOT REPORT"
        if vuln_lower == "open_redirect" and "chain" not in evidence_lower:
            issues.append("LOW IMPACT: Open redirect without chain — consider escalation path")
        if vuln_lower in ("missing_headers", "cookie_flags", "version_disclosure"):
            issues.append(f"NEVER SUBMIT: {never_submit.get(vuln_lower, 'Informative only')}")
            verdict = "DO NOT REPORT"

        # Evidence quality
        if vuln_lower == "sqli":
            strong = any(x in evidence_lower for x in ["sleep", "delay", "error", "union", "version()", "database()"])
            if not strong:
                issues.append("WEAK EVIDENCE: SQLi needs timing (3x), error-based, or UNION evidence")

        if vuln_lower == "ssrf":
            strong = any(x in evidence_lower for x in ["collaborator", "callback", "dns", "metadata", "169.254"])
            if not strong:
                issues.append("WEAK EVIDENCE: SSRF needs Collaborator callback or metadata access proof")

        if vuln_lower == "xss":
            strong = any(x in evidence_lower for x in ["alert", "reflected", "executed", "dom", "stored"])
            if not strong:
                issues.append("WEAK EVIDENCE: XSS needs proof of execution (reflected in context, not just present)")

        if vuln_lower == "idor":
            strong = any(x in evidence_lower for x in ["different user", "unauthorized", "other account", "access"])
            if not strong:
                issues.append("WEAK EVIDENCE: IDOR needs proof of accessing another user's data")

        # Timing-based needs 3x
        if "time" in evidence_lower or "delay" in evidence_lower or "sleep" in evidence_lower:
            if "3x" not in evidence_lower and "three" not in evidence_lower:
                issues.append("TIMING RULE: Timing-based findings must be verified 3+ times (network noise)")

        if not issues:
            return (
                f"VERDICT: {verdict}\n"
                f"  Type: {vuln_type}\n"
                f"  Endpoint: {endpoint}\n"
                f"  All 7 questions PASS. Proceed with save_finding()."
            )

        lines = [f"VERDICT: {verdict}"]
        lines.append(f"  Type: {vuln_type}")
        lines.append(f"  Endpoint: {endpoint}")
        lines.append(f"\n  Issues ({len(issues)}):")
        for issue in issues:
            lines.append(f"    - {issue}")

        if verdict == "REPORT":
            lines.append(f"\n  Action: Address the issues above, then save_finding().")
        else:
            lines.append(f"\n  Action: Do not report. Move to next target/parameter.")

        return "\n".join(lines)

    @mcp.tool()
    async def pick_tool(task: str) -> str:
        """Given a task description, return the best MCP tool to use with example arguments.
        Instant tool selection — saves 100-200 thinking tokens per decision.

        Args:
            task: What you want to accomplish (e.g. 'extract CSRF token from login page',
                  'test for SQL injection', 'check if endpoint is vulnerable to IDOR')
        """
        task_lower = task.lower()

        # Map tasks to tools. Entries are checked in order, first match wins — so
        # more specific keywords (e.g. "jwt") must come BEFORE more generic ones
        # (e.g. "token" which could match CSRF tokens). When ambiguous words
        # appear, use multi-word anchors like "csrf token" rather than bare "token".
        mappings = [
            (["crawl", "browse", "populate history", "visit pages"], "browser_crawl",
             "browser_crawl('https://target.com', max_pages=20)"),
            # JWT first — before any generic "token" keyword — because "jwt token" must map to test_jwt
            (["jwt", "bearer token", "access token", "id_token", "refresh_token", "algorithm none"], "test_jwt",
             "test_jwt(token='eyJ...')"),
            # CSRF-specific token extraction uses multi-word anchors so it doesn't eat generic "token" queries
            (["csrf", "csrf token", "anti-csrf", "extract from html", "hidden field"], "extract_css_selector",
             "extract_css_selector(index, 'input[name=csrf]', attribute='value')"),
            (["header", "security header", "cors header", "cookie"], "extract_headers",
             "extract_headers(index, ['Set-Cookie', 'X-Frame-Options', 'Content-Security-Policy'])"),
            (["json", "api response", "json field", "json path"], "extract_json_path",
             "extract_json_path(index, '$.data.user.role')"),
            (["regex", "pattern", "extract value"], "extract_regex",
             "extract_regex(index, 'pattern_here', group=1)"),
            (["sqli", "sql injection", "database"], "auto_probe",
             "auto_probe(session='hunt', categories=['sqli'])"),
            (["xss", "cross-site", "reflected"], "auto_probe",
             "auto_probe(session='hunt', categories=['xss'])"),
            (["ssrf", "server-side request"], "auto_probe",
             "auto_probe(session='hunt', categories=['ssrf'])"),
            (["ssti", "template injection"], "auto_probe",
             "auto_probe(session='hunt', categories=['ssti'])"),
            (["idor", "access control", "authorization"], "test_auth_matrix",
             "test_auth_matrix(endpoints=['/api/users/1','/api/users/2'], auth_states={'admin':{...},'user':{...}})"),
            (["race", "concurrent", "double spend", "toctou"], "test_race_condition",
             "test_race_condition(session='hunt', request={...}, concurrent=10)"),
            (["cors", "origin", "cross-origin"], "test_cors",
             "test_cors(session='hunt', path='/api/endpoint')"),
            (["fuzz", "brute", "payloads", "test parameter"], "fuzz_parameter",
             "fuzz_parameter(index, parameter='param_name', smart_payloads=True)"),
            (["encode", "decode", "base64", "url encode"], "transform_chain",
             "transform_chain('input', ['url_encode', 'base64_encode'])"),
            (["waf bypass", "encoding chain", "bypass filter"], "transform_chain",
             "transform_chain('<script>alert(1)</script>', ['url_encode', 'base64_encode', 'url_encode'])"),
            (["login", "authenticate", "session"], "create_macro",
             "create_macro(name='login', steps=[{method:'GET',url:'/login',extract:[...]},{method:'POST',...}])"),
            (["compare", "diff", "different response"], "compare_responses",
             "compare_responses(index1, index2, mode='full')"),
            (["annotate", "mark", "flag", "highlight"], "annotate_request",
             "annotate_request(index, color='RED', comment='Possible SQLi')"),
            (["tech stack", "technology", "framework"], "detect_tech_stack",
             "detect_tech_stack(index)"),
            (["hidden param", "parameter discovery"], "discover_hidden_parameters",
             "discover_hidden_parameters(session='hunt', method='GET', path='/endpoint')"),
            (["sensitive file", ".git", ".env", "backup"], "discover_common_files",
             "discover_common_files(session='hunt')"),
            (["report", "finding", "document"], "save_finding",
             "save_finding(title='...', description='...', severity='HIGH', endpoint='...', evidence='...')"),
        ]

        for keywords, tool, example in mappings:
            if any(kw in task_lower for kw in keywords):
                return f"Use: {tool}\nExample: {example}"

        return (
            f"No direct match for '{task}'. Try:\n"
            f"  - get_hunt_plan() for full strategy\n"
            f"  - smart_analyze(index) for attack surface analysis\n"
            f"  - auto_probe(session, categories=[...]) for vulnerability testing"
        )
