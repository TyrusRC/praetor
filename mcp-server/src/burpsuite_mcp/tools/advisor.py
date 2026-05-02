"""Strategic hunt advisor — pre-computes testing plans to minimize Claude's reasoning tokens.

Implements the Advisor Strategy: instead of Claude spending tokens figuring out
WHAT to test and in WHAT order, the advisor encodes expert methodology directly
and returns structured action plans. Claude focuses on EXECUTING, not deciding.

Decision logic sourced from: hunt.md, burp-workflow.md, verify-finding.md skills.
"""

import json
import re
from pathlib import Path

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
        """Get a prioritized testing plan for a target with phased tool recommendations based on tech stack.

        Args:
            target_url: Target base URL
            tech_stack: Known technologies (auto-detected if omitted)
            known_endpoints: Already-discovered endpoints to skip
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

        # Phase 0: Edition gate — call once per session.
        lines.append("PHASE 0 — EDITION CHECK (do this FIRST, once per session):")
        lines.append(f"  0. check_pro_features()")
        lines.append(f"     → Confirms Pro vs Community. If Community: skip scan_url/")
        lines.append(f"       crawl_target/Collaborator-based tools and use the")
        lines.append(f"       MCP-side equivalents listed in that tool's output.")
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
        """Get the single best next action based on current progress. Returns one specific tool call to execute.

        Args:
            target_url: Target base URL
            completed_phases: Phases done ('recon', 'probe', 'exploit', 'verify')
            findings_count: Number of findings so far
            tested_params: Parameters already tested
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
        """Execute the entire recon phase in one call -- session create, tech detect, sensitive files, and analysis.

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
        domain: str = "",
        business_context: str = "",
        environment: str = "",
        logger_index: int = -1,
        human_verified: bool = False,
        overrides: list[str] | None = None,
    ) -> str:
        """Assess a suspected finding against the 7-Question Validation Gate before save_finding.

        Args:
            vuln_type: Vulnerability type (e.g. 'xss', 'sqli', 'idor', 'ssrf')
            evidence: What you observed (free-text)
            endpoint: The endpoint tested
            parameter: The parameter tested
            response_diff: How the response differed from baseline
            domain: Target domain for scope + duplicate checks
            business_context: Target business type for impact scoring (e.g. 'ecommerce', 'healthcare', 'banking', 'saas', 'social', 'government')
            environment: Deployment environment (e.g. 'production', 'staging', 'internal', 'public_api')
            logger_index: Proxy-history index of the confirming response. When provided, evidence is auto-augmented with class-specific markers detected programmatically (R1).
            human_verified: Operator manually confirmed in Burp UI / browser. Skips Q5 evidence gate; Q1/Q4/Q6 still apply (R19).
            overrides: Gate names to bypass (R20). Each entry "<gate>:<reason>". Recognized gates: q1_scope, q2_repro, q4_dedup, q5_evidence, q6_never_submit, q7_triager.
        """
        issues = []
        audit_overrides: list[str] = []
        verdict = "REPORT"
        override_set: set[str] = set()
        for ov in (overrides or []):
            gate = (ov.split(":", 1)[0] if ":" in ov else ov).strip().lower()
            if gate:
                override_set.add(gate)
                audit_overrides.append(ov)

        # NEVER SUBMIT — aligned with .claude/rules/hunting.md. Matching is
        # done on vuln_type AND on evidence keywords so hunters writing
        # vuln_type='xss' + evidence='self-XSS requires paste' still trip.
        never_submit_types = {
            "missing_headers": "Missing security headers alone — informative, not reportable",
            "cookie_flags": "Cookie without Secure/HttpOnly — requires MitM or XSS to exploit",
            "clickjacking": "Clickjacking on non-sensitive pages has no impact",
            "self_xss": "Self-XSS — victim must paste payload themselves",
            "csrf_logout": "CSRF on logout — minimal impact",
            "csrf_non_state_changing": "CSRF on non-state-changing endpoint — no impact",
            "open_redirect_no_chain": "Open redirect without token theft chain — low impact",
            "mixed_content": "Mixed content — browser mitigates",
            "rate_limit_missing": "Missing rate limiting on non-sensitive endpoint — no security impact",
            "stack_trace": "Stack traces alone — info disclosure, not exploitable",
            "user_enumeration": "Username enumeration on public sign-up — often by design",
            "referrer_policy": "Missing Referrer-Policy — extremely minor",
            "spf": "SPF/DMARC/DKIM issues — email security, usually out of scope",
            "dmarc": "SPF/DMARC/DKIM issues — email security, usually out of scope",
            "content_spoofing": "Content spoofing without XSS — minimal impact",
            "host_header_no_cache": "Host header injection without cache poisoning — no exploit path",
            "cors_no_creds": "CORS without credentials + sensitive data — browser blocks",
            "ssl_config": "SSL/TLS configuration issues — scanner noise",
            "version_disclosure": "Software version disclosure alone — needs exploit chain",
            "tabnabbing": "Reverse tabnabbing — low impact, disputed",
            "text_injection": "Text injection without HTML context — no code execution",
            "idn_homograph": "IDN homograph attacks — browser-mitigated",
            "autocomplete": "Missing autocomplete=off — password managers handle this",
            "options_method": "OPTIONS method enabled — normal HTTP behavior",
        }

        # Evidence keywords that imply a NEVER SUBMIT class regardless of vuln_type
        never_submit_keywords = {
            "self-xss": "Self-XSS — victim must paste payload themselves",
            "self xss": "Self-XSS — victim must paste payload themselves",
            "clickjacking": "Clickjacking on non-sensitive pages has no impact",
            "csrf on logout": "CSRF on logout — minimal impact",
            "autocomplete=off": "Missing autocomplete=off — password managers handle this",
            "stack trace": "Stack traces alone — info disclosure, not exploitable",
            "tabnabbing": "Reverse tabnabbing — low impact, disputed",
        }

        vuln_lower = vuln_type.lower()
        evidence_lower = evidence.lower()

        # ── R1: Auto-augment evidence from logger_index ────────────────
        # Hunters often confirm via Burp UI but write thin prose evidence.
        # When a concrete proxy/logger index is provided, fetch the entry
        # and append class-specific markers programmatically. Result: Q5
        # passes on automation evidence the human didn't bother to type.
        derived_markers: list[str] = []
        if logger_index is not None and logger_index >= 0:
            try:
                detail = await client.get(f"/api/proxy/history/{logger_index}")
                if "error" not in detail:
                    status = str(detail.get("status_code", ""))
                    body = (detail.get("response_body") or "")[:8000].lower()
                    headers = detail.get("response_headers", []) or []
                    header_blob = " ".join(
                        f"{h.get('name','').lower()}: {h.get('value','').lower()}"
                        for h in headers if isinstance(h, dict)
                    )

                    # Universal markers
                    if status:
                        derived_markers.append(f"status={status}")
                    if status in ("500", "502", "503"):
                        derived_markers.append("server-error")

                    # SQLi vendor errors
                    for sql_err in ("sql syntax", "ora-", "mysql_fetch", "pg_query",
                                    "sqlite", "syntax error", "unclosed quotation",
                                    "unterminated", "near \"", "type cast"):
                        if sql_err in body:
                            derived_markers.append(sql_err)

                    # XSS: payload echoed in executable context
                    for xss_marker in ("<script", "onerror=", "onload=", "javascript:",
                                       "alert(", "<svg", "<img"):
                        if xss_marker in body:
                            derived_markers.append(f"executable: {xss_marker}")

                    # SSRF: cloud-metadata or callback proof
                    for ssrf_marker in ("ami-id", "instance-identity", "169.254.169.254",
                                        "metadata.google", "compute.metadata"):
                        if ssrf_marker in body or ssrf_marker in header_blob:
                            derived_markers.append(ssrf_marker)

                    # RCE markers
                    for rce_marker in ("uid=", "gid=", "euid=", "/bin/sh", "/bin/bash"):
                        if rce_marker in body:
                            derived_markers.append(rce_marker)

                    # Path traversal
                    if "root:x:" in body or "/etc/passwd" in body[:500]:
                        derived_markers.append("file_read: passwd")

                    # IDOR proof: status 200 on cross-account access
                    if status == "200" and parameter:
                        derived_markers.append("200 ok")

                    # CORS leak
                    if "access-control-allow-origin: *" in header_blob and "access-control-allow-credentials: true" in header_blob:
                        derived_markers.append("cors_credentialed_wildcard")
            except Exception:
                pass

        if derived_markers:
            evidence_lower = (evidence_lower + " | derived: " + " ".join(derived_markers)).strip()

        # ── Apply active program policy overrides (Rule 17 dynamic) ──
        # set_program_policy persists a per-engagement override; merge it on
        # top of the hardcoded defaults so programs that DO pay
        # tabnabbing/user_enum aren't auto-killed.
        try:
            from burpsuite_mcp.tools.intel import load_active_program_policy
            program = load_active_program_policy()
        except Exception:
            program = {}
        for k in program.get("never_submit_remove", []) or []:
            never_submit_types.pop(k, None)
        for k in program.get("never_submit_add", []) or []:
            never_submit_types.setdefault(
                k, f"Program-specific NEVER SUBMIT override ({k})"
            )
        program_confidence_floor = float(program.get("confidence_floor", 0.0) or 0.0)

        # Q1: Scope. SKIP on transient extension errors (R17). Only DO NOT
        # REPORT when the extension explicitly says out-of-scope.
        if "q1_scope" in override_set:
            issues.append("Q1 OVERRIDE: scope check bypassed by operator")
        elif domain:
            try:
                scope_resp = await client.post(
                    "/api/scope/check",
                    json={"url": endpoint if "://" in endpoint else f"https://{domain}{endpoint}"},
                )
                if "error" in scope_resp:
                    # Transient — extension unreachable / 500 / etc. Skip not Fail.
                    issues.append(f"Q1 SKIP: scope check unavailable ({scope_resp['error'][:60]})")
                elif not scope_resp.get("in_scope", False):
                    issues.append(f"Q1 FAIL: endpoint {endpoint} is OUT OF SCOPE — do not report")
                    verdict = "DO NOT REPORT"
            except Exception as e:
                issues.append(f"Q1 SKIP: scope check raised ({type(e).__name__})")
        else:
            issues.append("Q1 SKIP: pass `domain=...` to enable scope verification")

        # Q2: Reproducible
        if "q2_repro" in override_set:
            issues.append("Q2 OVERRIDE: reproducibility check bypassed")
        elif any(w in evidence_lower for w in ("once", "intermittent", "one time", "non-reproducible", "could not reproduce")):
            issues.append("Q2 FAIL: evidence suggests non-reproducible — re-test 3+ times from clean state")

        # Q6: NEVER SUBMIT type match — word-boundary so `xss_filter_bypass`
        # doesn't mis-fire on `self_xss`, and `idor_via_csrf_logout` doesn't
        # trip `csrf_logout`.
        import re as _re_q6
        if "q6_never_submit" in override_set:
            issues.append("Q6 OVERRIDE: NEVER SUBMIT bypass — must include chain_with[] in save_finding")
        else:
            for ns_key, ns_reason in never_submit_types.items():
                if _re_q6.search(rf"(?<![a-z]){_re_q6.escape(ns_key)}(?![a-z])", vuln_lower):
                    issues.append(f"Q6 NEVER SUBMIT: {ns_reason}")
                    verdict = "DO NOT REPORT"
                    break

        # Q6: NEVER SUBMIT evidence-keyword match — skip when the keyword
        # appears in a NEGATED context. Hunters often write "not a stack
        # trace, the fingerprint is..." — that's a contrast, not a self-flag.
        # Heuristic: ignore the match if "not", "isn't", "no ", "without",
        # "instead of", "ruled out" appears within 24 chars BEFORE the keyword.
        if verdict == "REPORT" and "q6_never_submit" not in override_set:
            negation_window = 24
            negators = (" not ", " no ", "isn't ", "is not", "without ", "instead of", "ruled out", "not a ", "not just")
            for ns_key, ns_reason in never_submit_keywords.items():
                pattern = _re_q6.compile(rf"(?<![a-z]){_re_q6.escape(ns_key)}(?![a-z])")
                m = pattern.search(evidence_lower)
                if not m:
                    continue
                # Look back up to negation_window chars
                lookback = evidence_lower[max(0, m.start() - negation_window):m.start()]
                if any(neg in lookback for neg in negators):
                    continue  # negated — not actually a NEVER SUBMIT signal
                issues.append(f"Q6 NEVER SUBMIT: {ns_reason}")
                verdict = "DO NOT REPORT"
                break

        # ── Q3 / Q5: Impact + evidence quality per vuln class ──────────
        # R2: expanded keyword lists; unknown vuln_type SKIPS Q5 (default REPORT
        # rather than weak). R19: human_verified bypasses Q5 entirely.
        weak_evidence = False

        # Per-class strong-evidence keyword sets. Generous — match how
        # hunters actually write evidence.
        Q5_KEYWORDS: dict[str, list[str]] = {
            "sqli": [
                "sleep", "delay", "union", "version()", "current_user",
                "database()", "schema_name", "table_name", "stacked query",
                "boolean differential", "boolean diff", "subquery",
                "type cast", "cast error", "type mismatch", "string concat",
                "concat error", "sql syntax", "ora-", "mysql_fetch",
                "pg_query", "sqlite", "syntax error", "unclosed quotation",
                "unterminated", "1=1 vs 1=2", "and 1=1", "and 1=2",
            ],
            "ssrf": [
                "collaborator", "callback", "dns", "metadata", "169.254",
                "ami-id", "instance-identity", "compute.metadata",
                "metadata.google", "imdsv1", "imdsv2", "interaction received",
                "oob", "out-of-band", "pingback",
            ],
            "xss": [
                "alert(", "executed", "dom-based", "stored", "reflected in",
                "<scr" "ipt", "onerror=", "onload=", "j" "avascript:",
                "executable context", "html context", "attribute context",
                "js sink", "innerhtml", "doc-write", "dom xss",
                "popup", "confirm(", "prompt(", "executable: ",
                "rendered as raw", "raw <scr" "ipt",
            ],
            "idor": [
                "different user", "unauthorized", "other account",
                "cross-tenant", "200 ok", "sequential", "predictable",
                "incrementing", "guessable", "auto-increment", "monotonic",
                "id range", "id space", "fuzz id", "enumerate id",
                "id enumeration", "id walk", "user_id=", "userid=",
                "account_id=", "order_id=", "uuid v1", "uuidv1",
                "same id space", "shared id", "cross-app", "cross app",
                "other app same", "bola", "bfla",
            ],
            "rce": [
                "uid=", "gid=", "euid=", "whoami", "collaborator",
                "dns callback", "/bin/sh", "/bin/bash", "command output",
                "shell return", "exec returned", "process executed",
            ],
            "path_traversal": [
                "root:x:", "/etc/passwd", "boot.ini", "win.ini",
                "file_read", "file content disclosed", "../../../",
                "..\\..\\", "directory traversal",
            ],
            "xxe": [
                "external entity", "doctype", "system identifier",
                "&xxe;", "collaborator", "file_read", "callback",
            ],
            "ssti": [
                "{{7*7}}", "49", "${{", "<%= ", "template engine",
                "jinja", "twig", "freemarker", "velocity", "executed template",
            ],
            "command_injection": [
                "uid=", "whoami", "; ls", "| ls", "&& ls",
                "command output", "shell return", "/bin/", "cmd.exe",
            ],
            "open_redirect_chain": [
                "token leaked", "session captured", "fragment exfil",
                "oauth code intercepted", "redirect destination controlled",
            ],
            "csrf": [
                "no token", "missing csrf", "samesite none",
                "state-changing", "performed action", "successfully posted",
            ],
        }
        # Aliases: vuln_type variants normalize to canonical keyword class
        Q5_ALIASES = {
            "reflected xss": "xss", "stored xss": "xss", "dom xss": "xss",
            "blind xss": "xss",
            "sqli_blind": "sqli", "sqli_time": "sqli", "sqli_boolean": "sqli",
            "sqli_error": "sqli", "sqli_oob": "sqli",
            "id_enumeration": "idor", "predictable_id": "idor",
            "sequential_id": "idor", "access_control": "idor",
            "bola": "idor", "bfla": "idor",
            "rce_blind": "rce", "remote code execution": "rce",
            "lfi": "path_traversal", "directory_traversal": "path_traversal",
            "cmdi": "command_injection",
        }

        q5_class = Q5_ALIASES.get(vuln_lower, vuln_lower)

        if human_verified:
            issues.append("Q5 SKIP: human_verified=True (operator confirmed in Burp UI/browser)")
            audit_overrides.append("q5_evidence:human_verified")
        elif "q5_evidence" in override_set:
            issues.append("Q5 OVERRIDE: evidence gate bypassed by operator")
        elif q5_class in Q5_KEYWORDS:
            keywords = Q5_KEYWORDS[q5_class]
            strong = any(k in evidence_lower for k in keywords)
            if not strong:
                issues.append(
                    f"Q5 WEAK EVIDENCE: {q5_class} needs at least one of: "
                    f"{', '.join(keywords[:6])}, ... ({len(keywords)} accepted markers). "
                    f"Pass logger_index=<N> to auto-derive, or human_verified=True if confirmed in UI."
                )
                weak_evidence = True
        else:
            # R2: unknown vuln_type — DEFAULT REPORT, not weak.
            issues.append(f"Q5 SKIP: unknown vuln_type '{vuln_type}' — no keyword list. Defaulting REPORT.")

        # ── R3: Timing-based requires 3x reproductions, but ONLY when
        # vuln_type signals timing/blind/race. Don't trip on prose like
        # "response time was 200ms".
        TIMING_VULN_TYPES = {
            "sqli_blind", "sqli_time", "sqli_oob",
            "command_injection_blind", "ssti_blind", "ssrf_blind",
            "xxe_blind", "rce_blind", "race_condition",
            "request_smuggling", "http_desync",
        }
        if vuln_lower in TIMING_VULN_TYPES and "q5_evidence" not in override_set and not human_verified:
            has_replays = any(
                w in evidence_lower
                for w in ("3x", "three iterations", "3/3", "3 consistent",
                          "consistent across", "confirmed 3", "3 repeats", "repeated 3")
            )
            if not has_replays:
                issues.append(
                    "Q5 TIMING RULE: timing/blind vuln types require 3+ consistent "
                    "iterations (include '3/3' or 'confirmed 3' in evidence)"
                )
                weak_evidence = True

        # Q4: Duplicate check — read persisted findings if domain given.
        # Match must be on (endpoint, vuln_type root, parameter) tuple. Old
        # logic used substring `vuln_lower in f.get("vuln_type", "")` which
        # falsely deduped any `sqli` finding against any prior `sqli_blind`
        # / `sqli_time`, dropping legitimate distinct findings.
        def _vuln_root(v: str) -> str:
            v = (v or "").lower().strip()
            # Trim common suffixes/prefixes so sqli == sqli_blind == sqli_time
            for sep in ("_blind", "_time", "_boolean", "_error", "_oob",
                        "_reflected", "_stored", "_dom", "_second_order"):
                if v.endswith(sep):
                    v = v[: -len(sep)]
            return v

        if domain and verdict == "REPORT" and "q4_dedup" not in override_set:
            try:
                import re as _re
                sanitized = _re.sub(r'[^a-zA-Z0-9._-]', '_', domain)
                findings_path = Path.cwd() / ".burp-intel" / sanitized / "findings.json"
                if findings_path.exists():
                    existing = json.loads(findings_path.read_text()).get("findings", [])
                    new_root = _vuln_root(vuln_lower)
                    # R4: dedup ONLY when both new and existing have non-empty
                    # parameter and they match. Empty parameter on either side
                    # = treat as distinct, let through. Stops silent merging.
                    for f in existing:
                        same_ep = f.get("endpoint", "") == endpoint
                        existing_root = _vuln_root(f.get("vuln_type", ""))
                        same_type = (
                            new_root and existing_root and new_root == existing_root
                        )
                        existing_param = f.get("parameter", "") or ""
                        if not parameter or not existing_param:
                            same_param = False  # empty -> assume distinct
                        else:
                            same_param = existing_param == parameter
                        if same_ep and same_type and same_param:
                            issues.append(f"Q4 DUPLICATE: already saved as {f.get('id', '?')} — update instead of re-save")
                            verdict = "DO NOT REPORT"
                            break
            except (OSError, json.JSONDecodeError, ImportError):
                pass  # best-effort; no crash on missing intel

        # Q7: Triager-mass-report heuristic. If only weak-evidence flags and
        # a low-impact vuln class, the triager will mark informative.
        low_impact_classes = {"open_redirect", "information_disclosure", "info_disclosure"}
        if "q7_triager" in override_set:
            issues.append("Q7 OVERRIDE: triager-mass-report heuristic bypassed")
        elif verdict == "REPORT" and weak_evidence and vuln_lower in low_impact_classes:
            issues.append("Q7 TRIAGER TEST: low-impact class + weak evidence — likely marked informative. Chain with another finding first.")
            verdict = "NEEDS MORE EVIDENCE"

        # Any weak-evidence flag alone downgrades from REPORT to NEEDS MORE EVIDENCE
        if verdict == "REPORT" and weak_evidence:
            verdict = "NEEDS MORE EVIDENCE"

        # ── Business Impact & Environment Scoring ──────────────────
        # Adjust severity based on what the target handles and where it runs.
        impact_boost = 0.0
        impact_notes = []

        biz = business_context.lower() if business_context else ""
        env = environment.lower() if environment else ""

        # High-value business contexts where same vuln has higher impact
        biz_multipliers = {
            "banking": ("financial data at risk", 0.10),
            "fintech": ("financial data at risk", 0.10),
            "healthcare": ("PHI/PII exposure — HIPAA implications", 0.10),
            "government": ("citizen data / national security", 0.08),
            "ecommerce": ("payment data / PCI scope", 0.08),
            "payment": ("payment data / PCI scope", 0.08),
            "saas": ("multi-tenant data leakage risk", 0.06),
            "social": ("user PII / account takeover risk", 0.05),
            "crypto": ("financial loss / wallet compromise", 0.10),
        }
        for biz_key, (reason, boost) in biz_multipliers.items():
            if biz_key in biz:
                impact_boost += boost
                impact_notes.append(f"Business context ({biz_key}): {reason} (+{boost:.0%})")
                break

        # Environment context
        if "production" in env or "prod" in env:
            impact_boost += 0.05
            impact_notes.append("Production environment: live user impact (+5%)")
        elif "internal" in env:
            impact_boost -= 0.05
            impact_notes.append("Internal environment: reduced external exposure (-5%)")

        # Vuln-class × business-context amplifiers
        high_impact_combos = {
            ("sqli", "banking"): "SQL injection on banking app = direct financial data access",
            ("sqli", "healthcare"): "SQL injection on healthcare = PHI breach",
            ("idor", "saas"): "IDOR on multi-tenant SaaS = cross-tenant data leak",
            ("idor", "ecommerce"): "IDOR on ecommerce = other users orders/payment data",
            ("ssrf", "cloud"): "SSRF on cloud-hosted = metadata credential theft",
            ("xss", "banking"): "XSS on banking = session hijack for financial access",
            ("auth_bypass", "payment"): "Auth bypass on payment = unauthorized transactions",
            ("rce", "production"): "RCE on production = full system compromise",
        }

        # Predictable/sequential-ID escalator — independent of business context.
        # This is the "fuzz IDs to dump the table" class. High impact when the
        # endpoint returns PII or when the same ID space is shared across
        # ecosystem apps (see hunting Rule 6 — this is authz, NOT credential
        # brute-force).
        id_enum_signals = ("sequential", "predictable", "incrementing", "guessable",
                           "auto-increment", "id enumeration", "fuzz id", "enumerate id",
                           "same id space", "cross-app", "shared id")
        if any(s in evidence_lower for s in id_enum_signals):
            impact_boost += 0.08
            impact_notes.append(
                "Predictable/sequential ID exposure (+8%): ID range is fuzzable; "
                "full record set enumerable and likely reusable across apps in same ecosystem"
            )
        for (vtype, ctx), reason in high_impact_combos.items():
            if vtype in vuln_lower and (ctx in biz or ctx in env):
                impact_boost += 0.05
                impact_notes.append(f"High-impact combo: {reason}")
                break

        # Derive a suggested confidence in [0.0, 1.0]. Pass this straight to
        # save_finding(confidence=...). The thresholds line up with
        # ProxyHighlight's RED/ORANGE/YELLOW/GREEN mapping so the colour of
        # the proxy-history entry matches the gate's verdict.
        if verdict == "DO NOT REPORT":
            suggested_confidence = 0.05
        elif verdict == "NEEDS MORE EVIDENCE":
            # Weak evidence -> ORANGE-ish band. Each flag drags it down ~0.05,
            # floor at 0.40 so something survives to the hunter.
            penalty = max(0, len(issues) - 1) * 0.05
            suggested_confidence = max(0.40, 0.65 - penalty + impact_boost)
        elif not issues:
            # Verdict REPORT and zero gate issues — highest confidence.
            suggested_confidence = min(1.0, 0.92 + impact_boost)
        else:
            # REPORT with some non-fatal issues (e.g. Q1 skipped because no
            # domain passed). Slightly lower than the clean-pass case.
            suggested_confidence = min(1.0, 0.80 + impact_boost)

        # Apply program-policy confidence floor
        if verdict == "REPORT" and program_confidence_floor > 0:
            if suggested_confidence < program_confidence_floor:
                issues.append(
                    f"Q7 PROGRAM POLICY: program requires confidence >= "
                    f"{program_confidence_floor:.2f}; current is "
                    f"{suggested_confidence:.2f} — strengthen evidence first"
                )
                verdict = "NEEDS MORE EVIDENCE"

        # ── R5: Surface program policy at top of output ──
        program_banner = (
            f"PROGRAM: {program.get('slug')}"
            if program.get("slug")
            else "PROGRAM: DEFAULT (no policy set; consider set_program_policy)"
        )

        # ── R8: Decouple color from confidence ──
        # severity_color encodes severity. confidence is a separate number.
        # Tools that consume this output must NOT use color as a confidence
        # signal. Both shown explicitly.
        sev_to_color = {
            "CRITICAL": "RED",
            "HIGH": "RED",
            "MEDIUM": "ORANGE",
            "LOW": "YELLOW",
            "INFO": "GRAY",
        }
        # Severity is inferred when not explicitly set: REPORT+strong → MEDIUM
        # by default; weak_evidence → LOW; DO NOT REPORT → INFO.
        if verdict == "DO NOT REPORT":
            inferred_severity = "INFO"
        elif weak_evidence:
            inferred_severity = "LOW"
        else:
            inferred_severity = "MEDIUM"
        severity_color = sev_to_color.get(inferred_severity, "YELLOW")

        # Derived markers surfaced for transparency (R1)
        derived_str = ""
        if derived_markers:
            derived_str = f"\n  Auto-derived markers: {', '.join(derived_markers[:8])}"

        override_audit = ""
        if audit_overrides:
            override_audit = f"\n  Operator overrides: {'; '.join(audit_overrides)}"

        # Build impact context string
        impact_str = ""
        if impact_notes:
            impact_str = "\n  Impact context:\n" + "\n".join(f"    + {n}" for n in impact_notes)

        if not issues:
            return (
                f"VERDICT: {verdict}\n"
                f"  {program_banner}\n"
                f"  Type: {vuln_type}\n"
                f"  Endpoint: {endpoint}\n"
                f"  Severity (inferred): {inferred_severity} [color={severity_color}]\n"
                f"  Confidence (separate from color): {suggested_confidence:.2f}\n"
                f"  All 7 questions PASS. Proceed with save_finding(confidence={suggested_confidence:.2f})."
                f"{derived_str}"
                f"{override_audit}"
                f"{impact_str}"
            )

        lines = [f"VERDICT: {verdict}"]
        lines.append(f"  {program_banner}")
        lines.append(f"  Type: {vuln_type}")
        lines.append(f"  Endpoint: {endpoint}")
        if parameter:
            lines.append(f"  Parameter: {parameter}")
        lines.append(f"  Severity (inferred): {inferred_severity} [color={severity_color}]")
        lines.append(f"  Confidence (separate from color): {suggested_confidence:.2f}")
        if derived_markers:
            lines.append(f"  Auto-derived markers: {', '.join(derived_markers[:8])}")
        if audit_overrides:
            lines.append(f"  Operator overrides: {'; '.join(audit_overrides)}")
        if impact_notes:
            lines.append(f"\n  Impact context:")
            for n in impact_notes:
                lines.append(f"    + {n}")
        lines.append(f"\n  Gate issues ({len(issues)}):")
        for issue in issues:
            lines.append(f"    - {issue}")

        if verdict == "DO NOT REPORT":
            lines.append(f"\n  Action: Do not report. Move to next target/parameter.")
        elif verdict == "NEEDS MORE EVIDENCE":
            lines.append(
                f"\n  Action: Strengthen the flagged evidence items, then re-assess before save_finding."
                f"\n  Fast path: pass logger_index=<N> to auto-derive evidence, "
                f"or human_verified=True if confirmed in Burp UI."
            )
        else:
            lines.append(f"\n  Action: Address the issues above, then save_finding(confidence={suggested_confidence:.2f}).")

        return "\n".join(lines)

    @mcp.tool()
    async def pick_tool(task: str) -> str:
        """Given a task description, return the best MCP tool with example arguments.

        Args:
            task: What you want to accomplish
        """
        task_lower = task.lower()

        # Map tasks to tools. Entries are checked in order, first match wins — so
        # more specific keywords (e.g. "jwt") must come BEFORE more generic ones
        # (e.g. "token" which could match CSRF tokens). When ambiguous words
        # appear, use multi-word anchors like "csrf token" rather than bare "token".
        mappings = [
            # ── Evidence-first: SEARCH proxy history before sending new traffic (Rule 29)
            (["find evidence", "find request", "find response", "search history", "look in history",
              "captured request", "evidence for finding", "where is the request", "did we capture",
              "proxy history", "logger entry"], "search_history",
             "search_history(query='<endpoint or string>', filter_method='POST')"),
            # ── Modify-and-iterate on a captured request → Repeater (Rule 30)
            (["modify request", "tweak request", "change header", "change body", "iterate request",
              "test variation", "send to repeater", "repeater"], "send_to_repeater",
             "send_to_repeater(index=<N>, tab_name='f001-sqli-login') then repeater_resend(tab_name, modifications={...})"),
            # ── Volume work → Intruder (Rule 30)
            (["brute", "brute force", "tested creds", "common creds", "default creds",
              "rate limit", "rate-limit", "ratelimit", "spam", "flood", "value enumeration",
              "header injection sweep", "send to intruder", "intruder", "attack with payloads"],
             "send_to_intruder_configured",
             "send_to_intruder_configured(index=<N>, mode='auto', payload_lists=[['admin','test','guest']], attack_type='sniper', tab_name='f002-creds')"),
            # ── Bookmark evidence for the report (Rule 31)
            (["bookmark", "save for report", "organize evidence", "send to organizer", "organizer",
              "remember this request"], "send_to_organizer",
             "send_to_organizer(index=<N>)  # then later: get_organizer_entries() to retrieve"),
            # ── Read existing captured req/resp without re-sending
            (["read request", "read response", "show request", "show response",
              "view captured", "request detail"], "get_request_detail",
             "get_request_detail(index=<N>)  # use extract_regex/headers/json_path for token efficiency"),
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
            (["regex", "regex pattern", "extract value"], "extract_regex",
             "extract_regex(index, 'pattern_here', group=1)"),
            (["sqli", "sql injection"], "auto_probe",
             "auto_probe(session='hunt', categories=['sqli'])"),
            (["xss", "cross-site", "reflected"], "auto_probe",
             "auto_probe(session='hunt', categories=['xss'])"),
            (["ssrf", "server-side request"], "auto_probe",
             "auto_probe(session='hunt', categories=['ssrf'])"),
            (["ssti", "template injection"], "auto_probe",
             "auto_probe(session='hunt', categories=['ssti'])"),
            (["open redirect", "unvalidated redirect"], "test_open_redirect",
             "test_open_redirect(session='hunt', path='/login', parameter='next')"),
            (["idor", "access control", "authorization"], "test_auth_matrix",
             "test_auth_matrix(endpoints=['/api/users/1','/api/users/2'], auth_states={'admin':{...},'user':{...}})"),
            (["race", "concurrent", "double spend", "toctou"], "test_race_condition",
             "test_race_condition(session='hunt', request={...}, concurrent=10)"),
            (["cors", "cross-origin"], "test_cors",
             "test_cors(session='hunt', path='/api/endpoint')"),
            # fuzz anchors are multi-word so bare "test parameter X for SQLi"
            # doesn't hijack more specific routes
            (["fuzz", "smart fuzz", "fuzz param"], "fuzz_parameter",
             "fuzz_parameter(index, parameter='param_name', smart_payloads=True)"),
            (["encode", "decode", "base64", "url encode"], "transform_chain",
             "transform_chain('input', ['url_encode', 'base64_encode'])"),
            (["waf bypass", "encoding chain", "bypass filter"], "transform_chain",
             "transform_chain('<script>alert(1)</script>', ['url_encode', 'base64_encode', 'url_encode'])"),
            # "session" keyword removed — too generic; "login flow" / "authenticate" stay
            (["login flow", "authenticate", "login macro"], "create_macro",
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
