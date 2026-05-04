"""run_recon_phase: orchestrated session-create + tech-detect + sensitive files."""

import re

from burpsuite_mcp import client
from burpsuite_mcp.tools.advisor._constants import TECH_PRIORITIES
from burpsuite_mcp.tools.advisor._helpers import detect_tech_from_headers


async def run_recon_phase_impl(
    target_url: str,
    session_name: str = "hunt",
    crawl_depth: int = 20,
) -> str:
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
        techs = detect_tech_from_headers(headers)

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
            for vuln in TECH_PRIORITIES.get(tech.lower(), TECH_PRIORITIES["default"]):
                if vuln not in seen:
                    vuln_priority.append(vuln)
                    seen.add(vuln)

        results.append(f"\nPriority test order: {', '.join(vuln_priority[:8])}")
    else:
        results.append(f"\nHome page fetch failed: {home.get('error')}")
        techs = []
        vuln_priority = TECH_PRIORITIES["default"]

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
