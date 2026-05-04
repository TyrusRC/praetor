"""Edge-case test: discover_common_files."""

import asyncio
import base64
import json
import time
import uuid

from burpsuite_mcp import client

async def discover_common_files_impl(
    session: str,
    tech_specific: bool = True,
) -> str:
    """Probe for common sensitive files and paths (.git, .env, actuator, etc).

    Args:
        session: Session name
        tech_specific: Add tech-specific paths based on detected stack (Java/Spring,
            PHP/WordPress, Node, .NET, Ruby/Rails, Python/Django/Flask). Default True.
    """
    # Universal high-signal paths.
    paths = [
        # VCS exposure
        "/.git/HEAD", "/.git/config", "/.git/index", "/.gitignore",
        "/.svn/entries", "/.svn/wc.db", "/.hg/store",
        # Environment / secrets
        "/.env", "/.env.bak", "/.env.local", "/.env.production",
        "/.env.dev", "/.env.development", "/.env.staging",
        "/credentials.json", "/secrets.json",
        "/config.json", "/config.yml", "/config.yaml",
        # Lockfiles / dependency manifests
        "/package.json", "/package-lock.json", "/yarn.lock",
        "/composer.json", "/composer.lock",
        "/Gemfile", "/Gemfile.lock",
        "/requirements.txt", "/Pipfile", "/Pipfile.lock", "/poetry.lock",
        "/go.mod", "/go.sum",
        "/Cargo.toml", "/Cargo.lock",
        # Cloud creds / CI artefacts
        "/.aws/credentials", "/.aws/config",
        "/.npmrc", "/.dockercfg", "/.docker/config.json",
        "/.gitlab-ci.yml", "/.travis.yml", "/.circleci/config.yml",
        "/Jenkinsfile", "/.github/workflows/", "/buildspec.yml",
        # Server config
        "/.htaccess", "/.htpasswd",
        "/web.config", "/Web.config",
        "/nginx.conf", "/httpd.conf", "/apache2.conf",
        # Status / debug surfaces
        "/server-status", "/server-info",
        "/.DS_Store", "/Thumbs.db",
        "/backup/", "/backups/", "/old/", "/tmp/",
        "/debug/", "/test/", "/dev/", "/staging/",
        # PHP / WordPress
        "/phpinfo.php", "/info.php", "/test.php",
        "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.swp",
        "/wp-admin/", "/wp-login.php",
        # .NET
        "/elmah.axd", "/trace.axd", "/AppPath.config",
        # Spring Actuator
        "/actuator", "/actuator/env", "/actuator/heapdump",
        "/actuator/threaddump", "/actuator/mappings", "/actuator/configprops",
        "/actuator/loggers", "/actuator/health",
        # Java / app servers
        "/console", "/__debug__/", "/h2-console", "/hawtio/",
        "/admin/", "/manager/html", "/manager/status",
        # API docs
        "/swagger.json", "/swagger.yaml", "/swagger-ui",
        "/api-docs", "/openapi.json", "/openapi.yaml",
        "/graphql", "/graphiql", "/playground",
        # Crawl seeds
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/security.txt", "/.well-known/security.txt",
    ]

    if tech_specific:
        # Best-effort tech detection from session intel (cookies, headers).
        # Falls open: if intel unavailable, the universal list still runs.
        try:
            intel = await client.get(f"/api/session/list")
            stack = (str(intel) if isinstance(intel, dict) else "").lower()
        except Exception:
            stack = ""

        extras: list[str] = []
        if any(t in stack for t in ("php", "wordpress", "laravel")):
            extras += [
                "/wp-content/debug.log", "/wp-content/uploads/",
                "/storage/logs/laravel.log", "/.env.example",
            ]
        if any(t in stack for t in ("spring", "java", "tomcat", "jetty")):
            extras += [
                "/META-INF/MANIFEST.MF", "/WEB-INF/web.xml",
                "/WEB-INF/classes/application.properties",
                "/error", "/trace", "/dump", "/jolokia",
            ]
        if any(t in stack for t in ("django", "flask", "python")):
            extras += [
                "/__debug__/", "/django_debug/", "/admin/login/",
                "/static/admin/", "/media/",
            ]
        if any(t in stack for t in ("rails", "ruby")):
            extras += [
                "/rails/info/properties", "/rails/info/routes",
                "/rails/db", "/_specs/",
            ]
        if any(t in stack for t in ("aspnet", ".net", "iis")):
            extras += [
                "/_vti_bin/", "/aspnet_client/", "/bin/",
                "/App_Data/", "/PrecompiledApp.config",
            ]
        if any(t in stack for t in ("node", "express")):
            extras += [
                "/server.js", "/index.js", "/app.js",
                "/.next/static/", "/_next/static/",
            ]
        # Dedup while preserving order.
        seen = set(paths)
        for p in extras:
            if p not in seen:
                paths.append(p)
                seen.add(p)

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
