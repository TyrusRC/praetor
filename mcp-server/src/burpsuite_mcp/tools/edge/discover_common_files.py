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
