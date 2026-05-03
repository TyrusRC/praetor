"""full_recon — multi-step recon pipeline (tech / endpoints / secrets / sensitive files)."""

import asyncio

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.analyze import _score_security_headers

from ._helpers import _classify_param_risk


# Sensitive-paths list lifted to module scope so it's allocated once, not per call.
_SENSITIVE_PATHS = [
    # Version control
    "/.git/HEAD", "/.git/config", "/.git/index", "/.git/logs/HEAD",
    "/.gitignore", "/.gitattributes",
    "/.svn/entries", "/.svn/wc.db", "/.hg/store",
    # Env / secrets
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.env.staging", "/.env.test", "/.env.backup", "/.env.sample",
    "/config.json", "/config.yml", "/config.yaml", "/secrets.json",
    "/credentials.json", "/credentials.yml",
    # Cloud credentials
    "/.aws/credentials", "/.aws/config", "/.azure/credentials",
    "/.gcp/credentials.json", "/serviceaccount.json",
    "/.s3cfg", "/.boto", "/.npmrc", "/.pypirc", "/.netrc",
    "/.docker/config.json", "/kube/config", "/.kube/config",
    # Server config
    "/.htaccess", "/.htpasswd", "/web.config", "/web.xml",
    "/server.xml", "/context.xml", "/wp-config.php", "/wp-config.bak",
    "/config.php", "/config.inc.php", "/configuration.php",
    # Lock / manifest files (version disclosure for CVE matching)
    "/composer.json", "/composer.lock", "/package.json",
    "/package-lock.json", "/yarn.lock", "/Gemfile", "/Gemfile.lock",
    "/Pipfile", "/Pipfile.lock", "/poetry.lock", "/requirements.txt",
    "/go.mod", "/go.sum", "/Cargo.toml", "/Cargo.lock",
    "/pom.xml", "/build.gradle", "/settings.gradle",
    # Backups
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql",
    "/database.sql", "/db.sqlite", "/db.sqlite3", "/site.bak",
    # API docs
    "/swagger.json", "/swagger/v1/swagger.json", "/api-docs",
    "/api-docs.json", "/openapi.json", "/openapi.yaml",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/api-docs",
    "/graphql/schema.json", "/graphql.json", "/_graphql",
    # Framework actuators / debug
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/actuator", "/actuator/env", "/actuator/heapdump",
    "/actuator/health", "/actuator/mappings", "/actuator/configprops",
    "/actuator/loggers", "/actuator/threaddump",
    "/server-status", "/server-info", "/status",
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    # Editor / IDE artifacts
    "/.DS_Store", "/Thumbs.db", "/desktop.ini",
    "/.idea/workspace.xml", "/.vscode/settings.json",
    # CI / deployment
    "/.travis.yml", "/.gitlab-ci.yml", "/.circleci/config.yml",
    "/Jenkinsfile", "/azure-pipelines.yml", "/.github/workflows/",
    # Common admin
    "/admin", "/administrator", "/manager/html", "/console",
    "/robots.txt", "/sitemap.xml", "/security.txt", "/humans.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
]


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def full_recon(  # cost: expensive
        session: str,
        depth: str = "standard",
    ) -> str:
        """Full recon pipeline: tech detection, endpoints, headers, secrets, robots.txt, sensitive files.

        Args:
            session: Session name with base_url configured
            depth: 'quick', 'standard', or 'deep'
        """
        lines = [f"FULL RECON (depth: {depth})\n"]

        root_req: dict = {"session": session, "method": "GET", "path": "/", "analyze": True}
        root_resp = await client.post("/api/session/request", json=root_req)
        if "error" in root_resp:
            return f"Error: {root_resp['error']}"

        root_index = root_resp.get("proxy_index", -1)
        analysis = root_resp.get("analysis", {})

        techs = analysis.get("tech_stack", {}).get("technologies", [])
        if techs:
            lines.append(f"TECH STACK: {', '.join(techs)}")

        present = []
        missing = []
        sec_headers = analysis.get("tech_stack", {}).get("security_headers", {})
        for h, v in sec_headers.items():
            (present if v else missing).append(h)

        lines.append(_score_security_headers(present, missing))

        ep_data = await client.get("/api/analysis/unique-endpoints", params={"limit": "100"})
        endpoints = ep_data.get("endpoints", []) if "error" not in ep_data else []
        lines.append(f"\nENDPOINTS: {len(endpoints)} unique")
        for ep in endpoints[:15]:
            params = ep.get("parameters", [])
            param_names = [p.get("name", "?") if isinstance(p, dict) else str(p) for p in params]
            param_str = f" (params: {', '.join(param_names)})" if param_names else ""
            lines.append(f"  [{ep.get('status_code', '?')}] {ep.get('endpoint', '?')}{param_str}")
        if len(endpoints) > 15:
            lines.append(
                f"  ... and {len(endpoints) - 15} more "
                f"[TRUNCATED for token budget; re-run with priority='remaining' to cover the rest]"
            )

        if depth in ("standard", "deep"):
            if root_index >= 0:
                page_res = await client.post("/api/resources/fetch-page", json={"index": root_index})
                if "error" not in page_res:
                    fetched = page_res.get("fetched", [])
                    js_secrets = []
                    for res in fetched[:5]:
                        idx = res.get("proxy_index", -1)
                        if idx >= 0 and res.get("url", "").endswith(".js"):
                            sec_data = await client.post("/api/analysis/js-secrets", json={"index": idx})
                            if "error" not in sec_data:
                                for s in sec_data.get("secrets", []):
                                    js_secrets.append(s)

                    if js_secrets:
                        lines.append(f"\nJS SECRETS: {len(js_secrets)} found")
                        for s in js_secrets[:10]:
                            lines.append(f"  [{s.get('severity', '?')}] {s.get('type', '?')}: {s.get('match', '?')[:60]}")

            robots = await client.post("/api/session/request", json={
                "session": session, "method": "GET", "path": "/robots.txt",
            })
            if "error" not in robots and robots.get("status") == 200:
                body = robots.get("response_body", "")
                disallowed = [l.split(":", 1)[1].strip() for l in body.split("\n")
                              if l.lower().startswith("disallow:") and l.split(":", 1)[1].strip()]
                if disallowed:
                    lines.append(f"\nROBOTS.TXT: {len(disallowed)} disallowed")
                    for d in disallowed[:10]:
                        lines.append(f"  {d}")

        if depth == "deep":
            # Parallel sensitive-paths probe in chunks of 10. Sequential
            # was 30-60s wall-clock; chunked gather drops it to ~5s.
            found_files: list[str] = []

            async def _probe(sp: str):
                r = await client.post("/api/session/request", json={
                    "session": session, "method": "GET", "path": sp,
                })
                return sp, r

            CHUNK = 10
            for i in range(0, len(_SENSITIVE_PATHS), CHUNK):
                chunk = _SENSITIVE_PATHS[i:i + CHUNK]
                results = await asyncio.gather(*(_probe(sp) for sp in chunk), return_exceptions=True)
                for item in results:
                    if isinstance(item, Exception):
                        continue
                    sp, resp = item
                    if "error" in resp:
                        continue
                    status = resp.get("status", 0)
                    length = resp.get("response_length", 0)
                    if status == 200 and length > 0:
                        found_files.append(f"{sp} ({length}B)")
                    elif status == 403:
                        found_files.append(f"{sp} (403 - exists but blocked)")

            if found_files:
                lines.append(f"\nSENSITIVE FILES: {len(found_files)} found")
                for f in found_files:
                    lines.append(f"  {f}")

        priorities = []
        for ep in endpoints:
            ep_risks = set()
            for p in ep.get("parameters", []):
                pname = p.get("name", "") if isinstance(p, dict) else str(p)
                risks = _classify_param_risk(pname)
                ep_risks.update(risks)
            if ep_risks:
                priorities.append((ep, sorted(ep_risks)))

        if priorities:
            lines.append("\nATTACK PRIORITIES:")
            for i, (ep, risks) in enumerate(priorities[:10], 1):
                lines.append(f"  {i}. {ep.get('endpoint', '?')} -> {', '.join(risks)}")
            if len(priorities) > 10:
                lines.append(
                    f"  [+{len(priorities) - 10} more priorities truncated; "
                    f"call again or use load_target_intel(domain, 'endpoints', limit=N, offset=10)]"
                )

        return "\n".join(lines)
