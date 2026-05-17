"""probe_cron_backfill — auth-less scheduled-job / webhook / backfill endpoints.

Premise: backend cron jobs / webhooks / backfill tasks often hit /jobs/run,
/cron/*, /tasks/*, /admin/jobs/*, /webhooks/*, /internal/queue/* without
request-time auth — relying instead on "only the scheduler hits this" or
internal-network trust. From outside, hitting these endpoints can:

  - Trigger arbitrary jobs (mass-mail, password resets, backfills)
  - Bypass rate-limits (job runs as a service principal)
  - Read internal queue state
  - Force-process pending workflows

Strix-derived. Pure black-box recon.
"""

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


_PATH_PATTERNS = [
    # Generic
    "/jobs", "/jobs/run", "/jobs/trigger", "/jobs/execute",
    "/cron", "/cron/run", "/cron/trigger", "/cron/heartbeat",
    "/tasks", "/tasks/run", "/tasks/execute", "/tasks/trigger",
    "/queue/process", "/queue/pop", "/queue/peek",
    "/webhooks/run", "/webhooks/replay", "/webhooks/trigger",
    "/scheduler/run", "/scheduler/trigger", "/scheduler/heartbeat",
    "/backfill", "/backfill/run", "/backfill/trigger",
    "/_jobs", "/_cron", "/_tasks",
    # Common platform paths
    "/_ah/start", "/_ah/cron",  # App Engine
    "/cron.php",  # PHP
    "/healthcheck/cron", "/api/cron",
    "/api/jobs/run", "/api/jobs/trigger",
    "/api/cron/run", "/api/scheduler/run",
    "/internal/jobs", "/internal/cron", "/internal/queue",
    "/admin/jobs/run", "/admin/cron/run", "/admin/tasks/run",
    "/admin/queue/process", "/admin/backfill",
    # Sidekiq / Resque / Hangfire / Quartz
    "/sidekiq", "/resque", "/hangfire", "/quartz",
    "/sidekiq/queues", "/sidekiq/scheduled",
    # Common webhook endpoints
    "/webhook/github", "/webhook/stripe", "/webhook/sendgrid", "/webhook/slack",
    "/hooks/incoming",
    # Specific framework patterns
    "/django-q/", "/django-rq/",
    "/celery/inspect", "/celery/heartbeat",
    "/.well-known/cron",
]


_INTERNAL_TRUST_HEADERS = [
    {"X-Cron-Token": "internal"},
    {"X-Job-Token": "internal"},
    {"X-Scheduler-Token": "1"},
    {"X-Internal-Request": "true"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-Ip": "127.0.0.1"},
    {"X-Appengine-Cron": "true"},
    {"X-Cloudscheduler": "true"},
    {"User-Agent": "Google-Cron"},
    {"User-Agent": "AppEngine-Google; (+http://code.google.com/appengine; appid: s~example)"},
    {"User-Agent": "Sidekiq"},
]


def register(mcp: FastMCP):

    @mcp.tool()
    async def probe_cron_backfill(
        base_url: str,
        session: str = "",
        custom_paths: list[str] | None = None,
        trigger_methods: list[str] | None = None,
    ) -> str:
        """Probe common scheduled-job / webhook / backfill paths for auth-less exposure.

        Args:
            base_url: Target base URL (e.g. https://api.example.com).
            session: Optional auth session (use unauthenticated for max signal — leave empty).
            custom_paths: Extra paths to test alongside the built-in list.
            trigger_methods: Methods to test (default: GET, POST).

        Reports endpoints that respond with 2xx without auth. Each finding requires
        manual verification — a /jobs endpoint that returns 200 may be a noop
        listing or a real trigger. Inspect response body before claiming impact.
        """
        if trigger_methods is None:
            trigger_methods = ["GET", "POST"]
        paths = list(_PATH_PATTERNS) + (custom_paths or [])

        if base_url.endswith("/"):
            base_url = base_url[:-1]

        # Scope check
        scope_res = await client.check_scope(base_url + "/")
        if "error" in scope_res:
            return f"Error: scope check failed: {scope_res['error']}"
        if not scope_res.get("in_scope", False):
            return f"Error: {base_url} not in scope"

        lines = [f"probe_cron_backfill base_url={base_url}", f"Testing {len(paths)} paths × {len(trigger_methods)} methods", ""]
        findings: list[dict] = []

        async def _send(path: str, method: str, headers: dict, body: str = "{}") -> dict:
            target_url = base_url + path
            if session:
                return await client.post("/api/session/request", json={
                    "session": session, "method": method, "path": path,
                    "headers": headers,
                    "body": body if method != "GET" else "",
                })
            return await client.post("/api/http/curl", json={
                "method": method, "url": target_url,
                "headers": headers,
                "body": body if method != "GET" else "",
            })

        for path in paths:
            for method in trigger_methods:
                # Pass 1: clean
                r = await _send(path, method, {"Content-Type": "application/json"})
                if "error" in r:
                    continue
                s = r.get("status", 0) or r.get("status_code", 0)
                body = r.get("response_body", "") or r.get("body", "")
                if 200 <= s < 300:
                    findings.append({
                        "path": path, "method": method, "headers": "clean",
                        "status": s, "length": len(body),
                        "preview": body[:120].replace("\n", " "),
                    })
                    lines.append(f"  [!] {method} {path} -> {s} (clean, len={len(body)})")
                    continue
                # Skip 401/403/404 quickly; only retry with trust headers on suggestive statuses (405/415/500)
                if s not in (405, 415, 500):
                    continue
                # Pass 2: try internal-trust headers
                for ih in _INTERNAL_TRUST_HEADERS:
                    headers = {"Content-Type": "application/json", **ih}
                    r2 = await _send(path, method, headers)
                    if "error" in r2:
                        continue
                    s2 = r2.get("status", 0) or r2.get("status_code", 0)
                    body2 = r2.get("response_body", "") or r2.get("body", "")
                    if 200 <= s2 < 300:
                        header_key = list(ih.keys())[0]
                        findings.append({
                            "path": path, "method": method,
                            "headers": f"trust:{header_key}={ih[header_key]}",
                            "status": s2, "length": len(body2),
                            "preview": body2[:120].replace("\n", " "),
                        })
                        lines.append(f"  [!] {method} {path} -> {s2} (header bypass via {header_key}, len={len(body2)})")
                        break

        lines.append("\n--- Summary ---")
        if findings:
            lines.append(f"AUTH-LESS / TRUST-BYPASSABLE: {len(findings)} endpoints")
            for f in findings[:30]:
                lines.append(f"  {f['method']} {f['path']} status={f['status']} ({f['headers']}) len={f['length']}")
                if f["preview"]:
                    lines.append(f"    > {f['preview']}")
            if len(findings) > 30:
                lines.append(f"  ... +{len(findings)-30} more ...")
            lines.append("\nRisk: scheduled-job / webhook / queue endpoints exposed. Verify side effects (job triggered? queue popped?). Many of these are MEDIUM severity standalone, HIGH when chained with mass-mail / privilege actions.")
        else:
            lines.append("No auth-less scheduled-job endpoints detected.")
        return "\n".join(lines)
