"""Proxy control: intercept toggle + match-and-replace rules."""

from mcp.server.fastmcp import FastMCP

import json

from praetor import client
from ._helpers import _DANGEROUS_HEADER_PATTERNS

# Defaults for set_capture_hygiene — the assets/hosts that bloat a .burp project
# without ever carrying a finding. Overridable per call.
_DEFAULT_STATIC_EXTS = [
    "js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp",
    "avif", "bmp", "woff", "woff2", "ttf", "eot", "otf", "mp4", "webm", "mp3",
    "wav", "ogg", "pdf", "wasm",
]
_DEFAULT_NOISE_HOSTS = [
    "google-analytics.com", "analytics.google.com", "googletagmanager.com",
    "doubleclick.net", "google-analytics.l.google.com", "stats.g.doubleclick.net",
    "connect.facebook.net", "facebook.com", "fbcdn.net", "hotjar.com",
    "mixpanel.com", "segment.com", "segment.io", "sentry.io", "bugsnag.com",
    "newrelic.com", "nr-data.net", "cloudflareinsights.com", "gstatic.com",
    "fonts.googleapis.com", "fonts.gstatic.com", "clarity.ms", "bing.com",
]


def register(mcp: FastMCP):

    @mcp.tool()
    async def set_capture_hygiene(
        record_in_scope_only: bool = True,
        exclude_static: bool = True,
        exclude_noise: bool = True,
        static_extensions: list[str] | None = None,
        noise_hosts: list[str] | None = None,
    ) -> dict:
        """Keep the .burp project lean at CAPTURE time — exclude static assets + noise hosts from scope and request in-scope-only Proxy history.

        Burp cannot delete history or scanner issues after the fact (Montoya has
        no delete), so the only real lever is to stop recording noise. This
        excludes static-asset URLs and known analytics/tracker/CDN hosts from
        Burp scope (which also stops Praetor's own tools annotating them) and
        best-effort enables "record Proxy history only for in-scope items".

        Returns the applied rules, whether the option import succeeded, and an
        excerpt of Burp's live proxy options so you can VERIFY the effect (the
        exact project-option key varies by Burp version — if `record_only_in_scope`
        isn't reflected, flip the one-time toggle named in the response `note`).
        Scanner issues from Burp's audit + other extensions can't be deleted;
        filter them with `get_issues_dashboard` (Certain/Firm, High+).

        Args:
            record_in_scope_only: request Burp record Proxy history only for in-scope items.
            exclude_static: exclude static-asset extensions from scope.
            exclude_noise: exclude analytics/tracker/CDN hosts from scope.
            static_extensions: override the default static-extension list.
            noise_hosts: override the default noise-host list.
        """
        body = {
            "record_in_scope_only": record_in_scope_only,
            "exclude_static": exclude_static,
            "exclude_noise": exclude_noise,
            "static_extensions": static_extensions if static_extensions is not None else _DEFAULT_STATIC_EXTS,
            "noise_hosts": noise_hosts if noise_hosts is not None else _DEFAULT_NOISE_HOSTS,
        }
        data = await client.post("/api/proxy/capture-hygiene", json=body)
        if isinstance(data, dict) and "error" in data:
            return {"error": data["error"]}
        return data

    @mcp.tool()
    async def intercept(action: str = "status") -> str:
        """Control Burp proxy interception.

        Args:
            action: 'on' (enable), 'off' (disable), or 'status' (check)
        """
        a = action.lower()
        if a in ("on", "enable", "enabled"):
            data = await client.post("/api/intercept/enable")
            if "error" in data:
                return f"Error: {data['error']}"
            return "Proxy intercept ENABLED — requests will be held"
        if a in ("off", "disable", "disabled"):
            data = await client.post("/api/intercept/disable")
            if "error" in data:
                return f"Error: {data['error']}"
            return "Proxy intercept DISABLED — requests passing through"
        if a in ("status", "state", "check"):
            data = await client.get("/api/intercept/status")
            if "error" in data:
                return f"Error: {data['error']}"
            enabled = data.get("intercept_enabled", False)
            return f"Intercept is {'ENABLED' if enabled else 'DISABLED'}"
        return f"Unknown action '{action}'. Use 'on', 'off', or 'status'."

    # ── Match & Replace (collapsed) ────────────────────────────────

    @mcp.tool()
    async def match_replace(
        action: str = "list",
        rules: list[dict] | None = None,
        rule_id: int = -1,
        force: bool = False,
    ) -> str:
        """Manage Burp's match-and-replace rules.

        Args:
            action: 'set' (add rules), 'list' (show active), 'remove' (delete by rule_id), 'clear' (remove all)
            rules: For action=set — list of {type, match, replace, scope?, enabled?}
            rule_id: For action=remove — rule ID returned by 'set' or 'list'
            force: For action=set — allow dangerous header rewrites (Host, Auth, Cookie, Content-Length, Transfer-Encoding)
        """
        a = action.lower()

        if a == "set":
            if not rules:
                return "Error: action=set requires rules list"
            if not force:
                blocked = []
                for i, r in enumerate(rules):
                    match_str = str(r.get("match", "")).lower()
                    for pat in _DANGEROUS_HEADER_PATTERNS:
                        if pat in match_str:
                            blocked.append(f"rule #{i}: matches '{pat}' — set force=True to override")
                            break
                if blocked:
                    return (
                        "Refused: dangerous header rewrite detected.\n  "
                        + "\n  ".join(blocked)
                        + "\nRe-run with force=True if intentional."
                    )
            data = await client.post("/api/match-replace/add", json={"rules": rules})
            if "error" in data:
                return f"Error: {data['error']}"
            active = data.get("rules", [])
            if not active:
                return "No rules active"
            lines = [f"Active Rules ({len(active)}):"]
            lines.append(f"{'ID':<5} {'TYPE':<10} {'SCOPE':<10} MATCH → REPLACE")
            lines.append("-" * 70)
            for r in active:
                match_short = str(r.get("match", ""))[:25]
                replace_short = str(r.get("replace", ""))[:25]
                lines.append(
                    f"{r.get('id', '?'):<5} {r.get('type', '?'):<10} {r.get('scope', 'all'):<10} "
                    f"{match_short} → {replace_short}"
                )
            global_rules = [r for r in active if r.get("scope") not in ("in_scope",)]
            if global_rules:
                lines.append(f"\nWarning: {len(global_rules)} rule(s) apply to ALL traffic (not in-scope-only).")
            lines.append("Note: rules are in-memory only — Burp restart wipes them.")
            return "\n".join(lines)

        if a == "list":
            data = await client.get("/api/match-replace")
            if "error" in data:
                return f"Error: {data['error']}"
            rules_list = data.get("rules", [])
            if not rules_list:
                return "No match-replace rules active"
            lines = [f"Match-Replace Rules ({len(rules_list)}):"]
            for r in rules_list:
                status = "ON" if r.get("enabled", True) else "OFF"
                lines.append(
                    f"  [{r.get('id')}] [{status}] {r.get('type')}/{r.get('scope','all')}: "
                    f"{r.get('match', '')[:40]} → {r.get('replace', '')[:40]}"
                )
            return "\n".join(lines)

        if a == "remove":
            if rule_id < 0:
                return "Error: action=remove requires rule_id"
            data = await client.delete(f"/api/match-replace/{rule_id}")
            if "error" in data:
                return f"Error: {data['error']}"
            return f"Rule #{rule_id} removed"

        if a == "clear":
            data = await client.post("/api/match-replace/clear")
            if "error" in data:
                return f"Error: {data['error']}"
            return "All match-replace rules cleared"

        return f"Unknown action '{action}'. Use 'set', 'list', 'remove', or 'clear'."

    # ── Annotations ─────────────────────────────────────────────
