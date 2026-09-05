"""Proxy control: intercept toggle + match-and-replace rules."""

from mcp.server.fastmcp import FastMCP

import json

from praetor import client
from ._helpers import _DANGEROUS_HEADER_PATTERNS


def register(mcp: FastMCP):

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
