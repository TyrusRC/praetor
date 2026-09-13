"""burp_settings — single dispatcher over the Burp settings Montoya actually exposes.

Montoya (Burp's extension API) only lets an extension read/drive a subset of Burp's
settings. This tool dispatches to the SAME REST endpoints the existing scope /
proxy_control tools already use (no new Java, no new endpoints) — it is a thinner,
single-entry-point surface over `configure_scope` / `check_scope` / `get_scope` /
`intercept` / `match_replace`.

SETTABLE actions (call `praetor.client`, verbatim endpoints):
    scope_get             GET  /api/scope
    scope_check           POST /api/scope/check            {url}
    scope_add             POST /api/scope/configure         {include: urls, exclude: [],
                                                              auto_filter: False, replace: False,
                                                              keep_in_scope: [], mode}
    scope_exclude         POST /api/scope/configure         {include: [], exclude: urls,
                                                              auto_filter: False, replace: False,
                                                              keep_in_scope: [], mode}
    intercept_on          POST /api/intercept/enable
    intercept_off         POST /api/intercept/disable
    intercept_status      GET  /api/intercept/status
    match_replace_list    GET  /api/match-replace
    match_replace_add     POST /api/match-replace/add       {rules}  (dangerous-header guard —
                                                              same _DANGEROUS_HEADER_PATTERNS
                                                              check as `match_replace`; force=True
                                                              to override)
    match_replace_delete  DELETE /api/match-replace/{rule_id}
    match_replace_clear   POST /api/match-replace/clear

NOT SETTABLE via Montoya (returns a documented {"manual": ..., "montoya": False} dict;
`praetor.client` is never called, no silent error):
    proxy_listener        — Proxy > Proxy settings > Proxy listeners
    upstream_proxy        — Settings > Network > Connections > Upstream proxy servers
    tls                   — Settings > Network > TLS
    native_match_replace  — Proxy > Proxy settings > Match and replace (Burp's OWN native
                             rule table — distinct from Praetor's extension-owned
                             match_replace_* rule set, which IS settable above)
    intercept_state_read  — Proxy > Intercept (live held request/response body has no
                             Montoya getter)

Unknown action -> {"error": "unknown action '<a>' — see docstring for the supported set"}
"""

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools._scope_mode import set_mode
from praetor.tools.proxy_control._config import _DANGEROUS_HEADER_PATTERNS

_MANUAL: dict[str, str] = {
    "proxy_listener": (
        "proxy_listener: Burp's Montoya API has no setter for the proxy listener "
        "bind address/port — configure it in the Burp UI: Proxy > Proxy settings > "
        "Proxy listeners"
    ),
    "upstream_proxy": (
        "upstream_proxy: Burp's Montoya API has no setter for upstream proxy "
        "chaining — configure it in the Burp UI: Settings > Network > Connections > "
        "Upstream proxy servers"
    ),
    "tls": (
        "tls: Burp's Montoya API has no setter for TLS/SSL pass-through or client "
        "certificate configuration — configure it in the Burp UI: Settings > "
        "Network > TLS"
    ),
    "native_match_replace": (
        "native_match_replace: Burp's Montoya API cannot read or write Burp's own "
        "native Proxy > Match and replace rule table (Praetor's match_replace_* "
        "actions manage a separate, extension-owned rule set, not this table) — "
        "configure it in the Burp UI: Proxy > Proxy settings > Match and replace"
    ),
    "intercept_state_read": (
        "intercept_state_read: Burp's Montoya API has no getter for the live "
        "contents of a currently-intercepted (held) request/response — inspect it "
        "in the Burp UI: Proxy > Intercept"
    ),
}


def register(mcp: FastMCP):

    @mcp.tool()
    async def burp_settings(
        action: str,
        urls: list[str] | None = None,
        url: str = "",
        rules: list[dict] | None = None,
        rule_id: str = "",
        force: bool = False,
        mode: str = "operator",
    ) -> dict:
        """Control Burp settings actually exposed by Montoya, dispatched by `action`.

        Settable (routed to the same REST endpoints as configure_scope/check_scope/
        get_scope/intercept/match_replace — see module docstring for exact
        endpoints/payloads): scope_get, scope_check, scope_add, scope_exclude,
        intercept_on, intercept_off, intercept_status, match_replace_list,
        match_replace_add, match_replace_delete, match_replace_clear.

        Not settable via Montoya — returns {"manual": "...", "montoya": False}
        naming the Burp UI location, WITHOUT calling the extension: proxy_listener,
        upstream_proxy, tls, native_match_replace, intercept_state_read.

        Args:
            action: one of the actions listed above.
            urls: full URLs — used by scope_add (as include) / scope_exclude (as exclude).
            url: single URL — used by scope_check.
            rules: list of {type, match, replace, scope?, enabled?} — used by match_replace_add.
            rule_id: rule id — used by match_replace_delete.
            force: match_replace_add only — allow a rule matching a dangerous header
                pattern (Host/Authorization/Cookie/Content-Length/Transfer-Encoding).
            mode: 'operator' (default, warn-and-log) or 'strict' (hard-block) —
                used by scope_add / scope_exclude (see `configure_scope`).
        """
        a = action.lower()

        if a == "scope_get":
            data = await client.get("/api/scope")
            if "error" in data:
                return {"error": data["error"]}
            return data

        if a == "scope_check":
            if not url:
                return {"error": "scope_check requires url"}
            data = await client.post("/api/scope/check", json={"url": url})
            if "error" in data:
                return {"error": data["error"]}
            return data

        if a in ("scope_add", "scope_exclude"):
            try:
                set_mode(mode)
            except ValueError as e:
                return {"error": str(e)}
            payload = {
                "include": (urls or []) if a == "scope_add" else [],
                "exclude": (urls or []) if a == "scope_exclude" else [],
                "auto_filter": False,
                "replace": False,
                "keep_in_scope": [],
                "mode": mode,
            }
            data = await client.post("/api/scope/configure", json=payload)
            if "error" in data:
                return {"error": data["error"]}
            return data

        if a == "intercept_on":
            data = await client.post("/api/intercept/enable")
            if "error" in data:
                return {"error": data["error"]}
            return data

        if a == "intercept_off":
            data = await client.post("/api/intercept/disable")
            if "error" in data:
                return {"error": data["error"]}
            return data

        if a == "intercept_status":
            data = await client.get("/api/intercept/status")
            if "error" in data:
                return {"error": data["error"]}
            return data

        if a == "match_replace_list":
            data = await client.get("/api/match-replace")
            if "error" in data:
                return {"error": data["error"]}
            return data

        if a == "match_replace_delete":
            if not rule_id:
                return {"error": "match_replace_delete requires rule_id"}
            data = await client.delete(f"/api/match-replace/{rule_id}")
            if "error" in data:
                return {"error": data["error"]}
            return data

        if a == "match_replace_clear":
            data = await client.post("/api/match-replace/clear")
            if "error" in data:
                return {"error": data["error"]}
            return data

        if a == "match_replace_add":
            if not rules:
                return {"error": "match_replace_add requires rules list"}
            if not force:
                blocked = []
                for i, r in enumerate(rules):
                    match_str = str(r.get("match", "")).lower()
                    for pat in _DANGEROUS_HEADER_PATTERNS:
                        if pat in match_str:
                            blocked.append(
                                f"rule #{i}: matches '{pat}' — set force=True to override"
                            )
                            break
                if blocked:
                    return {
                        "error": (
                            "Refused: dangerous header rewrite detected. "
                            + "; ".join(blocked)
                            + " Re-run with force=True if intentional."
                        )
                    }
            data = await client.post("/api/match-replace/add", json={"rules": rules})
            if "error" in data:
                return {"error": data["error"]}
            return data

        if a in _MANUAL:
            return {"manual": _MANUAL[a], "montoya": False}

        return {"error": f"unknown action '{action}' — see docstring for the supported set"}
