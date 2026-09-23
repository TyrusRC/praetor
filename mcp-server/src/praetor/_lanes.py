"""Tool-lane gating — advertise only the tools a given engagement needs.

Why: a host that eager-loads every tool schema into its LLM call (dsh / Codex via
the API) pays a large share of its context window on tool definitions before any
work. Claude Code defers schemas (names-only until used) so it never pays that; other
hosts have no such mechanism. The only server-side lever is to REGISTER fewer tools.
This module
classifies every tool into a lane and lets `apply_profile` drop the lanes an
engagement is not using.

Design:
- Each tool belongs to exactly one lane, decided by the package that defined it
  (`fn.__module__`'s 3rd component), with per-tool overrides for the few packages
  that span lanes (exploit = web confirm_* + msf + mcp; redteam = network + report).
- `core` is the complement: anything not claimed by an optional lane stays on
  ALWAYS. Unclassified/new tools default to core — fail-safe (never silently hidden).
- `PRAETOR_PROFILE` selects lanes; DEFAULT `all` (every lane — zero change vs today).
  An eager-loading host (dsh) sets `PRAETOR_PROFILE=web` (or `core`/`network`/...) in
  its MCP config to shrink the manifest it sends to the model. Claude Code defers
  tool schemas, so it stays on `all` and pays nothing.

Gating NEVER blocks a workflow. A gated tool is removed from the advertised manifest
(no tokens) but kept in HIDDEN, still fully executable. The core `run_tool` dispatcher
runs any hidden tool (and fetches its schema on demand — app-layer lazy loading, the
thing dsh's client lacks), and `promote_lane` re-advertises a lane. The dsh MCP client
registers `tools/list` ONCE and ignores `notifications/tools/list_changed` (verified in
its `tools.ts`), so promotion won't surface new tools mid-session there — but `run_tool`
reaches them regardless, so nothing is ever a dead end. On Claude Code, promotion fires
`tools/list_changed` and the lane appears live.

Safety Rules 5-9 and the save-finding gate are enforced in the tool layer regardless
of which tools are advertised or hidden.
"""

from __future__ import annotations

# ---- lanes -----------------------------------------------------------------

CORE = "core"
LANES = ("web", "recon_ext", "scanners", "network", "msf", "llm", "mobile", "bench")
ALL_LANES = frozenset(LANES)

# package (fn.__module__ split('.')[2]) -> lane. Packages not listed are CORE.
_PACKAGE_LANE = {
    # web attack / test surface + Burp HTTP-interaction primitives
    "testing": "web", "testing_extended": "web", "edge": "web", "vuln": "web",
    "auth": "web", "scan": "web", "collaborate": "web", "browser": "web",
    "dom": "web", "dom_probe": "web", "dom_xss_executed": "web",
    "csp_analyzer": "web", "postmessage_probe": "web", "session": "web",
    "repeater": "web", "macro": "web", "payloads": "web", "secrets": "web",
    "analysis": "web", "harvest": "web", "bucket_urls": "web",
    "waf_bypass": "web", "clean_room_confirm": "web", "adhoc_probe": "web",
    "shadow_repeater": "web", "smart_js_analyze": "web",
    "smart_request_triage": "web", "recon": "web", "pyexploit": "web",
    "grpc_probe": "web", "saml_xsw_probe": "web", "dns_rebind_probe": "web",
    "sse_probe": "web", "http3_probe": "web", "sveltekit_probe": "web",
    "nuxt_island_probe": "web", "graphql_csrf_probe": "web",
    "struts2_ognl_probe": "web", "grpc_path_canonicalization_probe": "web",
    "fastmcp_openapi_ssrf_probe": "web", "apollo_federation_probe": "web",
    "graphql_entities_injection_probe": "web",
    "spring_grpc_thread_leak_probe": "web",
    "unicode_normalize_split_probe": "web", "bopla_probe": "web",
    "cve_variant_probe": "web", "version_delta": "web", "rre_chain_finder": "web",
    "auth_negotiate": "web",
    # infra recon CLIs (ProjectDiscovery suite)
    "recon_pd": "recon_ext",
    # SCA / IaC / cloud / k8s / CI / SAST scanners
    "sca": "scanners", "k8s_audit": "scanners", "cloud_audit": "scanners",
    "iac_scan": "scanners", "ci_audit": "scanners", "source_aware": "scanners",
    "vulnwalker": "scanners", "sast_handoff": "scanners",
    # network / AD lane
    "network": "network", "nmap_report": "network", "redteam": "network",
    # LLM / AI + MCP-security lane
    "llm_redteam": "llm", "local_llm": "llm", "web_llm_sweep": "llm",
    "nuclei_llm_infra": "llm", "mcptox": "llm", "owasp_asi_top10": "llm",
    "a2a_agent_card_probe": "llm", "mcp_enumerate": "llm",
    "mcp_jsonrpc_probe": "llm", "mcp_stdio_shell_meta_probe": "llm",
    "mcp_schema_drift": "llm", "mcp_invisible_unicode": "llm",
    "claude_code_hook_scanner": "llm", "cua_probe": "llm",
    # mobile device lane
    "mobile": "mobile",
    # AI-pentest eval harnesses (rarely used in a live engagement)
    "benchmark": "bench",
}

# per-tool overrides for packages that span lanes. tool name -> lane.
_TOOL_LANE = {
    # exploit pkg: web confirmers vs metasploit vs mcp-attack
    "confirm_rce": "web", "confirm_sqli": "web", "confirm_ssrf": "web",
    "confirm_ssti": "web", "confirm_xxe": "web", "blind_sqli_extract": "web",
    "msf_check": "msf", "msf_exploit": "msf", "msf_module_info": "msf",
    "msf_payload_gen": "msf", "msf_search": "msf", "msfrpc_login": "msf",
    "msfrpc_module_check": "msf", "msfrpc_module_execute": "msf",
    "msfrpc_module_info": "msf", "msfrpc_module_search": "msf",
    "msfrpc_version": "msf", "probe_mcp_server_attacks": "llm",
    # redteam pkg: the Ghostwriter reporting hub is core, not network
    "ghostwriter_status": CORE, "sync_to_ghostwriter": CORE,
    # recon pkg: tool-availability diagnostic is core
    "check_recon_tools": CORE,
}

# named profiles -> the optional lanes they enable (core is always on).
PROFILES = {
    "all": set(ALL_LANES),
    "core": set(),
    "web": {"web"},
    "bugbounty": {"web", "recon_ext"},
    "recon": {"web", "recon_ext"},
    "network": {"network"},
    "mobile": {"mobile"},
    "llm": {"llm"},
    "cloud": {"scanners"},
    "scanners": {"scanners"},
    "msf": {"network", "msf"},
}

DEFAULT_PROFILE = "all"


def tool_lane(name: str, module: str) -> str:
    """The lane a tool belongs to. Override wins; else package; else CORE."""
    if name in _TOOL_LANE:
        return _TOOL_LANE[name]
    parts = module.split(".")
    pkg = parts[2] if len(parts) > 2 else module
    return _PACKAGE_LANE.get(pkg, CORE)


def resolve_lanes(profile: str) -> set[str]:
    """Profile string -> enabled optional lanes (core implicit, always on).

    Accepts a named profile ('web', 'all', 'network', ...) or a comma list of
    lane names ('web,network,mobile'). Unknown tokens are ignored. Always a
    valid set; falls back to the default profile when the string is empty/bad.
    """
    s = (profile or "").strip().lower()
    if not s:
        return set(PROFILES[DEFAULT_PROFILE])
    if s in PROFILES:
        return set(PROFILES[s])
    lanes = {tok.strip() for tok in s.split(",") if tok.strip()}
    valid = lanes & ALL_LANES
    return valid or set(PROFILES[DEFAULT_PROFILE])


# set by apply_profile so a status tool can report what is live.
LAST_APPLIED: dict = {"profile": DEFAULT_PROFILE, "enabled_lanes": sorted(ALL_LANES),
                      "kept": 0, "removed": 0}

# Tools gated OUT of the manifest but kept EXECUTABLE. name -> Tool object. A gated
# tool costs no manifest tokens (not in tools/list) yet is never blocked: the core
# `run_tool` dispatcher runs it from here, and `promote_lane` can re-advertise it.
HIDDEN: dict = {}


def _lane_of(name: str, tool) -> str:
    module = getattr(getattr(tool, "fn", None), "__module__", "") or ""
    return tool_lane(name, module)


def apply_profile(mcp, profile: str) -> dict:
    """Gate tools not in `profile` OUT of the manifest — but keep them executable.

    Removed tools move to HIDDEN (still runnable via `run_tool` / re-advertisable via
    `promote_lane`), so gating shrinks the manifest without ever blocking a workflow.
    Core tools are never gated. Idempotent given the same registered set.
    """
    global LAST_APPLIED
    enabled = resolve_lanes(profile)
    tm = mcp._tool_manager
    HIDDEN.clear()
    kept = 0
    for name, tool in list(tm._tools.items()):
        lane = _lane_of(name, tool)
        if lane != CORE and lane not in enabled:
            HIDDEN[name] = tool
            tm.remove_tool(name)
        else:
            kept += 1
    LAST_APPLIED = {"profile": profile, "enabled_lanes": sorted(enabled),
                    "kept": kept, "removed": len(HIDDEN)}
    return LAST_APPLIED


def hidden_by_lane() -> dict:
    """{lane: [tool names]} for the currently-gated (hidden-but-runnable) tools."""
    out: dict = {}
    for name, tool in HIDDEN.items():
        out.setdefault(_lane_of(name, tool), []).append(name)
    for names in out.values():
        names.sort()
    return out


def promote_lane(mcp, lane: str) -> list[str]:
    """Re-advertise every hidden tool of `lane` (move it back into the manifest).

    Returns the promoted tool names. A host that honours tools/list_changed then
    sees them directly; on a host that does not, they were already reachable via
    `run_tool`, so nothing was ever blocked.
    """
    tm = mcp._tool_manager
    promoted = []
    for name, tool in list(HIDDEN.items()):
        if _lane_of(name, tool) == lane:
            tm._tools[name] = tool
            del HIDDEN[name]
            promoted.append(name)
    return promoted
