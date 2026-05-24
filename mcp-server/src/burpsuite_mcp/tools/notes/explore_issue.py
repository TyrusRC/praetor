"""explore_issue — class-specific follow-up probe suggestions.

Reads a saved finding, emits concrete next-probe directives (tool +
args + rationale). Pure policy table keyed by vuln_type. Operator
executes; no auto-fire.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ._helpers import _find_by_id, _load_findings_file, _safe_findings_path


_PROBES: dict[str, list[dict]] = {
    "xss": [
        {"tool": "probe_xss_executed", "rationale": "promote reflected -> EXECUTED via headless dialog hook"},
        {"tool": "test_dom_sinks", "rationale": "look for DOM-context sinks (innerHTML, eval, postMessage)"},
        {"tool": "mutate_payload", "rationale": "generate WAF-bypass variants if reflection blocked"},
    ],
    "sqli": [
        {"tool": "confirm_sqli", "rationale": "verdict via vendor error / boolean / timing oracle"},
        {"tool": "run_sqlmap", "rationale": "auto-extract DB info if oracle confirmed"},
        {"tool": "auto_collaborator_test", "rationale": "blind OOB exfil if visible oracle absent"},
    ],
    "sqli_blind": [
        {"tool": "auto_collaborator_test", "rationale": "OOB DNS exfil — only path for blind"},
        {"tool": "probe_timeless_timing", "rationale": "race-condition timing-side-channel oracle"},
    ],
    "ssrf": [
        {"tool": "test_cloud_metadata", "rationale": "AWS/GCP/Azure metadata endpoints"},
        {"tool": "confirm_ssrf", "rationale": "Collaborator callback for outbound proof"},
        {"tool": "auto_probe", "rationale": "categories=['ssrf_protocol','ssrf_bypass'] for filter-bypass surface"},
    ],
    "ssti": [
        {"tool": "confirm_ssti", "rationale": "engine-specific RCE confirmation"},
        {"tool": "auto_probe", "rationale": "categories=['ssti_python','ssti_java','ssti_js','ssti_php']"},
    ],
    "rce_detection": [
        {"tool": "confirm_rce", "rationale": "exec real command (uid/whoami) under tool-layer denylist"},
        {"tool": "auto_collaborator_test", "rationale": "OOB callback for blind RCE"},
    ],
    "xxe": [
        {"tool": "confirm_xxe", "rationale": "file-read or OOB exfil confirmation"},
        {"tool": "test_xxe", "rationale": "parameter-entity / XInclude variants"},
    ],
    "idor": [
        {"tool": "probe_id_monotonic", "rationale": "enumerate sequential/UUIDv1/Snowflake range for cross-tenant"},
        {"tool": "probe_cross_transport_idor", "rationale": "replay across REST/GraphQL/WebSocket"},
        {"tool": "test_auth_matrix", "rationale": "Subject x Object x Action matrix"},
    ],
    "mass_assignment": [
        {"tool": "test_mass_assignment", "rationale": "inject role/is_admin/price fields"},
        {"tool": "discover_hidden_parameters", "rationale": "find shadow params accepted by handler"},
    ],
    "jwt": [
        {"tool": "test_jwt", "rationale": "alg=none / kid / jku / weak-secret coverage"},
        {"tool": "crack_jwt_secret", "rationale": "HS256/384/512 dictionary crack"},
        {"tool": "forge_jwt", "rationale": "craft tampered token once weakness identified"},
    ],
    "oauth": [
        {"tool": "auto_probe", "rationale": "categories=['oauth','oauth_device_flow','oauth_dpop_confused_deputy']"},
        {"tool": "test_open_redirect", "rationale": "redirect_uri chain candidate"},
    ],
    "open_redirect": [
        {"tool": "auto_probe", "rationale": "categories=['oauth'] — chain to token theft"},
        {"tool": "test_csrf", "rationale": "chain to CSRF token replay"},
    ],
    "csrf": [
        {"tool": "test_csrf", "rationale": "verify SameSite / token absence"},
        {"tool": "test_mass_assignment", "rationale": "chain to privilege change via CSRF"},
    ],
    "cors": [
        {"tool": "test_cors", "rationale": "Origin reflection + credentials matrix"},
    ],
    "host_header": [
        {"tool": "test_host_header", "rationale": "password-reset / cache-key poisoning chain"},
        {"tool": "test_cache_poisoning", "rationale": "host-header to cache poisoning"},
    ],
    "cache_poisoning": [
        {"tool": "test_cache_poisoning", "rationale": "X-Forwarded-Host / X-Original-URL / etc."},
        {"tool": "auto_probe", "rationale": "categories=['cache_deception_v2','web_cache_deception']"},
    ],
    "request_smuggling": [
        {"tool": "test_request_smuggling", "rationale": "CL.TE / TE.CL / TE.0 / CL.0 / 0.CL variants"},
        {"tool": "auto_probe", "rationale": "categories=['http_desync'] — full 2025 family"},
    ],
    "graphql": [
        {"tool": "test_graphql", "rationale": "introspection + alias-DoS + batching"},
        {"tool": "test_mass_assignment", "rationale": "GraphQL input overreach"},
    ],
    "websocket": [
        {"tool": "test_websocket", "rationale": "CSWSH + subprotocol + handshake"},
    ],
    "prototype_pollution": [
        {"tool": "test_prototype_pollution", "rationale": "client + server-side variants"},
        {"tool": "opengrep_audit", "rationale": "static confirm via custom prototype_pollution ruleset"},
    ],
    "deserialization": [
        {"tool": "generate_deserialization_gadget", "rationale": "ysoserial-style gadget per language"},
    ],
    "race_condition": [
        {"tool": "probe_race_singlepacket", "rationale": "H2 single-packet coalesce attack"},
        {"tool": "probe_race_lastbyte", "rationale": "H1 last-byte sync"},
        {"tool": "test_race_condition", "rationale": "burst concurrency"},
    ],
    "subdomain_takeover": [
        {"tool": "test_subdomain_takeover", "rationale": "verify dangling CNAME + claim eligibility"},
    ],
    "info_disclosure": [
        {"tool": "extract_js_secrets", "rationale": "leaked secrets in disclosed JS"},
        {"tool": "discover_common_files", "rationale": "expand exposed-path coverage"},
        {"tool": "auto_probe", "rationale": "categories=['source_code_exposure']"},
    ],
}


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def explore_issue(finding_id: str, domain: str = "") -> str:
        """Suggest class-specific follow-up probes for a saved finding.

        Args:
            finding_id: persistent finding ID.
            domain: optional explicit domain. Auto-resolved if omitted.
        """
        if not domain:
            try:
                base = _safe_findings_path("")
                root = base.parent
            except Exception:
                root = None
            if root is not None and root.exists():
                for child in root.iterdir():
                    p = child / "findings.json"
                    if not p.exists():
                        continue
                    if _find_by_id(_load_findings_file(p), finding_id)[1] is not None:
                        domain = child.name
                        break
        if not domain:
            return f"Error: finding {finding_id!r} not found."

        findings = _load_findings_file(_safe_findings_path(domain))
        _, f = _find_by_id(findings, finding_id)
        if f is None:
            return f"Error: finding {finding_id!r} not found in domain {domain!r}."

        vt = (f.get("vuln_type") or "").lower()
        probes = _PROBES.get(vt, [])
        if not probes:
            return (
                f"# explore_issue — {finding_id}\n"
                f"Vuln class '{vt}' has no curated follow-up table.\n"
                f"Run auto_probe(endpoint, categories=['{vt}']) or chain via explain_finding()."
            )

        endpoint = f.get("endpoint", "")
        param = f.get("parameter", "")
        lines = [
            f"# explore_issue — {finding_id} [{vt}]",
            f"Endpoint: {endpoint}",
            f"Parameter: {param or '(none)'}",
            "",
            "## Suggested follow-up probes",
        ]
        for p in probes:
            lines.append(f"  - {p['tool']:30s}  — {p['rationale']}")
        return "\n".join(lines)
