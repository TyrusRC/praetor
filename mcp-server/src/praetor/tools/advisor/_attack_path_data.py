"""Capability model for plan_attack_paths — the search space, data only.

Complements `propose_chains` (a fixed 16-rule progression matcher). This models
findings as *capabilities gained*, and attacker escalation as *transitions*
between capability sets, so a beam search can discover multi-hop kill-chains the
rulebook never enumerated — and, crucially, name the ONE capability a near-miss
path is missing (the next proof to obtain).

Tokens are internal capability names, not vuln_types. `_CLASS_GRANTS` is the
only bridge from a finding's vuln_type to the capability space.
"""

from __future__ import annotations

# vuln_type substring -> capabilities the confirmed finding grants.
# Substring match (so `sqli_blind`, `ssrf_protocol` resolve to their parent).
_CLASS_GRANTS: dict[str, list[str]] = {
    "ssrf": ["internal_reach"],
    "xxe": ["internal_reach", "file_read"],
    "cloud_metadata": ["imds_reach"],
    "cloud_imds": ["imds_reach"],
    "open_redirect": ["controlled_landing"],
    "oauth": ["oauth_flow_control"],
    "saml": ["token_forge_surface"],
    "jwt": ["token_forge_surface"],
    "xss": ["js_exec_victim"],
    "dom_xss": ["js_exec_victim"],
    "csrf": ["forced_request"],
    "idor": ["cross_object_read"],
    "bola": ["cross_object_read"],
    "id_enumeration": ["enumeration"],
    "id_monotonic": ["enumeration"],
    "auth_bypass": ["authz_bypass"],
    "broken_access": ["authz_bypass"],
    "access_control": ["authz_bypass"],
    "mass_assignment": ["privileged_write"],
    "subdomain_takeover": ["subdomain_control"],
    "prototype_pollution": ["proto_gadget"],
    "cspp": ["proto_gadget"],
    "sspp": ["server_gadget"],
    "request_smuggling": ["frontend_acl_bypass"],
    "http_desync": ["frontend_acl_bypass"],
    "parser_differential": ["frontend_acl_bypass"],
    "cache_poisoning": ["cache_control"],
    "web_cache_deception": ["cache_control"],
    "host_header": ["host_injection"],
    "info_disclosure": ["internal_intel"],
    "stack_trace": ["internal_intel"],
    "verbose_error": ["internal_intel"],
    "source_code_exposure": ["internal_intel"],
    "sqli": ["db_read"],
    "nosql": ["db_read"],
    "file_upload": ["upload_surface"],
    "lfi": ["file_read"],
    "path_traversal": ["file_read"],
    "graphql": ["schema_intel"],
    "session_fixation": ["session_control"],
    "cookie_scope": ["session_control"],
    # Terminal-class findings: grant the objective capability directly.
    "rce": ["code_exec"],
    "command_injection": ["code_exec"],
    "deserialization": ["code_exec"],
    "ssti": ["code_exec"],
}

# Escalation edges: (preconditions, capability_gained, uplift, ATT&CK id, human,
# severed_by). `uplift` (0..1) is the confidence that the escalation succeeds — it
# multiplies the chain score. Preconditions are ANDed; a transition fires only when
# every precondition capability is already held. `severed_by` names the ONE
# defensive control token (see `_CONTROLS`) that breaks THIS hop's precondition:
# deploying it cuts every kill-chain routed through this edge, so the earliest
# severable edge is the cheapest remediation. (Mirrors the pcybox-attackgraph
# "controls break preconditions" model, applied to real confirmed findings.)
_TRANSITIONS: list[tuple[frozenset[str], str, float, str, str, str]] = [
    (frozenset({"internal_reach"}), "imds_reach", 0.7, "T1046",
     "pivot internal reach to the 169.254.169.254 cloud metadata endpoint",
     "segmentation"),
    (frozenset({"imds_reach"}), "cloud_creds", 0.9, "T1552.005",
     "read IAM role credentials from the metadata service",
     "imds_hardening"),
    (frozenset({"internal_reach"}), "internal_intel", 0.5, "T1046",
     "enumerate internal-only services reachable from the SSRF sink",
     "segmentation"),
    (frozenset({"controlled_landing", "oauth_flow_control"}), "token_theft", 0.8, "T1539",
     "leak the OAuth code/token to a controlled origin via the open redirect",
     "redirect_allowlist"),
    (frozenset({"token_theft"}), "ato", 0.95, "T1078",
     "replay the stolen token to seize the account",
     "token_binding"),
    (frozenset({"token_forge_surface"}), "authz_bypass", 0.8, "T1550.001",
     "forge a JWT/SAML assertion (alg=none / key confusion / XSW)",
     "signature_validation"),
    (frozenset({"authz_bypass"}), "ato", 0.7, "T1078",
     "use the forged privileged identity to take over the account",
     "authz_enforcement"),
    (frozenset({"js_exec_victim", "forced_request"}), "admin_action", 0.85, "T1059.007",
     "XSS defeats SameSite so CSRF forces a privileged action under the victim session",
     "input_validation"),
    (frozenset({"js_exec_victim"}), "session_theft", 0.7, "T1539",
     "exfiltrate the victim session/token through the XSS sink",
     "input_validation"),
    (frozenset({"session_theft"}), "ato", 0.9, "T1078",
     "replay the stolen session to take over the account",
     "token_binding"),
    (frozenset({"cross_object_read", "enumeration"}), "mass_pii", 0.85, "T1213",
     "IDOR over a predictable id space yields bulk cross-tenant PII",
     "authz_enforcement"),
    (frozenset({"authz_bypass", "enumeration"}), "mass_pii", 0.8, "T1213",
     "auth-bypassed collection endpoint plus predictable ids = wholesale data theft",
     "authz_enforcement"),
    (frozenset({"proto_gadget"}), "js_exec_victim", 0.75, "T1059.007",
     "prototype pollution reaches a DOM sink, becoming executable XSS",
     "input_validation"),
    (frozenset({"server_gadget"}), "code_exec", 0.85, "T1190",
     "server-side prototype pollution gadget reaches a sink -> RCE",
     "input_validation"),
    (frozenset({"frontend_acl_bypass"}), "authz_bypass", 0.8, "T1190",
     "smuggling / parser differential slips past the front-end ACL",
     "request_normalization"),
    (frozenset({"frontend_acl_bypass"}), "internal_intel", 0.6, "T1190",
     "desync routes a request to an internal-only backend route",
     "request_normalization"),
    (frozenset({"cache_control", "js_exec_victim"}), "mass_victim", 0.75, "T1189",
     "poisoned shared cache serves the XSS payload to every visitor",
     "cache_key_hygiene"),
    (frozenset({"host_injection"}), "cache_control", 0.6, "T1190",
     "host-header injection lands in a cache key, enabling poisoning",
     "host_validation"),
    (frozenset({"subdomain_control"}), "session_control", 0.7, "T1584.001",
     "a taken-over subdomain inherits parent-scoped cookies",
     "dns_hygiene"),
    (frozenset({"session_control"}), "ato", 0.85, "T1078",
     "fixed/inherited session is promoted to victim login -> takeover",
     "session_management"),
    (frozenset({"file_read"}), "internal_intel", 0.6, "T1552.001",
     "read config/secrets off disk (env, credentials, keys)",
     "secrets_management"),
    (frozenset({"internal_intel"}), "cross_object_read", 0.4, "T1213",
     "leaked internal identifiers seed IDOR victim enumeration",
     "authz_enforcement"),
    (frozenset({"upload_surface"}), "code_exec", 0.7, "T1505.003",
     "upload a web shell through the unrestricted file upload -> RCE",
     "upload_restriction"),
    (frozenset({"schema_intel"}), "cross_object_read", 0.5, "T1213",
     "GraphQL introspection exposes types enabling BOLA on field resolvers",
     "authz_enforcement"),
    (frozenset({"db_read"}), "internal_intel", 0.5, "T1213",
     "SQL read dumps schema/rows revealing further attack surface",
     "parameterized_queries"),
]

# Objective capability -> (severity, base value 0..100, human name).
_OBJECTIVES: dict[str, tuple[str, int, str]] = {
    "code_exec": ("critical", 100, "Remote code execution"),
    "cloud_creds": ("critical", 98, "Cloud IAM credential theft"),
    "ato": ("critical", 95, "Account takeover"),
    "admin_action": ("critical", 90, "Forced privileged/admin action"),
    "mass_pii": ("high", 85, "Bulk / cross-tenant PII exposure"),
    "mass_victim": ("high", 80, "Mass stored/cache victim impact"),
}

# Human-readable label for every capability token (for output legibility).
_CAP_HUMAN: dict[str, str] = {
    "internal_reach": "internal network reach",
    "imds_reach": "cloud metadata (IMDS) reach",
    "cloud_creds": "cloud IAM credentials",
    "controlled_landing": "attacker-controlled landing origin",
    "oauth_flow_control": "influence over the OAuth flow",
    "token_forge_surface": "a forgeable token/assertion",
    "token_theft": "a stolen OAuth token",
    "js_exec_victim": "JS execution in a victim context",
    "forced_request": "forced cross-site request",
    "cross_object_read": "cross-object read (IDOR/BOLA)",
    "enumeration": "predictable-id enumeration",
    "authz_bypass": "authorization bypass",
    "privileged_write": "privileged mass-assignment write",
    "subdomain_control": "control of an in-scope subdomain",
    "proto_gadget": "a client-side prototype-pollution gadget",
    "server_gadget": "a server-side pollution gadget",
    "frontend_acl_bypass": "front-end ACL bypass (desync)",
    "cache_control": "control over a shared cache entry",
    "host_injection": "host-header injection",
    "internal_intel": "internal intelligence (paths/ids/secrets)",
    "db_read": "database read",
    "upload_surface": "an unrestricted upload surface",
    "file_read": "arbitrary file read",
    "schema_intel": "API schema intelligence",
    "session_control": "session fixation/inheritance",
    "session_theft": "a stolen victim session",
    "admin_action": "a forced admin action",
    "mass_pii": "bulk PII exposure",
    "mass_victim": "mass victim impact",
    "code_exec": "code execution",
}

# Defensive control token -> the remediation that severs the edges tagged with it.
# One control per `_TRANSITIONS` edge; deploying it breaks that hop's precondition
# and cuts every kill-chain through the edge. Phrased as report-ready guidance.
_CONTROLS: dict[str, str] = {
    "segmentation":
        "network segmentation / egress filtering to link-local (169.254.0.0/16) and internal ranges",
    "imds_hardening":
        "enforce IMDSv2 (token + hop-limit) and scope the instance IAM role to least privilege",
    "redirect_allowlist":
        "exact-match allow-list for OAuth redirect_uri / redirect targets — no wildcards or prefix checks",
    "token_binding":
        "short-lived, sender-constrained tokens (DPoP / mTLS) so a stolen token cannot be replayed",
    "signature_validation":
        "verify token signatures — reject alg=none, pin the signing key, harden against SAML XSW",
    "authz_enforcement":
        "server-side object-level authorization on every access, deny-by-default (fixes IDOR/BOLA/BFLA)",
    "input_validation":
        "context-aware output encoding + CSP to neutralize the injection/XSS sink at the boundary",
    "request_normalization":
        "normalize requests at the edge so front-end and back-end parse them identically (kills desync)",
    "cache_key_hygiene":
        "include every request-influencing header in the cache key; never cache attacker-influenced responses",
    "host_validation":
        "validate the Host header against an allow-list of expected hostnames",
    "dns_hygiene":
        "decommission dangling DNS records; scope cookies host-only rather than to the parent domain",
    "session_management":
        "rotate the session id on authentication and reject client-supplied session identifiers",
    "secrets_management":
        "keep secrets out of the web root/filesystem; least-privilege file permissions on config",
    "upload_restriction":
        "restrict upload type/extension, store outside the web root, and disable execution on the upload path",
    "parameterized_queries":
        "parameterized queries / prepared statements to remove the SQL injection at source",
}
