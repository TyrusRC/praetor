"""Alias map + fuzzy-resolver strip suffixes for the framework lookup table."""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Aliases: variant vuln_type -> canonical key in FRAMEWORK_MAP.
# ---------------------------------------------------------------------------
_ALIASES: dict[str, str] = {
    "rce_detection": "rce",
    "command_execution": "command_injection",
    "cmdi": "command_injection",
    "os_command_injection": "command_injection",
    "insecure_deserialization": "deserialization",
    "sql_injection": "sqli",
    "blind_sqli": "sqli",
    "reflected_xss": "xss",
    "stored_xss": "xss",
    "cross_site_scripting": "xss",
    "lfi": "path_traversal",
    "rfi": "path_traversal",
    "directory_traversal": "path_traversal",
    "hpp": "parameter_pollution",
    "http_parameter_pollution": "parameter_pollution",
    "http_desync": "request_smuggling",
    "smuggling": "request_smuggling",
    "cswsh": "websocket",
    "ws_no_auth": "websocket",
    "ws_token_in_url": "websocket",
    "csp_missing": "info_disclosure",
    "csp_misconfig": "cors",
    "dom_security_signals": "dom_xss",
    "authentication": "auth_bypass",
    "login_bypass": "auth_bypass",
    "saml_xsw": "saml",
    "webauthn_passkey": "auth_bypass",
    "passkey_stepup_bypass": "mfa_bypass",
    "oauth_chain_attacks": "oauth",
    "trpc_sspp": "prototype_pollution",
    "nextjs_cache_poisoning": "cache_poisoning",
    "state_machine_race": "race_condition",
    "stale_privilege": "access_control",
    "bola": "idor",
    "bopla": "idor",
    "bfla": "access_control",
    "grpc_idor": "idor",
    "cross_transport_idor": "idor",
    "nosql_injection": "nosql",
    "mongodb_injection": "nosql",
    "graphql_csrf": "csrf",
    "graphql_entities_injection": "graphql",
    "postmessage": "postmessage_listener",
    "rag_injection": "ai_prompt_injection",
    "web_llm": "ai_prompt_injection",
    "local_llm_prompt_injection": "ai_prompt_injection",
    "weak_token_generation": "crypto_weakness",
    "payment_flow": "business_logic",
    "webhook_replay": "business_logic",
    "id_enumeration": "idor",
}

# Suffixes stripped by the fuzzy resolver (order matters — longest first).
_STRIP_SUFFIXES = (
    "_detection", "_confirm", "_probe", "_blind", "_time", "_timing",
    "_v2", "_check", "_test", "_scan", "_bypass", "_injection", "_attack",
    "_attacks", "_leak", "_misconfig",
)
