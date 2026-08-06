"""One vocabulary for vulnerability class names.

Each gate grew its own spelling of the same class. The report layer capped
`open_redirect`; the NEVER-SUBMIT gate guarded `open_redirect_no_chain`; the
CVSS defaults knew `lfi` but not `path_traversal`; Q5 knew `xss` but not
`xss_reflected`. A gate that keys on a name nobody passes is a gate that never
fires, and 15 classes the report treats as ineligible were sailing through Q6 on
spelling alone.

`canonical()` collapses the spellings so every gate asks the same question.
Aliases are added here, never by giving a second gate its own list.
"""

from __future__ import annotations

# alias -> canonical class. The canonical name is whichever spelling the
# NEVER-SUBMIT / severity-cap tables already key on, so existing entries keep
# working and the Java FindingsStore parity comment stays true.
_ALIASES: dict[str, str] = {
    # Missing security headers — all one ineligible class.
    "missing_security_header": "missing_headers",
    "missing_security_headers": "missing_headers",
    "missing_csp": "missing_headers",
    "missing_hsts": "missing_headers",
    "missing_x_frame_options": "missing_headers",
    "missing_xfo": "missing_headers",
    "csp_missing": "missing_headers",
    "hsts_missing": "missing_headers",
    "security_headers": "missing_headers",
    "referrer_policy_missing": "referrer_policy",
    "missing_referrer_policy": "referrer_policy",
    # Cookie attributes.
    "cookie_flag": "cookie_flags",
    "cookie_without_secure": "cookie_flags",
    "cookie_without_httponly": "cookie_flags",
    "cookie_missing_secure": "cookie_flags",
    "cookie_missing_httponly": "cookie_flags",
    "insecure_cookie": "cookie_flags",
    # Open redirect is only reportable chained.
    "open_redirect": "open_redirect_no_chain",
    "unvalidated_redirect": "open_redirect_no_chain",
    "redirect_unvalidated": "open_redirect_no_chain",
    # Information disclosure — a lead, never a result on its own.
    "information_disclosure": "info_disclosure",
    "info_leak": "info_disclosure",
    "information_leak": "info_disclosure",
    "verbose_error": "info_disclosure",
    "path_disclosure": "info_disclosure",
    "full_path_disclosure": "info_disclosure",
    "internal_path_disclosure": "info_disclosure",
    "directory_listing": "info_disclosure",
    "db_error_disclosure": "info_disclosure",
    "database_error": "info_disclosure",
    "debug_endpoint": "info_disclosure",
    "banner_disclosure": "info_disclosure",
    "software_version_disclosure": "version_disclosure",
    # TLS / transport config.
    "ssl_tls_config": "ssl_config",
    "tls_config": "ssl_config",
    "weak_cipher": "ssl_config",
    "ssl_weak_cipher": "ssl_config",
    "tls_version": "ssl_config",
    "mixed_content_warning": "mixed_content",
    # Enumeration.
    "username_enumeration": "user_enumeration",
    "email_enumeration": "user_enumeration",
    "account_enumeration": "user_enumeration",
    # Misc ineligible.
    "autocomplete_off_missing": "autocomplete",
    "missing_autocomplete": "autocomplete",
    "options_method_enabled": "options_method",
    "http_options_enabled": "options_method",
    "cors_no_credentials": "cors_no_creds",
    "cors_without_credentials": "cors_no_creds",
    "reverse_tabnabbing": "tabnabbing",
    "rate_limit_absent": "rate_limit_missing",
    "no_rate_limit": "rate_limit_missing",
    "stack_trace_disclosure": "stack_trace",
    "spf_record": "spf",
    "dmarc_record": "dmarc",
    "dkim_record": "dmarc",
    "dkim": "dmarc",

    # ── Spelling variants of reportable classes ──────────────────────────────
    # Same defect written two ways. These matter for the systemic-duplicate
    # gate: `reflected_xss` on one endpoint and `xss_reflected` on another is
    # one bug reported twice, and a triager will say so.
    #
    # Only genuine synonyms belong here. Stored and reflected XSS are NOT
    # merged — different sink, different fix, separately reportable — and
    # neither are blind and error-based SQLi collapsed into anything that would
    # weaken a gate keyed on the more specific name.
    "reflected_xss": "xss_reflected",
    "xss_reflect": "xss_reflected",
    "stored_xss": "xss_stored",
    "persistent_xss": "xss_stored",
    "blind_sqli": "sqli_blind",
    "sql_injection": "sqli",
    "sqli_error_based": "sqli_error",
    "sqli_union_based": "sqli_union",
    "time_based_sqli": "sqli_time",
    "directory_traversal": "path_traversal",
    "arbitrary_file_read": "path_traversal",
    "lfi": "path_traversal",
    "local_file_inclusion": "path_traversal",
    "bola": "idor",
    "broken_object_level_auth": "idor",
    "insecure_direct_object_reference": "idor",
    "bfla": "broken_function_level_auth",
    "ssrf_blind": "ssrf",
    "command_injection": "rce",
    "code_injection": "rce",
    "remote_code_execution": "rce",
    "account_takeover": "ato",
    "auth_bypass_403_to_200": "auth_bypass",
    "login_bypass": "auth_bypass",
}


def canonical(vuln_type: str) -> str:
    """Collapse a class spelling to the name the gates key on.

    Unknown names pass through unchanged: a class this table has never seen is
    not thereby ineligible, and silently rewriting it would be worse than
    leaving it alone.
    """
    vt = (vuln_type or "").strip().lower().replace("-", "_").replace(" ", "_")
    return _ALIASES.get(vt, vt)


def aliases_of(canonical_name: str) -> set[str]:
    """Every spelling that collapses to this canonical class."""
    name = (canonical_name or "").strip().lower()
    return {a for a, c in _ALIASES.items() if c == name} | {name}
