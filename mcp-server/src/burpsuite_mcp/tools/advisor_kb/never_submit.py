"""NEVER SUBMIT lists + sensitive-endpoint patterns for assess_finding Q6."""

# UNCONDITIONAL NEVER SUBMIT — these vuln_types never reach REPORT standalone.
# clickjacking / csrf_logout / host_header_no_cache / cors_no_creds /
# version_disclosure / options_method live in CONDITIONAL_NEVER_SUBMIT_TYPES
# below since each has a real exploit path on a sensitive endpoint.
NEVER_SUBMIT_TYPES = {
    "missing_headers": "Missing security headers alone — informative, not reportable",
    "cookie_flags": "Cookie without Secure/HttpOnly — requires MitM or XSS to exploit",
    "self_xss": "Self-XSS — victim must paste payload themselves",
    "csrf_non_state_changing": "CSRF on non-state-changing endpoint — no impact",
    "open_redirect_no_chain": "Open redirect without token theft chain — low impact",
    "mixed_content": "Mixed content — browser mitigates",
    "stack_trace": "Stack traces alone — info disclosure, not exploitable",
    "user_enumeration": "Username enumeration on public sign-up — often by design",
    "username_enumeration": "Username enumeration on public sign-up — often by design",
    "email_enumeration": "Email enumeration on public sign-up / forgot-password — often by design",
    "referrer_policy": "Missing Referrer-Policy — extremely minor",
    "spf": "SPF/DMARC/DKIM issues — email security, usually out of scope",
    "dmarc": "SPF/DMARC/DKIM issues — email security, usually out of scope",
    "content_spoofing": "Content spoofing without XSS — minimal impact",
    "ssl_config": "SSL/TLS configuration issues — scanner noise",
    "text_injection": "Text injection without HTML context — no code execution",
    "idn_homograph": "IDN homograph attacks — browser-mitigated",
    "autocomplete": "Missing autocomplete=off — password managers handle this",
}

# CONDITIONAL NEVER SUBMIT — reportable when chained (chain_with non-empty)
# OR when context indicates real impact. Keys MUST match Java
# FindingsStore.CONDITIONAL_NEVER_SUBMIT_TYPES.
CONDITIONAL_NEVER_SUBMIT_TYPES = {
    "tabnabbing": "Reverse tabnabbing alone is low impact — chain with token theft / postMessage hijack",
    "rate_limit_absent_non_sensitive": "Missing rate limit on non-sensitive endpoint — but rate-limit on auth/reset/OTP/payment IS reportable; tag endpoint accordingly or chain with ATO",
    "rate_limit_missing": "Missing rate limit on non-sensitive endpoint — but rate-limit on auth/reset/OTP/payment IS reportable; tag endpoint accordingly or chain with ATO",
    # Sensitive-endpoint contextual exemption (clickjacking on 2FA / funds /
    # OAuth-consent IS paid). Promoted from unconditional with endpoint check.
    "clickjacking": "Clickjacking on non-sensitive pages has no impact — but clickjacking on funds-transfer / 2FA-disable / OAuth consent / password change IS reportable; chain or land on a sensitive endpoint",
    "csrf_logout": "CSRF logout alone is minimal — but CSRF-logout chained with phishing / pre-auth flow IS reportable",
    "host_header_no_cache": "Host header injection without cache effect is no exploit — UNLESS the endpoint generates emails (password reset, magic link, 2FA send), in which case host-header poisoning IS reportable",
    "cors_no_creds": "CORS reflection without Allow-Credentials usually browser-blocks — but if the endpoint serves private artefacts (signed S3 URL, presigned token, API key) without auth, the public-by-flaw exposure IS reportable",
    "version_disclosure": "Version disclosure alone — but a disclosed version with a known pre-auth CVE IS reportable; chain with the CVE finding",
    "options_method": "OPTIONS method enabled — normal HTTP — but OPTIONS allowing arbitrary verbs (TRACE/PUT/DELETE) on a sensitive path IS reportable",
}

# Endpoint substrings that flip rate-limit-missing AND the new sensitive-context
# conditionals (clickjacking, csrf_logout, host_header_no_cache, options_method)
# from NEVER SUBMIT to reportable.
SENSITIVE_ENDPOINT_PATTERNS = (
    "/login", "/signin", "/sign-in", "/auth", "/oauth", "/token",
    "/password", "/reset", "/forgot", "/recover", "/2fa", "/mfa",
    "/otp", "/verify", "/verification", "/code", "/captcha",
    "/payment", "/checkout", "/charge", "/withdraw", "/transfer",
    "/api-key", "/apikey",
    "/balance", "/wallet", "/funds", "/payout", "/refund",
    "/email-change", "/change-email", "/change-password",
    "/disable-2fa", "/remove-2fa", "/consent", "/authorize",
    "/admin", "/internal", "/billing", "/subscription",
    "/delete-account", "/close-account",
)

# Evidence-text keywords that imply a NEVER SUBMIT class regardless of vuln_type.
NEVER_SUBMIT_KEYWORDS = {
    "self-xss": "Self-XSS — victim must paste payload themselves",
    "self xss": "Self-XSS — victim must paste payload themselves",
    "clickjacking": "Clickjacking on non-sensitive pages has no impact",
    "csrf on logout": "CSRF on logout — minimal impact",
    "autocomplete=off": "Missing autocomplete=off — password managers handle this",
    "stack trace": "Stack traces alone — info disclosure, not exploitable",
}
