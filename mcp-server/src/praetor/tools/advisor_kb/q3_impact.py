"""Q3: "Real impact? What can an attacker actually DO?"

Historically a no-op — impact was folded into severity scoring and Q7's
low-impact-class heuristic. That left the single biggest source of rejected
submissions unguarded: a finding that *describes an observation* ("the endpoint
returns a stack trace", "the response reflects my input", "CORS echoes Origin")
rather than *an attacker capability* passes every other gate and is then closed
Informative by the program.

This gate now fires. Two tiers:

- Classes where the class IS the capability (RCE, SQLi, IDOR, auth bypass, ...)
  pass automatically — proving the class proves the impact.
- Everything else must show ONE of: a named asset actually obtained, an
  attacker-capability statement, a victim other than the tester, or a
  chain_with[] anchor that supplies the impact.

Failing the gate is not a rejection — it downgrades to NEEDS MORE EVIDENCE and
names the specific next proof to collect.
"""

from ..advisor._context import AssessContext
from . import CheckResult


# Classes where demonstrating the class demonstrates the impact. No separate
# impact statement demanded — asking for one just adds friction to real bugs.
IMPACT_INHERENT_CLASSES = {
    "rce", "command_injection", "code_injection",
    "sqli", "sqli_blind", "sqli_time", "sqli_error", "sqli_union", "nosqli",
    "ssti", "ssti_blind", "xxe", "xxe_blind", "deserialization",
    "ssrf", "ssrf_blind", "request_smuggling", "cache_poisoning",
    "idor", "bola", "bfla", "bopla", "broken_object_level_auth",
    "broken_function_level_auth", "id_enumeration",
    "auth_bypass", "auth_bypass_403_to_200", "login_bypass",
    "privilege_escalation", "account_takeover", "ato",
    "mass_assignment", "business_logic", "race_condition",
    "path_traversal", "lfi", "rfi", "file_upload_rce",
    "xss_stored", "jwt_alg_none", "jwt_kid", "jwt_forge",
    "saml_xsw", "mfa_bypass", "2fa_bypass", "password_reset_takeover",
    "prototype_pollution", "graphql_batching_bypass", "subdomain_takeover",
    "exposed_credentials", "secret_leak", "cloud_metadata_ssrf",
}

# Phrases proving an attacker capability rather than an observation. Kept in
# attacker-goal vocabulary on purpose — "returns", "reflects", "discloses" are
# observations and are deliberately NOT here.
_CAPABILITY_SIGNALS = (
    "another user", "other user", "other users", "different user",
    "cross-tenant", "cross tenant", "another tenant", "another account",
    "other account", "victim", "any user", "arbitrary user",
    "without authentication", "without auth", "unauthenticated access",
    "without authorization", "bypasses auth", "bypass auth",
    "escalate", "escalation", "takeover", "take over", "impersonate",
    "read arbitrary", "write arbitrary", "delete arbitrary", "modify arbitrary",
    "execute", "code execution", "shell",
    "exfiltrate", "exfiltration", "dump",
    "session hijack", "hijack", "steal", "stolen",
    "full account", "admin access", "administrative access",
    "internal service", "internal network", "internal api",
    "financial loss", "unauthorized transaction", "free ", "bypass payment",
)

# Concrete assets that only matter because possessing them enables an attack.
# A finding that names one of these as *obtained* has demonstrated impact.
_ASSET_SIGNALS = (
    "api key", "api_key", "apikey", "secret key", "private key",
    "credential", "password hash", "plaintext password",
    "access token", "refresh token", "session token", "session cookie",
    "bearer token", "jwt secret", "signing key",
    "aws_secret", "aws secret", "iam credential", "sts token",
    "database connection", "connection string", "db password",
    "pii", "personally identifiable", "ssn", "national id",
    "card number", "pan", "cvv", "iban", "bank account",
    "phone number", "home address", "date of birth", "medical", "phi",
    "source code", "git objects", ".env",
)

# Per-class instruction: what specific proof turns this observation into an
# impact. Falls back to a generic line when the class is unlisted.
_NEXT_PROOF = {
    "information_disclosure": "name the asset you retrieved and what it unlocks (a credential that authenticates, an internal host you then reached, PII of a user who is not you)",
    "info_disclosure": "name the asset you retrieved and what it unlocks",
    "verbose_error": "use the leaked detail to reach something you could not before (a path you then read, a query you then injected), or chain it",
    "stack_trace": "use the leaked framework/version to land a working exploit, then report that exploit instead",
    "version_disclosure": "land a working exploit for a known CVE against that exact version, then report the exploit",
    "directory_listing": "retrieve a file from the listing that contains a secret or another user's data",
    "debug_endpoint": "show the debug surface performing a privileged action or leaking a credential",
    "source_disclosure": "quote the secret or authz flaw the source reveals and exploit it",
    "cors": "show a credentialed cross-origin read returning another user's data",
    "cors_misconfiguration": "show a credentialed cross-origin read returning another user's data",
    "csrf": "show the forged request completing a state change on a victim account",
    "open_redirect": "show a token or code landing on the attacker destination (OAuth redirect_uri, SSO next=, password-reset link)",
    "clickjacking": "show a framed sensitive action (fund transfer, 2FA disable, OAuth consent) completing",
    "rate_limit_missing": "show the missing limit yielding an outcome — OTP brute-forced, coupon drained, account enumerated at scale",
    "xss": "show the payload executing in a victim's context and what it then steals or performs",
    "xss_reflected": "show the payload executing in a victim's context and what it then steals or performs",
    "user_enumeration": "pair the valid-account oracle with a working credential-stuffing or reset-flow attack",
    "websocket": "show the message crossing an authorization boundary or reaching another user's channel",
    "graphql": "show the query returning data the current role must not see",
    "host_header_injection": "show the poisoned host landing in an email link, a cache entry, or a password-reset URL",
    "subdomain_takeover": "show content you control served from the subdomain, and what trusts that origin",
}

_GENERIC_PROOF = (
    "state what an attacker DOES with this — whose data, which action, what "
    "they gain that they could not get legitimately"
)


def _has_signal(text: str, signals) -> bool:
    return any(s in text for s in signals)


async def check(ctx: AssessContext) -> CheckResult:
    """Require a demonstrated attacker capability before REPORT."""
    if "q3_impact" in ctx.override_set:
        ctx.issues.append("Q3 OVERRIDE: impact-demonstration gate bypassed")
        return {"passed": True, "reason": "override", "evidence": {}}

    # Already sunk — no point demanding impact for something we won't report.
    if ctx.verdict == "DO NOT REPORT":
        return {"passed": True, "reason": "already-rejected", "evidence": {}}

    root = ctx.q2_class_root or ctx.vuln_lower
    if ctx.vuln_lower in IMPACT_INHERENT_CLASSES or root in IMPACT_INHERENT_CLASSES:
        return {"passed": True, "reason": "class-is-impact", "evidence": {"class": root}}

    # A chain anchor is the impact statement — that is what chaining is for.
    if ctx.chain_provided:
        return {"passed": True, "reason": "chained", "evidence": {"chain_with": ctx.chain_with}}

    haystack = " ".join(
        p for p in (ctx.evidence_lower, (ctx.business_context or "").lower()) if p
    )
    if _has_signal(haystack, _CAPABILITY_SIGNALS):
        return {"passed": True, "reason": "capability-stated", "evidence": {}}
    if _has_signal(haystack, _ASSET_SIGNALS):
        return {"passed": True, "reason": "asset-obtained", "evidence": {}}

    proof = _NEXT_PROOF.get(ctx.vuln_lower) or _NEXT_PROOF.get(root) or _GENERIC_PROOF
    ctx.issues.append(
        f"Q3 IMPACT NOT DEMONSTRATED: the evidence describes what the server "
        f"DOES, not what an attacker GAINS. Submitted as-is this is closed "
        f"Informative.\n      Next proof: {proof}.\n      Or pass "
        f"chain_with=['fNNN'] if another saved finding supplies the impact."
    )
    ctx.verdict = "NEEDS MORE EVIDENCE"
    return {"passed": False, "reason": "impact-not-demonstrated", "evidence": {"class": root}}
