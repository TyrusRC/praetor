"""Q2 / Q7 gate sets for assess_finding."""

# Q2: vuln types that MUST be repro'd within the same authenticated session;
# forcing a clean re-login destroys the state being tested.
AUTH_STATE_DEPENDENT = {
    "idor", "bfla", "bola", "business_logic", "authorization",
    "access_control", "mass_assignment", "privilege_escalation",
    "password_reset", "2fa_bypass", "mfa_bypass",
    "account_takeover", "ato",
    "oauth", "oauth_open_redirect", "oauth_state_bypass",
    "saml", "saml_xsw", "saml_replay",
    "jwt", "jwt_alg_none", "jwt_kid",
    "session_fixation", "session_hijack",
    "auth_bypass", "auth_bypass_403_to_200",
    "race_condition",
}

# Q7: classes for which weak evidence triggers triager-mass-report downgrade
# UNLESS chain_with[] is provided. Kept narrow on purpose — adding a class here
# means standalone weak-evidence findings of that class will be silently
# dropped to NEEDS MORE EVIDENCE.
LOW_IMPACT_CLASSES = {
    "open_redirect",
    "information_disclosure",
    "info_disclosure",
}
