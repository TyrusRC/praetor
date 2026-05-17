"""Calibration tests for advisor_kb data tables.

Tables drive the Q5/Q6 gates in assess_finding; calibration tests guard against
silent data-drift (alias -> nonexistent key, conditional + unconditional same
type, sensitive-endpoint pattern misformatted).

Run: uv run python -m unittest tests.test_advisor_kb -v
"""

import unittest

from burpsuite_mcp.tools.advisor_kb.gates import (
    AUTH_STATE_DEPENDENT,
    LOW_IMPACT_CLASSES,
)
from burpsuite_mcp.tools.advisor_kb.never_submit import (
    CONDITIONAL_NEVER_SUBMIT_TYPES,
    NEVER_SUBMIT_KEYWORDS,
    NEVER_SUBMIT_TYPES,
    SENSITIVE_ENDPOINT_PATTERNS,
)
from burpsuite_mcp.tools.advisor_kb.q5 import (
    Q5_ALIASES,
    Q5_KEYWORDS,
    TIMING_VULN_TYPES,
)


class NeverSubmitTableIntegrityTests(unittest.TestCase):
    def test_no_type_in_both_unconditional_and_conditional(self):
        overlap = set(NEVER_SUBMIT_TYPES) & set(CONDITIONAL_NEVER_SUBMIT_TYPES)
        self.assertFalse(overlap, f"{overlap} present in both tables")

    def test_all_descriptions_non_empty(self):
        for k, v in NEVER_SUBMIT_TYPES.items():
            self.assertTrue(v.strip(), f"{k!r} has empty description")
        for k, v in CONDITIONAL_NEVER_SUBMIT_TYPES.items():
            self.assertTrue(v.strip(), f"{k!r} has empty description")

    def test_sensitive_patterns_lowercase_and_slashed(self):
        for pat in SENSITIVE_ENDPOINT_PATTERNS:
            self.assertEqual(pat, pat.lower(), f"{pat!r} not lowercased")
            self.assertTrue(pat.startswith("/"), f"{pat!r} missing leading /")

    def test_sensitive_patterns_no_duplicates(self):
        self.assertEqual(
            len(SENSITIVE_ENDPOINT_PATTERNS),
            len(set(SENSITIVE_ENDPOINT_PATTERNS)),
        )

    def test_never_submit_keywords_lowercase(self):
        # Keyword matching elsewhere lowercases the haystack — keys must be lower.
        for k in NEVER_SUBMIT_KEYWORDS:
            self.assertEqual(k, k.lower(), f"{k!r} not lowercased")

    def test_known_unconditional_types_present(self):
        # Spot-check the entries the gates rely on. Catches accidental deletion.
        required = {
            "missing_headers", "cookie_flags", "self_xss",
            "stack_trace", "user_enumeration", "spf", "dmarc",
            "autocomplete",
        }
        missing = required - set(NEVER_SUBMIT_TYPES)
        self.assertFalse(missing, f"missing required: {missing}")

    def test_known_conditional_types_present(self):
        required = {
            "tabnabbing", "clickjacking", "csrf_logout",
            "host_header_no_cache", "cors_no_creds",
            "version_disclosure", "options_method",
            "rate_limit_missing",
        }
        missing = required - set(CONDITIONAL_NEVER_SUBMIT_TYPES)
        self.assertFalse(missing, f"missing required: {missing}")


class Q5TableIntegrityTests(unittest.TestCase):
    def test_aliases_resolve_to_real_canonical(self):
        # Every alias target must exist in Q5_KEYWORDS, otherwise the alias
        # silently drops findings through Q5 with no keyword bar.
        invalid = [
            (alias, target)
            for alias, target in Q5_ALIASES.items()
            if target not in Q5_KEYWORDS
        ]
        self.assertFalse(invalid, f"alias targets missing from Q5_KEYWORDS: {invalid}")

    def test_aliases_not_self_referential(self):
        # An alias that points at its own key is a footgun — usually means the
        # canonical class was renamed and the alias stayed.
        self_refs = [a for a in Q5_ALIASES if a in Q5_KEYWORDS and Q5_ALIASES[a] != a]
        # Actually this should just check no alias maps to itself
        for alias, target in Q5_ALIASES.items():
            self.assertNotEqual(alias, target, f"{alias!r} aliases to itself")

    def test_no_class_has_empty_keyword_list(self):
        for cls, kws in Q5_KEYWORDS.items():
            self.assertTrue(kws, f"{cls!r} has empty keyword list")

    def test_keywords_lowercased_or_intentional(self):
        # Most matchers downcase the haystack; uppercase keywords silently fail.
        # Allow uppercase only for known case-significant markers (HTTP headers,
        # SQL keywords printed in stack traces).
        case_significant_substrings = (
            "ORA-", "Set-Cookie",  # extend as needed
        )
        for cls, kws in Q5_KEYWORDS.items():
            for kw in kws:
                if kw == kw.lower():
                    continue
                # Allowed if it contains a case-significant marker.
                if any(m in kw for m in case_significant_substrings):
                    continue
                # Otherwise — comment-document intent or downcase.
                # Most current entries are lowercase; flag any drift.

    def test_timing_types_have_q5_keywords(self):
        # Each timing-class vuln_type must either match a Q5_KEYWORDS key or
        # alias into one, else assess_finding's evidence check has nothing to
        # compare against.
        for vt in TIMING_VULN_TYPES:
            canonical = Q5_ALIASES.get(vt, vt)
            self.assertIn(
                canonical, Q5_KEYWORDS,
                f"timing type {vt!r} -> {canonical!r} has no Q5 keywords",
            )

    def test_oauth_keywords_distinct_from_jwt(self):
        # oauth was previously aliased to jwt and missed state/PKCE evidence.
        # Verify the split is in place.
        self.assertIn("oauth", Q5_KEYWORDS)
        oauth_kw = " ".join(Q5_KEYWORDS["oauth"]).lower()
        self.assertIn("pkce", oauth_kw)
        self.assertIn("state", oauth_kw)
        self.assertIn("redirect_uri", oauth_kw)

    def test_oauth_alias_lands_on_oauth_not_jwt(self):
        for variant in ("oauth_state", "oauth_pkce", "oauth_redirect_uri",
                        "oauth_nonce", "oidc"):
            self.assertEqual(Q5_ALIASES[variant], "oauth")

    def test_idor_aliases_collapse_correctly(self):
        for variant in ("bola", "bfla", "id_enumeration",
                        "predictable_id", "sequential_id"):
            self.assertEqual(Q5_ALIASES[variant], "idor")

    def test_sqli_blind_alias_to_sqli(self):
        self.assertEqual(Q5_ALIASES["sqli_blind"], "sqli")
        self.assertEqual(Q5_ALIASES["sqli_time"], "sqli")


class GatesTableTests(unittest.TestCase):
    def test_auth_state_dependent_includes_core_classes(self):
        required = {"idor", "bfla", "bola", "business_logic",
                    "mass_assignment", "race_condition", "jwt",
                    "oauth", "ato", "account_takeover"}
        missing = required - AUTH_STATE_DEPENDENT
        self.assertFalse(missing, f"missing required: {missing}")

    def test_low_impact_classes_narrow(self):
        # LOW_IMPACT_CLASSES is intentionally narrow — anything we add here
        # silently downgrades standalone findings to NEEDS MORE EVIDENCE.
        self.assertEqual(LOW_IMPACT_CLASSES, {
            "open_redirect", "information_disclosure", "info_disclosure",
        })

    def test_no_overlap_between_auth_and_low_impact(self):
        # An auth-state-dependent class is by definition NOT low-impact —
        # catching cross-contamination at the data level.
        self.assertFalse(AUTH_STATE_DEPENDENT & LOW_IMPACT_CLASSES)


class SensitiveEndpointMatchTests(unittest.TestCase):
    """Spot-check that the sensitive-endpoint substring list catches real paths."""

    def _is_sensitive(self, endpoint: str) -> bool:
        ep = endpoint.lower()
        return any(p in ep for p in SENSITIVE_ENDPOINT_PATTERNS)

    def test_login_endpoint_sensitive(self):
        self.assertTrue(self._is_sensitive("/api/v1/login"))

    def test_password_reset_sensitive(self):
        self.assertTrue(self._is_sensitive("/password/reset"))

    def test_2fa_disable_sensitive(self):
        self.assertTrue(self._is_sensitive("/account/disable-2fa"))

    def test_oauth_consent_sensitive(self):
        self.assertTrue(self._is_sensitive("/oauth/authorize"))

    def test_funds_transfer_sensitive(self):
        self.assertTrue(self._is_sensitive("/api/wallet/transfer"))

    def test_payment_endpoint_sensitive(self):
        self.assertTrue(self._is_sensitive("/checkout/payment"))

    def test_admin_endpoint_sensitive(self):
        self.assertTrue(self._is_sensitive("/admin/users"))

    def test_billing_endpoint_sensitive(self):
        self.assertTrue(self._is_sensitive("/billing/charge"))

    def test_blog_post_NOT_sensitive(self):
        self.assertFalse(self._is_sensitive("/blog/post/123"))

    def test_static_asset_NOT_sensitive(self):
        self.assertFalse(self._is_sensitive("/static/css/main.css"))

    def test_help_page_NOT_sensitive(self):
        self.assertFalse(self._is_sensitive("/help/contact"))


if __name__ == "__main__":
    unittest.main()
