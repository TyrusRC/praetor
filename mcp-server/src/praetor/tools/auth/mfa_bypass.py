"""test_mfa_bypass — orchestrate the four most-payed MFA bypass classes.

Each class lands distinct evidence so the operator can save one finding per
class (or chain them):

1. step-skip — POST directly to the post-MFA endpoint with a half-auth cookie
2. direct-resource — fetch a protected resource that should require MFA
3. code brute — fire N OTP guesses (built-in 100-most-common list, then
   sequential 000000-999999 if requested), watch for 429/lockout
4. code reuse — replay an already-consumed code

Built-in OTP top-list: the 100 most common 6-digit codes seen in public
password-leak dumps + obvious human picks (DOB-shaped, 123456 patterns).
For deeper brute, pass `full_brute=True` (10000 4-digit OR 1000000 6-digit
— operator owns the noise budget). Default cap is 500.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ._mfa_bypass_impl import _run_test_mfa_bypass


def register(mcp: FastMCP):

    @mcp.tool()
    async def test_mfa_bypass(  # cost: medium-high (configurable)
        mfa_verify_url: str,
        protected_url: str = "",
        partial_session_cookies: dict | None = None,
        partial_session_bearer: str = "",
        code_param: str = "code",
        code_in: str = "json_body",
        used_code: str = "",
        otp_length: int = 6,
        full_brute: bool = False,
        max_brute_attempts: int = 500,
    ) -> dict:
        """Four-prong MFA bypass test. Returns VerdictResult (W7 schema).

        Args:
            mfa_verify_url: The /verify-mfa / /2fa/check / /otp endpoint
            protected_url: A post-MFA resource (used for step-skip + direct-access)
            partial_session_cookies: Cookies from the FIRST factor (password OK,
                MFA pending) — this is what the bypass tests "promote"
            partial_session_bearer: Bearer variant of the above
            code_param: Name of the code parameter (default "code")
            code_in: "json_body" (default) | "form" | "query"
            used_code: A code the operator already used successfully — set this
                to test the code-reuse class
            otp_length: 4 / 6 / 8 — controls built-in wordlist trimming
            full_brute: True = full numeric range 0..10^otp_length (HUGE,
                operator-confirmed only). Default False (built-in top-list).
            max_brute_attempts: Hard cap on brute step (default 500)
        """
        return await _run_test_mfa_bypass(
            mfa_verify_url,
            protected_url=protected_url,
            partial_session_cookies=partial_session_cookies,
            partial_session_bearer=partial_session_bearer,
            code_param=code_param,
            code_in=code_in,
            used_code=used_code,
            otp_length=otp_length,
            full_brute=full_brute,
            max_brute_attempts=max_brute_attempts,
        )
