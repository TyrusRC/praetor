---
description: OTP / 2FA / MFA and login-challenge bypass — drive the existing auth tools as one attack chain. Code reuse, response manipulation, step-skip, cross-account binding, lockout + rate-limit (Rule 6a), prompt bombing, backup-code abuse. Load when the target has an OTP/2FA/SMS/email-code or MFA challenge.
globs:
---

# OTP / 2FA / MFA Bypass Deep-Dive

Load when: the target sends a one-time code (SMS / email / TOTP / push), OR you
see a `/verify`, `/mfa`, `/2fa`, `/otp`, `/challenge`, `/login/verify` step, OR a
password-reset or step-up flow. The tools and KB already exist — this playbook
chains them so the whole OTP surface is tested as one attack, not one probe at a
time.

## SMART MOVE — first calls

```
1. create_session(...) for the account you OWN (e.g. wiener:peter) — needed for
   lockout / rate-limit tests without harming a real user (Rule 6a).
2. test_mfa_bypass(url, ...)            — step_skip / response_manipulation / null_value
3. analyze_reset_tokens(url)           — reset-token predictability + grant-revoke
4. auto_probe(categories=['mfa_bypass','authentication','auth_bypass'])
```

## The chain — test every link, stop the moment one confirms

Run against the OTP/MFA challenge, worst-impact first. KB contexts in
`mfa_bypass.json` + `authentication.json` back each.

1. **Response manipulation** (`mfa_bypass/response_manipulation`): submit a wrong
   code, then flip the verify response (`{"success":false}`→`true`, `403`→`200`)
   with `resend_with_modification`. If the client trusts the response, the SPA
   advances authenticated — confirm with an authenticated request, not the status.
2. **Step-skip** (`mfa_bypass/step_skip`, `authentication/multi_step_bypass`):
   request the post-MFA resource directly with the half-authenticated session.
   If it serves, the challenge is not enforced server-side.
3. **Null / empty / default code** (`mfa_bypass/null_value`): submit ``, `null`,
   `000000`, `123456`. A pass means the check is absent or default-accepted.
4. **Code reuse / no-expiry** (`mfa_bypass/code_reuse`): use a valid code twice,
   or after its window. Reuse = replayable MFA.
5. **Cross-account binding** (`authentication/otp_cross_account_binding`): request
   a code for account A, submit it on account B's challenge. Acceptance = the code
   is not bound to the user — HIGH impact ATO primitive.
6. **Backup-code abuse** (`mfa_bypass/backup_code_abuse`): verify backup codes are
   not guessable / not accepted without the 2FA having been enrolled.
7. **Lockout + rate-limit — CONTROL test, Rule 6a bounds** (`test_rate_limit`,
   `mfa_bypass/brute_force`): confirm the control EXISTS or is ABSENT. Bound the
   volume to what proves it — dozens, not thousands — and STOP the moment lockout
   or a rate-limit fires. A 6-digit code with no rate-limit is brute-forceable:
   that is the finding; do NOT then grind the code. Run lockout only against your
   OWN account.
8. **Prompt bombing** (`mfa_bypass/mfa_prompt_bombing`): repeated push requests
   with no throttle / number-matching → MFA-fatigue ATO.
9. **Reset / step-up downgrade** (`authentication/password_reset_flaws`,
   `analyze_reset_tokens`): does password-reset or a step-up skip MFA, or fail to
   revoke sessions on reset? A reset that bypasses MFA is a full ATO path.

## Rule 6a guardrails (HARD — do not cross)

- Lockout / rate-limit / weak-password tests are CONTROL tests: bounded, and
  stopped the instant the behaviour is observed.
- Lockout runs against an account you OWN only — never lock a real user.
- On a code-accepted / weak-cred hit you have CONFIRMED it — stop. Do NOT exfil
  or pivot into that account's data (Rules 7/8); the proof is "the code/control
  failed", not what is inside.
- Never fire breached / real-user credential dumps at third-party accounts.

## Confirm + save

- Read the BODY, not the status (Rule 13a): a `200` that returns "Invalid code"
  is a negative; a `403` that still issues a session is a bypass.
- `verify` ≥3× for any timing/replay link, then `assess_finding` →
  `save_finding(vuln_type='mfa_bypass'|'auth_bypass'|'weak_password'|'no_rate_limit',
  reproduction_steps=[...])`. Put the attempt count + observed control behaviour in
  evidence. Include numbered `reproduction_steps` — a MFA/OTP bypass with no
  step-by-step is unreplayable by a triager.
