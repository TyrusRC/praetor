---
name: playbook-exposed-api-keys
description: Turn an exposed secret (Google/Gemini AIza, AWS, GitHub, Slack, Stripe, SendGrid, …) from an informational finding into a reportable HIGH — classify, validate SAFELY, frame impact
---

# Playbook: Exposed Secrets → Impact

A leaked secret is a LEAD, not a finding (Rule 29). Filed as "exposed secret" it
closes Informative. The value is what the secret DOES.

## 0. Any secret — classify + safe-validate

```
audit_exposed_secret(secret='<value>')
```

Classifies the type (AWS / GitHub / GitLab / Slack / npm / Google / Stripe /
SendGrid / Twilio / Mailgun / private key) and returns service, severity, and
impact. It AUTO-VALIDATES only read-only whoami keys (GitHub `/user`, GitLab
`/user`, Slack `auth.test`, npm whoami) — returning the identity + scopes the
token holds. **Financial / send-capable / destructive keys (Stripe live, AWS,
Twilio, SendGrid, Mailgun, private keys) are never auto-called** — hitting them
can move money or data; they come back classified with impact and a
manual-authorized-only note. The secret is redacted to shape in all output —
never paste a full secret back.

Google keys are the richest case (Gemini raised their ceiling) and get a
dedicated deep tool below.

## 1. Detect (already covered)

AIza keys surface from JS/history/offline automatically:
`extract_js_secrets`, `smart_js_analyze`, `smart_request_triage`,
`analyze_artifact` (offline). GitHub dorks for the same pattern:
`/AIza[0-9A-Za-z_-]{35}/` optionally `path:.env` / `path:*.js` / `org:<target>`.
Record the EXACT source (repo URL + line, or live JS bundle URL) — triage
verifies the exposure first.

## 2. Validate + frame impact — one tool

```
audit_google_api_key(key='AIza…', referer='')
```

- Read-only: lists Gemini models (free) and, on 403, retries with a
  `Referer: https://www.google.com/` to test a weak browser restriction.
- Returns `active`, `restriction` (none/restricted/invalid), `models`,
  `referer_bypass`, `impact_estimate`, and `other_services_to_check`.
- The key is redacted to shape in every field — never paste the full key back.

## 3. Severity

- Active key exposing costly models (Veo video / Imagen image / TTS) →
  **HIGH**: unauthenticated billable compute on the victim's account
  (financial DoS / overbilling).
- Active text-only → **MEDIUM–HIGH**: quota exhaustion + spam/automation on
  their billing.
- `restricted` but `referer_bypass=True` → the restriction is the control and
  it failed — report it, not "restricted so safe".
- `invalid` → dead key, `save_target_notes`, not the board.

## 4. Safe PoC — hard rules

- **Never** run `generateContent`, `:predict` (Imagen/Veo), or TTS against the
  target's key — that spends the victim's money and is abuse (Rule 7 / no
  abusive code). Prove capability from the model list + a cost ESTIMATE from
  the Gemini pricing page, not by detonating generation.
- File/Corpora endpoints: only interact with objects YOU created for the PoC,
  and delete them. Never read, modify, or delete the owner's objects.
- Other Google services (Maps/Firebase/Vision/YouTube) are listed as manual
  follow-ups — each call may bill, so check deliberately, minimally, read-only.

## 5. Report

Source (repo/JS URL + line) → validated capabilities (models that responded,
`referer_bypass`) → **financial impact estimate** (per-image / per-second-video
/ per-1k-token cost × scale) → remediation (revoke + rotate the key, add
application/API restrictions). A concrete dollar figure moves severity; vague
"an attacker could abuse this" does not.
