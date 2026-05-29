---
description: OAuth 2.0 / OIDC flow attacks — Authorization Code / PKCE / Device Code / Client Credentials. Mix-up, redirect_uri quirks, state CSRF, jku swap, PAR-DPoP (2024-2025). Load when target uses OAuth/OIDC.
globs:
---

# OAuth / OIDC Flow Attacks Deep-Dive

Load when: target uses OAuth 2.0 / OIDC (Sign in with Google / Apple / GitHub / Microsoft / Okta / Auth0 / Keycloak / Cognito), OR you see `/oauth/authorize` / `/oauth/token` / `/.well-known/openid-configuration`, OR the program scope includes federated identity.

## Flow inventory

Identify which flow(s) the target uses BEFORE attacking — payload + severity ceiling change per flow.

| Flow | Identifier | Common attack surface |
|---|---|---|
| **Authorization Code** | `response_type=code` | redirect_uri / state CSRF / mix-up / code injection / code replay |
| **Authorization Code + PKCE** | `response_type=code` + `code_challenge=...` | downgrade attack (drop PKCE) / code_verifier theft via referrer / S256-vs-plain confusion |
| **Implicit (deprecated)** | `response_type=token` | URL fragment leak via redirect / referrer / browser history |
| **Hybrid** | `response_type=code id_token` / `code id_token token` | id_token swap / nonce reuse / front-channel leak |
| **Device Code** | `/device/code` + `urn:ietf:params:oauth:grant-type:device_code` | poll-rate abuse / user_code phishing / device authorization grant injection |
| **Client Credentials** | `grant_type=client_credentials` | client_secret leakage / scope upgrade |
| **Resource Owner Password (deprecated)** | `grant_type=password` | credential interception / scope inflation |

For OIDC specifically: also test `/userinfo` endpoint + `id_token` claim manipulation per `playbook-jwt-deep-dive.md`.

## Attack matrix

### 1. redirect_uri quirks (most common)

`auto_probe` doesn't catch these. Manual fuzz the registered redirect_uri:

```
Registered:   https://app.target.com/callback
Probes:
  https://app.target.com/callback/../../admin       # path traversal
  https://app.target.com.evil.com/callback          # suffix bypass
  https://app.target.com@evil.com/callback          # userinfo split
  https://evil.com/?app.target.com/callback         # parameter pollution
  https://app.target.com#@evil.com/callback         # fragment-vs-authority
  https://app.target.com/callback?a=b@evil.com      # query authority confusion
  https://app.target.com/callback%2f@evil.com       # encoded slash
  https://[email protected]/callback              # IPv6 userinfo
  https://app.target.com\@evil.com/callback         # backslash
  https://app.target.com/callback\..\..\admin       # Windows-style traversal
```

Auth server accepts any of these → code arrives at attacker. Pair with `state=` not enforced or guessable → full ATO.

### 2. State parameter (CSRF token for OAuth)

Test:
- Missing state — server accepts callback without state. Confirmed CSRF on the OAuth callback.
- Predictable state — same state across logins / state derivable from session.
- State not validated on callback — change state mid-flow.

### 3. Mix-up attack

When the target supports multiple IdPs (Google + GitHub + Microsoft), the attacker logs in via attacker-IdP, then triggers victim's flow to attacker-IdP, swapping the issuer mid-flow. Server confuses which IdP issued the code → attacker gets victim's session bound to attacker's identity.

Detection: read `.well-known/openid-configuration` for `issuer`. Test whether `state` includes IdP identifier. If not, mix-up candidate.

### 4. JWKS / jku swap (post-W7)

OAuth servers that fetch JWKS from `iss` claim → attacker controls `iss` → attacker controls JWKS → signs arbitrary id_token. Active KB `oauth.jwks_url_external_swap` (W12 addition).

Workflow per `playbook-jwt-deep-dive.md` §"Algorithm confusion (RS→HS)" — but with the issuer-derived URL twist.

### 5. PKCE downgrade

Client uses PKCE but auth server doesn't enforce. Attacker submits `code_verifier` mismatch (or none) — server still issues token.

Test:
- Capture full PKCE flow.
- Replay `/token` with `code_verifier=wrong` or omitted entirely.
- Server returns 200 with access_token → PKCE not enforced.

### 6. Authorization code replay

Single-use codes must be rejected on second use. Test:
- Capture code from `/authorize` redirect.
- `/token` exchange once.
- Replay the same code immediately at `/token`.
- If second exchange returns 200, code is not single-use → token theft + replay.

### 7. PAR (Pushed Authorization Requests, RFC 9126) — 2024-2025

PAR is a hardening mechanism. When supported but not enforced:
- Submit `/authorize` request with `request_uri` from attacker-controlled PAR endpoint.
- Server fetches attacker's PAR payload → attacker-supplied parameters override the user's intent.

Detection: read `/.well-known/oauth-authorization-server` for `pushed_authorization_request_endpoint`. If present, test downgrade (omit `request_uri`, supply parameters inline).

### 8. DPoP (Demonstrating Proof of Possession, RFC 9449)

DPoP binds the access token to a key the client holds. When server validates DPoP loosely:
- Strip the `DPoP` header — server still accepts.
- Submit DPoP signed with a different key — server doesn't validate the binding.
- Replay DPoP across endpoints / time windows beyond `iat` tolerance.

### 9. Device Code flow

- **User code brute-force**: low-entropy user codes (8 chars 0-9) brute-forceable within a 15-minute window.
- **Polling-rate abuse**: client polls `/token` every 5s. Attacker polls faster, hits race against legitimate user.
- **Backchannel injection**: poison `/device/code` response when victim's device fetches it.

## Tool chain

1. **Read metadata** — `curl https://target/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`. Note flows supported, JWKS URL, PAR/DPoP, supported algs.
2. **Drive the flow** — use a real browser (Burp browser) to capture the full Authorization Code flow into proxy history.
3. **Walk the matrix** — for each attack above, modify the captured request with `resend_with_modification(index, ...)` and observe outcome.
4. **JWT-side** — when an id_token / access_token is JWT, hand off to `playbook-jwt-deep-dive.md` workflow with `test_jwt` / `forge_jwt`.
5. **State/CSRF** — use `test_csrf` against the OAuth callback endpoint.

## Evidence ladder

| Verdict | Evidence shape | Severity |
|---|---|---|
| **CONFIRMED CRITICAL** | Forged code / token authenticates as victim against `/userinfo` or victim's protected resource | Critical (ATO) |
| **CONFIRMED HIGH** | redirect_uri bypass works → code delivered to attacker URL (Collaborator hit) but exchange step also tested and rejected by aud check | High |
| **CONFIRMED HIGH** | State missing or not validated → attacker can stitch attacker session onto victim's flow | High |
| **SUSPECTED** | Auth server returns unexpected response (500, error_description leak) on a malformed redirect_uri | NO save — keep iterating |
| **FAILED** | All quirks rejected | NO |

## save_finding shape

```python
save_finding(
    vuln_type="oauth",
    endpoint="https://auth.target.com/oauth/authorize",
    parameter="redirect_uri",
    severity="critical",
    evidence={
        "logger_index": <code-arrival index>,
        "collaborator_interaction_id": "<id>",         # for redirect_uri bypass demo
        "summary": "OAuth redirect_uri suffix bypass — code delivered to https://app.target.com.evil.com/callback. Combined with weak state validation, code replayed at /token to obtain victim access_token.",
        "flow_type": "authorization_code",
        "attack": "redirect_uri_suffix_bypass",
    },
)
```

## NEVER_SUBMIT traps

- "OAuth supports `response_type=token` (implicit)" — deprecated by spec but not a vuln if no exploit path is shown.
- "Authorization server uses HTTP for one redirect" — note for the program, not a finding unless tokens leak.
- "Login screen has CSRF token" — that's correct behavior.
- "/.well-known/openid-configuration exposes endpoints" — by spec, MUST be public.

## Chain patterns

- **redirect_uri bypass + missing state** = stitch attacker session onto victim's authorize call → ATO.
- **JWKS swap + alg confusion** = forge any id_token → ATO across federated identities.
- **PKCE downgrade + redirect_uri bypass** = mobile OAuth ATO via deep-link callback.
- **Device code + low-entropy user_code** = brute-force ATO in the 15-min window.

## Related

- `knowledge/oauth.json` — JWKS swap, parser quirks (W12 added `jwks_url_external_swap`)
- `knowledge/oauth_2025.json` — 2025 OAuth research
- `knowledge/oauth_device_flow.json` — device code class
- `knowledge/oauth_dpop_confused_deputy.json` — DPoP class
- `playbook-jwt-deep-dive.md` — token-level attacks
- `test_csrf` for the callback CSRF axis
- `chain-findings.md` — open_redirect_to_ato progression also applies here
