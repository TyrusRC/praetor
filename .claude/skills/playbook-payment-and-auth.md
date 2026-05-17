---
name: playbook-payment-and-auth
description: Deep-dive auth + payment attack surface — OAuth 2.0 / OIDC, WebAuthn / FIDO2 / passkeys, Google Pay, Apple Pay, Samsung Pay, IAP receipt validation, 3DS 2.x bypass, SCA exemption abuse, recovery flow downgrades. Money-flow / account-takeover class; consistently the highest-paying surface on any program that has it.
prerequisite: Target has at least one of — OAuth/SSO login (button or `/authorize` endpoint visible), WebAuthn / passkey enrollment, payment checkout with Stripe/Square/PayPal/Adyen/Braintree, Google/Apple/Samsung Pay button, IAP-backed subscription, recovery email/SMS flow handling money or admin actions.
stop_condition: 25 probes across ≥3 sections with no anomaly, no replay success, no scope/state mismatch → return to playbook-router for re-classification.
---

# Payment + Auth Deep-Dive Playbook

These are the bugs that pay $5k–$50k. Standard scanners find none of them.
Every section: **signal → flow map → attack matrix → evidence → severity → save template**.

Knowledge base already covers the matchers — this skill is the *workflow*
that drives `auto_probe` + `session_request` + `run_flow` against those
matchers. Probe files: `oauth.json`, `oauth_device_flow.json`,
`webauthn_passkey.json`, `payment_flow.json`.

**Anti-pattern killer:** none of these classes work by "spray a payload."
You need the multi-step flow captured AND the second-step replayed under
mutated state. Use `run_flow` or `session_request` chains — not `fuzz_parameter`.

---

## §1 OAuth 2.0 / OIDC

### Signals (any one triggers this section)
- `/authorize`, `/oauth/`, `/oidc/`, `/.well-known/openid-configuration` reachable
- `Location: https://idp.<tld>/...` redirect with `client_id`, `redirect_uri`, `response_type`, `state`, `code_challenge` in query
- `id_token`, `access_token`, `refresh_token` in responses
- `iss`, `aud`, `sub`, `nonce`, `at_hash` JWT claims
- Sign-in buttons: "Continue with Google / Microsoft / Apple / Okta / Auth0"

### Flow to map first
```
1. Click "Continue with X" → GET /authorize?client_id=...&redirect_uri=...&state=...&code_challenge=...
2. IdP login → 302 to redirect_uri with ?code=... or #access_token=...
3. App's /callback exchanges code → POST /token, returns {access_token, id_token, refresh_token}
4. App sets session cookie / Authorization header; subsequent calls authenticated
```

Capture all four requests (`get_proxy_history` + `annotate_request`). Every attack below targets one of these four hops.

### Attack matrix (in order of payout)

| # | Attack | Probe | Evidence to capture | Severity |
|---|---|---|---|---|
| 1 | Open `redirect_uri` allowlist | Send `redirect_uri=https://attacker.tld` / `legit.com.attacker.tld` / `legit.com@attacker.tld` / `legit.com/..//attacker.tld` | 302 with `code` to attacker domain | CRITICAL — ATO |
| 2 | Missing `state` validation | Drop / replay the `state` param at callback | Account linking succeeds without CSRF token | CRITICAL — ATO via CSRF |
| 3 | PKCE downgrade | Strip `code_challenge` from `/authorize`; or strip `code_verifier` from `/token` | Token issued without verifier | HIGH — code-theft chain |
| 4 | PKCE `plain` method | `code_challenge_method=plain`; `code_challenge` == `code_verifier` | Server accepts plain method (most should reject) | HIGH |
| 5 | Code reuse | Exchange same `code` twice | Second exchange succeeds | HIGH |
| 6 | Code/token mix-up (multi-IdP) | Login via IdP-A, swap the issued code with one from IdP-B at exchange | App accepts code from wrong IdP | CRITICAL — cross-tenant ATO |
| 7 | `response_type` confusion | `response_type=code id_token token` → fragment leak via redirect | Tokens land in URL fragment, exposed to referrer | HIGH |
| 8 | Scope creep | Add `scope=admin` / `scope=read:all` to /authorize | Token issued with elevated scope | CRITICAL |
| 9 | `nonce` reuse (OIDC) | Replay same `nonce` in two flows | Server doesn't bind nonce to session | MEDIUM-HIGH |
| 10 | `id_token` signature `alg:none` | Re-sign id_token with `alg:none` and modified `sub` | App accepts unsigned token | CRITICAL — full ATO |
| 11 | `iss` substitution | Change `iss` claim to attacker IdP whose key the app might fetch | Token validated against wrong issuer | CRITICAL |
| 12 | Refresh-token theft via XSS / leaked JS | Find `refresh_token` in localStorage / JS bundle / log | Long-lived ATO | CRITICAL |
| 13 | Refresh-token reuse after rotation | Old refresh_token still works after issuing new one | Token rotation not enforced | HIGH |
| 14 | `redirect_uri` parameter pollution | `redirect_uri=https://legit.com&redirect_uri=https://attacker.tld` | Some IdPs use last; some first; some both | CRITICAL if attacker wins |
| 15 | Authorization-code leak via Referer | Successful login → next page outbound request includes `?code=` in Referer | Code in third-party logs | MEDIUM-HIGH |

### Probe commands

```python
# 1) Drive auto_probe against the /authorize and /token endpoints
auto_probe(url="https://target.tld/authorize", categories=["oauth"], parameter="redirect_uri")
auto_probe(url="https://target.tld/oauth/token", categories=["oauth"], parameter="code")

# 2) Manual replay of code exchange (try twice)
session_request(name="user", method="POST", path="/oauth/token",
                json_body={"grant_type":"authorization_code","code":"<code>","redirect_uri":"...","code_verifier":"..."})
# Replay immediately:
session_request(name="user", method="POST", path="/oauth/token",
                json_body={"grant_type":"authorization_code","code":"<same_code>","redirect_uri":"...","code_verifier":"..."})

# 3) PKCE downgrade
# Capture flow, then resend /authorize without code_challenge — modify via Burp:
resend_with_modification(index=<authorize_idx>, modify_path="/authorize?client_id=...&redirect_uri=...")  # strip pkce

# 4) id_token alg=none / claim manipulation — use forge_jwt instead of manual encoding
forge_jwt(token="<captured_id_token>", mode="alg_none", claim_changes={"sub": "admin", "email": "admin@target.tld"})
forge_jwt(token="<captured_id_token>", mode="hs_confusion", public_key_pem="<server_pubkey>", claim_changes={"role": "admin"})

# 5) HS256 weak-secret check — built-in 200-secret wordlist runs in <1s
crack_jwt_secret(token="<captured_jwt>")
```

### Save template

```python
assess_finding(
  vuln_type="oauth_redirect_uri",
  endpoint="https://target.tld/oauth/authorize",
  parameter="redirect_uri",
  evidence={"logger_index": N, "reproductions": [...], "notes": "attacker.tld received code=abc123"},
  domain="target.tld",
)
save_finding(severity="critical", vuln_type="oauth_redirect_uri", ...)
```

---

## §2 WebAuthn / FIDO2 / Passkeys

### Signals
- `/webauthn/register/begin`, `/webauthn/authenticate/begin`, `/finish` endpoints
- Bodies contain `attestationObject`, `clientDataJSON`, `authenticatorData`, `signature`, `challenge`
- `navigator.credentials.create(...)` / `.get(...)` in JS bundle
- "Sign in with passkey" / "Set up passkey" / "Touch ID" / "Windows Hello" UI

### Flow to map
```
Registration:    /register/begin → returns challenge → browser creates keypair → /register/finish (attestationObject)
Authentication:  /authenticate/begin → returns challenge → browser signs → /authenticate/finish (signature)
Recovery:        usually weaker — email/SMS code, security questions, backup codes
```

### Attack matrix

| # | Attack | Probe | Severity |
|---|---|---|---|
| 1 | `attestation=none` accepted with attacker-controlled key | Register passkey with `fmt:"none"` and attacker pubkey | HIGH — full registration spoof |
| 2 | Challenge replay | Capture challenge from /begin, replay /finish with same challenge minutes later | HIGH — replay |
| 3 | Challenge not bound to session | Get challenge as user A, complete /finish as user B | CRITICAL — ATO |
| 4 | `rpId` mismatch tolerated | Send `clientDataJSON` with `rpId: "evil.tld"` instead of `target.tld` | HIGH |
| 5 | Origin mismatch tolerated | Send `clientDataJSON.origin: "https://attacker.tld"` | HIGH |
| 6 | `signCount` not validated | Reuse old assertion with stale signCount, or signCount going backwards | MEDIUM-HIGH (cloned auth) |
| 7 | Fallback-to-password downgrade | "Forgot passkey" link triggers password reset with weak verification | CRITICAL if email-only |
| 8 | Recovery code rate-limit absent | Brute-force 6-digit recovery code | CRITICAL |
| 9 | Recovery code reuse after success | Same code grants entry twice | HIGH |
| 10 | Conditional UI enumeration | `mediation:"conditional"` returns autofill — confirms which usernames have passkeys | LOW-MEDIUM (enum) |
| 11 | Credential ID list leak | `GET /webauthn/credentials` accessible cross-user → confirms account existence | LOW-MEDIUM |
| 12 | PRF extension cross-RP reuse | Server-derived secret via PRF reused across services | MEDIUM-HIGH |
| 13 | Authenticator delete without re-auth | DELETE /webauthn/credentials/<id> succeeds with only session cookie, no re-auth | CRITICAL — attacker removes victim's 2FA |
| 14 | Token-binding skip | Steal session cookie → use without passkey assertion | CRITICAL |

### Probe commands

```python
# Drive the existing matchers
auto_probe(url="https://target.tld/webauthn/register/finish", categories=["webauthn_passkey"])
auto_probe(url="https://target.tld/webauthn/authenticate/finish", categories=["webauthn_passkey"])

# Test recovery-code rate-limit
concurrent_requests(
  requests=[{"url":"https://target.tld/recovery/verify","method":"POST",
             "json_body":{"code":f"{i:06d}","email":"victim@x.tld"}} for i in range(0,1000)],
  concurrency=20
)
# 429 absence within 1000 attempts = critical
```

### Save template

```python
save_finding(
  vuln_type="webauthn_attestation_none",
  severity="high",
  title="Server accepts attestation=none with attacker-supplied public key",
  endpoint="https://target.tld/webauthn/register/finish",
  evidence={"logger_index": N, "notes": "attacker pubkey accepted; later authenticated as same user"},
)
```

---

## §3 Google Pay (Web + Android)

### Signals
- "Google Pay" button on checkout (Web: `payments.google.com/payjs`, Android: `com.google.android.apps.walletnfcrel`)
- Request bodies containing `paymentMethodData.tokenizationData.token` (JSON string with `signature`, `protocolVersion`, `signedMessage`)
- `gateway`, `gatewayMerchantId` fields in client config
- TEST vs PRODUCTION environment flag

### Flow to map
```
1. Client builds PaymentDataRequest with gateway config (Stripe / Adyen / Braintree / direct)
2. Google returns paymentMethodData.tokenizationData.token (encrypted blob signed by Google)
3. App posts token + amount + order_id to backend
4. Backend forwards token to payment gateway, receives charge result
```

### Attack matrix

| # | Attack | Probe | Severity |
|---|---|---|---|
| 1 | TEST → PROD token confusion | Use a TEST-env Google Pay token on the prod endpoint (TEST tokens are accepted by Google's libs but should be rejected server-side) | CRITICAL — free charges |
| 2 | Token replay | Replay same `paymentMethodData.token` for a second charge | CRITICAL if accepted |
| 3 | Amount tampering after tokenize | Token is for $1; backend request says amount=$1000 — does backend re-verify? | CRITICAL |
| 4 | `gateway` swap | Token tokenized for gateway A; submit to gateway B endpoint | CRITICAL if backend doesn't bind |
| 5 | `merchant_id` swap | Submit attacker-merchant token to victim-merchant endpoint | CRITICAL |
| 6 | Token-less charge | Drop the token field, send only `tokenized: true` flag | CRITICAL if accepted (server trusts boolean) |
| 7 | Direct PAN tokenization assumption | Backend treats DIRECT (raw PAN) tokens differently from network tokens — try both | MEDIUM-HIGH |
| 8 | `protocolVersion` downgrade | `ECv1` (legacy) when `ECv2` is current — older protocols had weaker crypto | MEDIUM |
| 9 | Order-id substitution | Charge token bound to order A; substitute order B in the API call | CRITICAL — pay for cheap, get expensive |
| 10 | Refund without capture race | Refund the pending GPay charge before backend captures | HIGH — depends on processor reconciliation |

### Probe commands

```python
# 1) Confirm TEST flag in client JS
search_history(query="environment", in_response_body=True)
search_history(query='"TEST"', in_response_body=True)

# 2) Replay the token
session_request(name="user", method="POST", path="/checkout/charge",
                json_body={"order_id":"X","payment_method_token":"<gpay_token>","amount":100})
# Replay immediately with order_id=Y, amount=10000:
session_request(name="user", method="POST", path="/checkout/charge",
                json_body={"order_id":"Y","payment_method_token":"<same_token>","amount":10000})
```

### Save template

```python
save_finding(
  vuln_type="payment_token_replay",
  severity="critical",
  title="Google Pay token replayable across orders / amounts (no backend re-verification)",
  endpoint="https://target.tld/checkout/charge",
  evidence={"logger_index": N, "reproductions":[...], "notes": "$10 token charged $10000 order, both captured"},
)
```

---

## §4 Apple Pay (Web + iOS)

### Signals
- "Apple Pay" button on checkout (Web: `ApplePaySession`, iOS: PassKit)
- Request bodies containing `paymentData.data` (base64), `paymentData.signature`, `paymentData.header.ephemeralPublicKey`, `paymentData.version`
- `PKPaymentToken` shape in app-to-backend traffic
- Merchant ID in client config (`merchant.<reverse_domain>`)

### Flow to map
```
1. Client requests merchant session — POST /apple-pay/start (proxies to Apple Pay session endpoint)
2. User authorizes — Apple returns PKPaymentToken (paymentData encrypted with Apple+merchant cert)
3. App posts token + amount to backend
4. Backend decrypts via payment gateway and charges
```

### Attack matrix

| # | Attack | Probe | Severity |
|---|---|---|---|
| 1 | Merchant session swap | Initiate Apple Pay for victim merchant, complete on attacker merchant page (or vice versa) | CRITICAL |
| 2 | `merchantIdentifier` substitution | Sub `merchant.attacker.com` in POST to `/apple-pay/start` | HIGH |
| 3 | Sandbox token on prod | Apple Pay sandbox cert chain accepted by prod decryption endpoint | CRITICAL |
| 4 | Token reuse | Replay same `PKPaymentToken.paymentData` | CRITICAL |
| 5 | Amount tampering post-tokenize | Same as Google Pay #3 — token for $1, request says $1000 | CRITICAL |
| 6 | Strip `signature` from paymentData | Server may parse without verifying signature | CRITICAL |
| 7 | `transactionIdentifier` reuse | Reuse transactionIdentifier (helps idempotency dedupe; some apps don't validate uniqueness) | HIGH |
| 8 | `applicationData` injection | Inject params via `applicationData` (echoed in some merchant integrations) | MEDIUM |
| 9 | Cross-region token | EU-region merchant token sent to US-region endpoint | MEDIUM-HIGH |
| 10 | Domain verification bypass | `/.well-known/apple-developer-merchantid-domain-association` — does attacker domain serve a fake one and Apple still validates? Usually no, but worth confirming. | MEDIUM |

### Probe commands

```python
# Capture both /apple-pay/start and /checkout
search_history(query="apple-pay", in_url=True)
search_history(query="PKPaymentToken", in_request_body=True)

# Token replay
session_request(name="user", method="POST", path="/checkout/apple-pay/charge",
                json_body={"token":"<paymentData>","amount":1,"order":"X"})
session_request(name="user", method="POST", path="/checkout/apple-pay/charge",
                json_body={"token":"<same_paymentData>","amount":10000,"order":"Y"})
```

---

## §5 Samsung Pay

Less common; less-tested by researchers (higher chance of finding bugs).

### Signals
- "Samsung Pay" button (Android only, Samsung Knox-required device)
- Knox-attestation tokens in headers (`X-Samsung-Knox-Token`)
- Endpoints: `/samsungpay/`, `/spay/`

### Attack matrix (subset; same patterns as GPay/Apple Pay)
- Knox attestation token replay / cross-user
- Sandbox vs production endpoint confusion
- Amount tampering post-tokenize
- Direct call to `/samsungpay/charge` without going through Samsung's SDK

Samsung's SDK gates much of this client-side — backend trust is the gap.

---

## §6 IAP server-side validation (Apple StoreKit, Google Play Billing)

Most common and most reportable mobile payment bug class. Full attack matrix lives in `playbook-mobile-dynamic.md` §7. Cross-reference here.

**Don't double-test** — if you have the IAP playbook running, skip this section.

---

## §7 3-D Secure 2.x bypass

### Signals
- 3DS challenge step in checkout: redirect to `acs.<bank>.com` or iframe-load `https://*.cardinalcommerce.com`
- Response fields `eci`, `cavv`, `xid`, `dsTransId`, `acsTransId`
- "Frictionless" vs "Challenge" flow

### Attack matrix

| # | Attack | Probe | Severity |
|---|---|---|---|
| 1 | Force frictionless flow | Set `threeDSRequestorChallengeInd: "01"` (no challenge preference) on a card that would normally challenge | HIGH — bypass cardholder verification |
| 2 | ECI downgrade | Replace `eci: "05"` (full auth) with `eci: "06"` or `eci: "07"` (no auth, merchant liable) — and confirm charge still succeeds | HIGH — confirms missing server check |
| 3 | Empty `cavv` accepted | Send `cavv: ""` or `cavv: null` | CRITICAL if charge captures |
| 4 | `dsTransId` reuse | Reuse one successful 3DS transaction ID across multiple charges | HIGH |
| 5 | Challenge bypass via JSON | Some merchant integrations skip ACS round-trip if `bypass3ds: true` in body | CRITICAL |
| 6 | Setup-intent reuse (Stripe) | `setup_intent` (saved card) doesn't trigger 3DS on next charge | HIGH — depends on setup |
| 7 | Issuer attempt-not-enrolled | When card issuer is not enrolled, ECI "06"/"01" used; merchant still liable — confirm backend treats this as authenticated | MEDIUM |

### Probe commands

```python
# Capture the full 3DS flow first via browser
browser_navigate("https://target.tld/checkout")
# After challenge resolves, dump the captured backend confirm:
search_history(query="cavv", in_request_body=True)
search_history(query="dsTransId", in_request_body=True)

# Now mutate
resend_with_modification(index=<confirm_idx>, modify_body='...{"cavv":"","eci":"07","dsTransId":"<reused>"}...')
```

---

## §8 SCA exemption abuse (PSD2 / EU)

### Signals
- Target operates in EU / processes EU cards
- Stripe `payment_intent` with `setup_future_usage`, `off_session`, `mandate_data`
- `exemption` field in checkout: `low_value`, `merchant_initiated`, `trusted_beneficiary`, `recurring`

### Attack matrix

| # | Attack | Probe | Severity |
|---|---|---|---|
| 1 | Low-value exemption stacking | <€30 limit — split a €100 purchase into 4×€25 (each exempt) | HIGH |
| 2 | Trusted-beneficiary self-add | Add attacker-controlled merchant to victim's trusted list (CSRF / IDOR on whitelist endpoint) | CRITICAL |
| 3 | Merchant-initiated transaction (MIT) without prior CIT | Send `off_session: true` for a card that never had a customer-initiated transaction with cardholder authentication | CRITICAL |
| 4 | TRA (Transaction Risk Analysis) flag client-set | `transaction_risk_score: 0.1` provided by client and trusted by backend | HIGH |
| 5 | Recurring-exemption first-charge | First charge of subscription should be CIT with SCA; some merchants mark it MIT | HIGH |

---

## §9 Wallet linking / unlinking

Often forgotten surface — high impact when broken.

### Attack matrix

| # | Attack | Probe | Severity |
|---|---|---|---|
| 1 | Link wallet without re-auth | `POST /wallet/link {"provider":"gpay","token":"<attacker_gpay>"}` from victim's session — does it succeed without password / SCA / 2FA? | CRITICAL — attacker funds victim purchases or vice versa |
| 2 | Unlink victim's wallet (CSRF) | `DELETE /wallet/<id>` without CSRF token / origin check | HIGH — DoS on payment |
| 3 | Wallet ID enumeration | `GET /wallet/<id>` walks sequential / predictable IDs | MEDIUM-HIGH |
| 4 | Default-card swap (IDOR) | `PATCH /wallet/default {"card_id":"<victim_card>"}` | HIGH |
| 5 | Wallet add-card race | Add card + delete account simultaneously — does card persist orphaned? | MEDIUM |

---

## §10 Recovery flows (the weakest link)

Strong auth + weak recovery = ATO. Always test.

### Signals
- "Forgot password" / "Forgot passkey" / "Reset 2FA" / "Use backup code"
- SMS / email codes
- Security questions
- Trusted-device registration

### Attack matrix

| # | Attack | Probe | Severity |
|---|---|---|---|
| 1 | Reset token in URL | `?token=<long_jwt_or_hex>` — long enough? bound to user? expires? | CRITICAL if predictable |
| 2 | Token leak via Referer | Reset page links to third-party (CDN, analytics) — token in Referer | HIGH |
| 3 | Token reuse | Reset → login → reset link still works | MEDIUM-HIGH |
| 4 | Email substitution in token | Token contains `email` field — change it, server still accepts | CRITICAL — change-of-account ATO |
| 5 | Rate-limit absent on code submit | `concurrent_requests(...)` 6-digit code brute force | CRITICAL |
| 6 | Email change race | Start password reset, change email mid-flow, complete reset → reset goes to new email | CRITICAL |
| 7 | Account linking abuse | Link attacker SSO IDP to victim email (verification skipped) | CRITICAL |
| 8 | Backup code reuse / count not enforced | Use same backup code twice; or all 10 codes don't actually invalidate after use | HIGH |
| 9 | Trusted device add via session only | Add a "remember this device" entry without 2FA confirm | HIGH |
| 10 | Recovery answer enumeration | Wrong answer responds differently than correct username | LOW-MEDIUM |

---

## Cross-cutting probes (run once before diving in)

```python
# 1) Are tokens in URLs at all?
search_history(query="access_token=", in_url=True, limit=50)
search_history(query="code=", in_url=True, limit=50)
search_history(query="token=", in_url=True, limit=50)

# 2) Where do JWTs flow?
search_history(query="eyJ", in_request_body=True, limit=50)   # JWT prefix
search_history(query="eyJ", in_response_body=True, limit=50)

# 3) Are refresh tokens long-lived and stored client-side?
search_history(query="refresh_token", in_response_body=True)

# 4) Payment endpoints
search_history(query="/checkout", in_url=True)
search_history(query="/charge", in_url=True)
search_history(query="/iap/", in_url=True)

# 5) Knowledge sweep on captured /authorize and /token
auto_probe(url="https://target.tld/authorize", categories=["oauth", "oauth_device_flow"])
auto_probe(url="https://target.tld/oauth/token", categories=["oauth"])
auto_probe(url="https://target.tld/webauthn/register/finish", categories=["webauthn_passkey"])
auto_probe(url="https://target.tld/checkout/charge", categories=["payment_flow"])
```

---

## Stop conditions

Bail to router when:
- 25 probes across ≥3 sections, no anomaly / no replay success / no state mismatch.
- Target uses only password auth with no SSO, no payment, no FIDO → this playbook does not apply.
- Recovery + auth + payment all behind a single SSO that you can't enumerate the IdP for → load `playbook-red-team-web.md` for SSO mix-up chains.

---

## Hand-off + Chain examples

These chains turn one §-finding into a higher-severity chain (`chain-findings.md`):

- **OAuth open redirect → ATO:** §1#1 + a phishing-friendly URL → full account takeover via stolen `code`. Pays 5–10x of redirect alone.
- **PKCE downgrade + code reuse:** §1#3 + §1#5 → silent ATO without victim interaction.
- **Recovery email change race → password reset to attacker:** §10#6 → standalone CRITICAL.
- **WebAuthn delete + password downgrade:** §2#13 + §2#7 → bypass 2FA + reset password.
- **GPay token replay across orders:** §3#2 + §3#9 → unlimited cheap-token charges on expensive orders.
- **3DS ECI downgrade + setup-intent reuse:** §7#2 + §7#6 → recurring charges without strong auth.

---

## Anti-patterns

- **Don't** fuzz `redirect_uri` with 1000 payloads — `auto_probe(categories=["oauth"])` covers the working bypasses. Spam wastes the WAF budget.
- **Don't** mark "missing PKCE" as critical unless you also confirm the code can be stolen (Referer, postMessage, open-redirect). Missing PKCE alone is medium at best.
- **Don't** report `attestation: none` as critical unless you actually authenticate as the registered user afterwards. Acceptance ≠ exploitable.
- **Don't** brute-force 6-digit recovery codes for hours — confirm rate-limit absence in 100 requests, save finding, move on.
- **Don't** treat sandbox-receipt-on-prod as theoretical — actually demonstrate one full charge cycle in writing.
- **Don't** skip §10 — recovery is where every "strong auth" target falls.
