---
name: verify-finding
description: Verify a suspected vulnerability is real with reproducible evidence before marking confirmed. Three steps in order — Logger replay → assess_finding → save_finding. Skipping any step results in either a server-side rejection or a false-positive in the report.
---

# Verify Finding

> **Rule reference (R12):** rules in this skill are NOT restated. The pipeline below references `hunting.md` Rule 10 (save-finding pipeline), Rule 11 (baseline), Rule 13 (verified evidence). When this skill text disagrees with the rule numbers, the rule wins.

```
Step 0: Logger replay  →  Step 1: assess_finding  →  Step 2: save_finding
prove reproducible        prove reportable          persist
```

Skip Step 0 → server rejects with 400 (no resolvable evidence index).
Skip Step 1 → wasted tokens drafting reports for findings that fail the 7-Question Gate downstream.

## Step 0 — Logger Replay (MANDATORY)

1. Identify the suspicious request via `get_logger_entries` (preferred) or `get_proxy_history`. Note its index.
2. `resend_with_modification(index)` — confirm the same anomaly (status, body delta, error string).
3. The Logger index of the **confirming replay** is what goes into `evidence.logger_index`.
4. **Timing/blind classes** (`sqli_blind`, `sqli_time`, `ssrf_blind`, `race_condition`, `request_smuggling`, `ssti_blind`, `command_injection_blind`, `xxe_blind`): replay 2 more times after the confirmation. Capture `{logger_index, elapsed_ms, status_code}` for each → these become `reproductions[]`.
5. If the anomaly does not reproduce on the second send → mark `likely_false_positive` and STOP. Do not call `save_finding`.

The server hard-rejects `save_finding` calls without a resolvable `evidence.logger_index` / `proxy_history_index` / `collaborator_interaction_id`.

## Step 1 — assess_finding (MANDATORY)

```
assess_finding(
  vuln_type="<class>",          # "sqli", "xss", "idor", ...
  evidence="<what you saw>",    # include "3/3" for timing
  endpoint="<full URL>",
  parameter="<name>",
  domain="<domain>",            # required: enables Q1 scope + Q4 dup
)
```

Verdict → action:

| Verdict | Action |
|---|---|
| `REPORT` | Proceed to Step 2 with `confidence=<suggested>` |
| `NEEDS MORE EVIDENCE` | Strengthen the flagged items, redo Step 0, re-assess |
| `DO NOT REPORT` | Mark `likely_false_positive`, move to next target |

Calling `save_finding` without `assess_finding` violates Rule 25.

## Step 2 — save_finding

Pass the suggested confidence directly. The Burp gate will reject only if Step 0's index is wrong.

## Efficient Evidence Extraction

Use specialised tools, not full responses:
- `extract_regex(index, '<proof_pattern>', group=1)` — just the proof
- `extract_json_path(index, '$.error')` — JSON field
- `get_response_hash(index)` — compare hashes for consistency
- `extract_headers(index, ['Set-Cookie', 'Location'])` — headers only

## Evidence Requirements (per vuln class)

Each class has a SPECIFIC bar. Without it, the finding is NOT confirmed.

### SQL Injection
- **Time-based:** response time > 3× baseline; replay 3×; compare to baseline
- **Error-based:** SQL error string (unclosed quote, ORA-, mysql_fetch, pg_query, ODBC, OLE DB)
- **Union:** UNION SELECT-injected data visible (version, table names, distinct column count)
- **Boolean blind:** consistent content delta between AND 1=1 and AND 1=2
- **Blind OOB:** Collaborator DNS/HTTP via `auto_collaborator_test`
- **NOT sufficient:** status code alone, generic error page, length without error string or boolean stability

### XSS
- **Reflected:** payload UNENCODED in body in executable context
- **Stored:** payload appears on a DIFFERENT page after submission
- **DOM:** payload reaches innerHTML/eval — verify via `analyze_dom` source→sink
- **NOT sufficient:** URL-encoded / HTML-encoded reflection, payload inside JS string properly escaped, inside HTML comment

### SSRF
- **Confirmed:** Collaborator HTTP/DNS via `auto_collaborator_test` or `get_collaborator_interactions`
- **Confirmed:** cloud-metadata content (ami-id, AccessKeyId, subscriptionId)
- **Partial:** internal-service response (internal IPs, Redis/SSH banners)
- **NOT sufficient:** status alone, timeout without Collaborator, connection-refused

### Open Redirect
- **Confirmed:** Collaborator interaction via `test_open_redirect`
- **Partial:** Location header to attacker-controlled external URL (LOW alone)
- **NOT sufficient:** parameter reflected in body but no redirect headers

### LFI / Path Traversal
- **Linux:** `root:x:`, `daemon:`, `/bin/bash`, `/bin/sh`, `nobody:`
- **Windows:** `[fonts]`, `[extensions]`, `for 16-bit app`, `[mail]`
- **PHP wrappers:** base64 contents (PD9..., PCFE...)
- **Source code:** PHP/config visible
- **NOT sufficient:** different error, status change, "file not found", length anomaly without file content

### IDOR
- **Confirmed:** `compare_auth_states` shows >90% similarity with DIFFERENT user creds
- **Confirmed:** read another user's PII with lower-priv creds
- **Confirmed:** modify/delete another user's resources via their ID
- **Confirmed (ID enumeration / BOLA / BFLA):** sequential / predictable ID space (auto-increment, UUIDv1 monotonic, base32 timestamp) yields cross-user data when walked. Per Rule 6 this is authorization testing, NOT credential brute force. Bar: (a) demonstrate the pattern (e.g. ID 1001→1010 each return distinct user records), (b) confirm at least 2-3 IDs return another user's data, (c) cap PoC count to avoid mass exfil per Rule 7. Tag evidence with "sequential", "predictable", "id enumeration", "cross-app", or "uuidv1" so `assess_finding` boosts impact.
- **Confirmed (BFLA — function-level):** lower-priv role can call admin/internal function (e.g. `/api/admin/users/delete` succeeds for `user` role). Distinct from object-level IDOR.
- **NOT sufficient:** same status with completely different content, admin endpoint returning 200 with "access denied" body, sequential IDs without verifying distinct user content

### File Upload
- **Confirmed:** uploaded file ACCESSIBLE at URL AND server processes it (PHP exec, SVG XSS, JSP exec)
- **Partial:** upload accepted (200) but location unknown — reportable only if dangerous extensions accepted
- **NOT sufficient:** upload rejected with 200 + error in body, file stored with safe extension

### SSTI
- **Confirmed:** math eval (7*7→49) — verify NOT client-side (Angular) by checking pre-JS response
- **Confirmed:** RCE probe returns system output (uid=, hostname, whoami)
- **Confirmed:** config/env leak (SECRET_KEY, DB creds)
- **Engine differentiation:** `7*'7'` = "7777777" → Jinja2; "49" → Twig
- **NOT sufficient:** literal expression reflected, client-side template, JS-context expression

### Command Injection
- **Confirmed:** unique marker echoed (`; echo UNIQUE_STRING` → UNIQUE_STRING in response)
- **Confirmed:** system output (uid=, whoami, hostname)
- **Time-based:** `; sleep 5` causes 5s+ delay (3 replays, vs baseline)
- **Blind OOB:** Collaborator via `; curl COLLAB` or `; nslookup COLLAB`
- **NOT sufficient:** status 500 alone, different error, timeout without timing correlation

### CSRF
- **Confirmed:** state-change without CSRF token (remove entirely; action executes)
- **Confirmed:** action succeeds with token from DIFFERENT user session
- **Confirmed:** POST→GET method-override bypass
- **Impact:** action MUST have real impact (password, funds, settings)
- **NOT sufficient:** missing CSRF on GET, no side effect, SameSite present

### Race Condition
- **Confirmed:** `test_race_condition` shows action ran MORE times than expected (coupon 3×, balance debited 3×)
- **Confirmed:** duplicate records from simultaneous identical requests
- **Quantify:** how much money/credit gained, repeatedly
- **NOT sufficient:** multiple 200s (server may return 200 but process once), <30% success rate (timing, not TOCTOU)

### JWT
- **alg:none:** server accepts JWT with `alg=none` and empty signature
- **Weak secret:** re-signed with common secret accepted (secret, password, 123456)
- **Algorithm confusion:** RS256→HS256, signed with public key, accepted
- **kid injection:** path traversal/SQLi in `kid` returns different data
- **NOT sufficient:** decoding the JWT (expected), 200 response while ignoring the JWT

### CORS
- **Confirmed:** server reflects arbitrary Origin in ACAO WITH ACAC: true
- **Confirmed:** server accepts Origin: null with credentials
- **Partial:** Origin reflected without credentials (LOW — read public data only)
- **NOT sufficient:** wildcard ACAO without credentials (browser blocks credentialed)

### Mass Assignment
- **Confirmed:** `role=admin` / `is_admin=true` actually changes privilege (verify via profile after)
- **Confirmed:** `price=0` / `discount=100` actually changes amount
- **Confirmed:** `verified=true` bypasses email verification
- **NOT sufficient:** server accepts extra field without using it

### CRLF
- **Confirmed:** injected header in response headers (X-Injected: true visible)
- **Confirmed:** Set-Cookie injection sets cookie in victim
- **Confirmed:** response splitting — body content after double CRLF
- **NOT sufficient:** CRLF reflected in body (not headers), URL-encoded CRLF in Location value

### HPP
- **Confirmed:** duplicate parameter causes different behaviour (status, content, returned data)
- **Confirmed:** backend uses different param instance than frontend (WAF/auth bypass)
- **NOT sufficient:** server consistently uses first/last, length differs <10%

### Deserialization
- **Confirmed:** crafted serialized object → server error with deserialization stack (ObjectInputStream, unserialize, Marshal.load)
- **Confirmed:** RCE via gadget chain (output in response, Collaborator callback)
- **Confirmed:** DoS via deeply nested object (measurable degradation)
- **NOT sufficient:** base64 in parameter (might not be deserialized), input accepted without error

### GraphQL
- **Introspection:** full schema returned from `__schema`
- **Injection:** SQL error from resolver arguments
- **Batch abuse:** unbounded batch processed (DoS vector)
- **Persisted-query attacks:** APQ hash collision accepted, hash preimage attacker-controlled, or old hashes cached forever
- **Alias amplification:** 1000+ aliases on the same field accepted (DoS-class)
- **NOT sufficient:** endpoint exists, field-suggestion enabled (low info leak)

### Password Reset
- **Confirmed (token reuse):** same reset link succeeds 2+ times — token not invalidated after first use
- **Confirmed (cross-account):** token issued for victim works for attacker's account or vice versa (account_id parameter manipulation)
- **Confirmed (race):** simultaneous reset requests issue different tokens both valid (TOCTOU)
- **Confirmed (weak token):** sequential / predictable / time-based reset token (epoch ms, sequential int)
- **Confirmed (host header poison):** `Host: attacker.com` causes reset link to point at attacker host
- **Confirmed (no rate limit on auth):** rate-limit-missing IS reportable here (sensitive endpoint)
- **NOT sufficient:** weak password policy alone, missing email confirmation on signup

### API Key / Token Leak
- **Confirmed:** key found in JS bundle, source map, error response, or git history AND key is live (validate against the API)
- **Confirmed:** token scope grants access beyond what owner intended (e.g. read-only key allows write)
- **Confirmed:** internal key exposed via debug header / verbose error
- **Severity scaling:** CRITICAL if AWS/GCP root keys; HIGH if 3rd-party with billing impact (Stripe, SendGrid); MEDIUM if scoped/limited
- **NOT sufficient:** dummy / sample / commented-out key, key with no permissions

### Auth Bypass (chain or standalone)
- **Confirmed (session fixation):** server accepts session ID set BEFORE authentication; victim's session becomes attacker-controlled
- **Confirmed (forced browsing / direct object access):** `/admin/dashboard` accessible without valid session or with low-priv role
- **Confirmed (HTTP method bypass):** `GET /api/users/delete/1` works when only POST should
- **Confirmed (path normalization bypass):** `/admin/..;/dashboard`, `/admin%2f`, `/admin/.`, `/admin/%2e/`
- **Confirmed (header bypass):** `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1` grants admin access
- **Confirmed (referer-based auth):** changing Referer to internal URL grants access
- **NOT sufficient:** missing rate limit on login (separate finding), missing CAPTCHA

## Decision

### VERIFIED → save with full evidence

```
save_target_intel(domain, "findings", {
  "endpoint": "...", "vulnerability_type": "...", "parameter": "...",
  "status": "confirmed", "severity": "CRITICAL/HIGH/MEDIUM/LOW",
  "evidence": {payload, baseline, exploit, collaborator_proof},
  "poc_request": {method, path, headers, body, expected_behavior},
  "impact": "...",
  "last_verified": "<ts>", "verification_failures": 0
})
```

### NOT VERIFIED → update status

- **First failure:** `stale` (intermittent or patched)
- **Second failure (verification_failures >= 2):** `likely_false_positive`
- Note what changed (different response, patched, WAF blocked)

`generate_report` will hard-delete `likely_false_positive` entries.

## Cross-references

- **7-Question Gate + NEVER SUBMIT:** `.claude/rules/hunting.md` (always loaded)
- **Conditionally Valid + chains:** `chain-findings.md`
- **Effort vs noise calls:** `noise-budget.md`

## Hard Rules

- Never confirm without meeting evidence requirements above
- Never skip Step 0 replay
- Never trust single-request timing (jitter — replay 3×, compare to baseline)
- Never report IDOR without access to ANOTHER user's data
- Never report XSS without payload in executable context (not encoded, not commented)
