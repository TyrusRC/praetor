---
name: verify-finding
description: Verify a suspected vulnerability is real with reproducible evidence before marking confirmed
---

# Verify Finding

You are verifying a suspected vulnerability. Your job is to PROVE it's real or mark it as a false positive. No guessing, no assumptions.

## Process

1. **Load the finding** from `load_target_intel(domain, "findings")`
2. **Re-send the PoC request** exactly as stored — use `session_request` or `send_http_request` with the exact method, path, headers, body
3. **Check the expected behavior** matches what was originally observed
4. **Test 2-3 times** for timing-based findings to rule out network jitter

## Evidence Requirements

Each vulnerability type needs SPECIFIC proof. Without meeting these requirements, the finding is NOT confirmed.

### SQL Injection
- **Time-based:** Response time > 3x baseline (e.g., SLEEP(3) causes 3+ second delay). Test 2-3 times to rule out network jitter. Compare against baseline timing.
- **Error-based:** SQL error string in response (unclosed quotation, syntax error, ORA-, mysql_fetch, pg_query, ODBC, Microsoft OLE DB)
- **Union-based:** Response contains data from injected UNION SELECT (version string, table names, different column count)
- **Boolean-blind:** Consistent response difference between AND 1=1 and AND 1=2 (content length, specific content present/absent)
- **Blind OOB:** Collaborator DNS/HTTP interaction via `auto_collaborator_test`
- **NOT sufficient:** Status code change alone. Generic error page. Different response length without error strings or consistent boolean behavior.

### XSS (Cross-Site Scripting)
- **Reflected:** Payload appears UNENCODED in response body (exact string match of `<script>`, `onerror=`, `onload=`, etc.) in an executable context
- **Stored:** Payload appears on a DIFFERENT page/request after submission
- **DOM-based:** Payload reaches a dangerous sink (innerHTML, eval) — verify via `analyze_dom` showing source-to-sink flow
- **NOT sufficient:** Payload appears URL-encoded (%3Cscript%3E) or HTML-encoded. Payload reflected inside a JavaScript string but properly escaped. Payload inside HTML comment.

### SSRF (Server-Side Request Forgery)
- **Confirmed:** Collaborator HTTP or DNS interaction received via `auto_collaborator_test` or `get_collaborator_interactions`
- **Confirmed:** Cloud metadata content in response (ami-id, instance-id, AccessKeyId, subscriptionId)
- **Partial:** Internal service response content (internal IPs, error messages from internal services, Redis/SSH banners)
- **NOT sufficient:** Different status code alone. Timeout without Collaborator interaction. Connection refused error (shows attempt but not success).

### Open Redirect
- **Confirmed:** Collaborator interaction (server followed redirect to Collaborator URL) via `test_open_redirect`
- **Partial:** Location header contains attacker-controlled external URL (client-side redirect — still reportable but lower severity)
- **NOT sufficient:** Parameter reflected in page body but no redirect headers. JavaScript redirect that doesn't actually fire.

### LFI / Path Traversal
- **Linux:** Response contains `root:x:`, `daemon:`, `/bin/bash`, `/bin/sh`, `nobody:`
- **Windows:** Response contains `[fonts]`, `[extensions]`, `for 16-bit app`, `[mail]`
- **PHP wrappers:** Base64-encoded file contents (long alphanumeric string starting with PD9, PCFE, etc.)
- **Source code:** Application source code visible (PHP tags, config files with DB credentials)
- **NOT sufficient:** Different error message. Status code change. Generic "file not found". Length anomaly without file content indicators.

### IDOR / Broken Access Control
- **Confirmed:** `compare_auth_states` shows same response (>90% similarity) with DIFFERENT user credentials
- **Confirmed:** Accessing another user's PII/data with lower-privilege credentials
- **Confirmed:** Modifying/deleting another user's resources with their ID
- **NOT sufficient:** Same status code with completely different content. Admin-only endpoint returning 200 with "access denied" in body. Different response that contains only your own data.

### File Upload
- **Confirmed:** Uploaded file is ACCESSIBLE at a URL AND server processes it (PHP executes, SVG renders with XSS, JSP executes)
- **Partial:** Upload accepted (200) but file location unknown — still reportable if dangerous extensions accepted (.php, .jsp, .aspx)
- **NOT sufficient:** Upload rejected with 200 status and error in body. Upload accepted but file stored with safe extension or in non-executable path.

### SSTI (Server-Side Template Injection)
- **Confirmed:** Mathematical expression evaluated (7*7 returns 49 in response body) — verify it's NOT client-side (AngularJS) by checking if server response contains the result before JavaScript executes
- **Confirmed:** RCE probe returns system output (uid=, hostname, whoami output)
- **Confirmed:** Config/environment leak (SECRET_KEY, database credentials via config dump)
- **Differentiate engines:** `7*'7'` = "7777777" means Jinja2, = "49" means Twig
- **NOT sufficient:** Expression reflected as literal string. Client-side template rendering (Angular/React). Expression in JavaScript context that browser evaluates.

### Command Injection
- **Confirmed:** Unique marker echoed in response (`; echo UNIQUE_STRING` and UNIQUE_STRING appears in response)
- **Confirmed:** System command output in response (uid=, whoami output, hostname)
- **Time-based:** `; sleep 5` causes 5+ second delay (test 2-3 times, compare to baseline)
- **Blind OOB:** Collaborator DNS/HTTP interaction via `; curl COLLABORATOR` or `; nslookup COLLABORATOR`
- **NOT sufficient:** Status 500 alone. Different error message. Timeout without timing correlation.

### CSRF (Cross-Site Request Forgery)
- **Confirmed:** State-changing action succeeds WITHOUT CSRF token (remove token entirely, verify action executed)
- **Confirmed:** State-changing action succeeds with CSRF token from DIFFERENT user session
- **Confirmed:** Action succeeds when switching POST to GET (method override bypass)
- **Assess impact:** The action must have real-world impact (change password, transfer funds, modify settings) — not just viewing data
- **NOT sufficient:** Missing CSRF token on GET requests. Missing CSRF on actions with no side effects. SameSite cookie attribute present (reduces but doesn't eliminate risk).

### Race Condition
- **Confirmed:** `test_race_condition` shows action succeeded MORE times than expected (e.g., coupon applied 3x, balance debited 3x)
- **Confirmed:** Duplicate records created from simultaneous identical requests
- **Quantify impact:** How much money/credit/resource can be gained? Is it consistently reproducible?
- **NOT sufficient:** Multiple 200 responses (server may return 200 but only process once). Inconsistent reproduction (< 30% success rate suggests network timing, not real TOCTOU).

### JWT Attacks
- **alg:none:** Server accepts JWT with algorithm set to "none" and empty signature — action succeeds with forged claims
- **Weak secret:** JWT re-signed with common secret (secret, password, 123456) is accepted by server
- **Algorithm confusion:** JWT changed from RS256 to HS256, signed with public key, accepted by server
- **kid injection:** Path traversal or SQLi in kid header field returns different data
- **NOT sufficient:** Decoding the JWT and seeing claims (that's expected). Server returning 200 but ignoring the JWT.

### CORS Misconfiguration
- **Confirmed:** Server reflects arbitrary Origin in Access-Control-Allow-Origin WITH Access-Control-Allow-Credentials: true
- **Confirmed:** Server accepts Origin: null with credentials (exploitable via sandboxed iframe)
- **Partial:** Origin reflected without credentials (lower impact — no cookie theft, but can read public API data cross-origin)
- **NOT sufficient:** Wildcard ACAO without credentials (browser blocks credentialed requests). CORS headers present but no sensitive data accessible.

### Mass Assignment
- **Confirmed:** Adding `role=admin` or `is_admin=true` to request actually changes the user's privilege (verify by checking profile/permissions after)
- **Confirmed:** Setting `price=0` or `discount=100` actually changes the transaction amount
- **Confirmed:** Setting `verified=true` bypasses email verification
- **NOT sufficient:** Server accepts the extra field without error but doesn't use it. Field appears in response but privilege hasn't changed.

### CRLF Injection
- **Confirmed:** Injected header appears in HTTP response headers (X-Injected: true visible in response)
- **Confirmed:** Set-Cookie injection — malicious cookie set in victim's browser
- **Confirmed:** Response splitting — injected body content after double CRLF
- **NOT sufficient:** CRLF characters reflected in response body (not headers). URL-encoded CRLF in Location header value (not a new header).

### HPP (HTTP Parameter Pollution)
- **Confirmed:** Duplicate parameter causes different behavior than single parameter (different status, significantly different response content, different data returned)
- **Confirmed:** Backend uses different parameter instance than frontend validator (WAF bypass, auth bypass)
- **NOT sufficient:** Server just uses first or last value consistently. Response length differs by < 10%.

### Deserialization
- **Confirmed:** Crafted serialized object causes server error with deserialization stack trace (ObjectInputStream, unserialize, Marshal.load)
- **Confirmed:** RCE via gadget chain (command output in response, Collaborator callback)
- **Confirmed:** Denial of service via deeply nested object (measurable performance degradation)
- **NOT sufficient:** Base64 data in parameter (might not be deserialized). Server accepts input without error (might validate but not deserialize).

### GraphQL
- **Introspection:** Full schema returned from __schema query (enumerate types, fields, mutations)
- **Injection:** SQL error strings from resolver arguments
- **Batch abuse:** Server processes unbounded batch queries (DoS vector)
- **NOT sufficient:** GraphQL endpoint exists. Field suggestions enabled (low severity info leak).

## Decision

### If VERIFIED:

Save with full evidence:
```
save_target_intel(domain, "findings", {
  "endpoint": "...",
  "vulnerability_type": "...",
  "parameter": "...",
  "status": "confirmed",
  "severity": "CRITICAL/HIGH/MEDIUM/LOW",
  "evidence": {payload, baseline response, exploit response, collaborator proof},
  "poc_request": {method, path, headers, body, expected_behavior},
  "impact": "What can an attacker actually do with this?",
  "last_verified": "<current timestamp>",
  "verification_failures": 0
})
```

### If NOT VERIFIED:

Update the finding status:
- **First failure:** Set status to `stale` (might be intermittent or patched)
- **Second failure (verification_failures >= 2):** Set status to `likely_false_positive`
- Add a note explaining what changed (different response, patched, WAF blocked, etc.)

```
save_target_intel(domain, "findings", {
  ...existing_finding,
  "status": "stale" or "likely_false_positive",
  "verification_failures": N,
  "last_verified": "<current timestamp>"
})
```

## Never

- Never mark as confirmed without meeting the evidence requirements above
- Never skip re-sending the PoC request (even if you "remember" it worked before)
- Never trust timing from a single request (network jitter exists — compare to baseline, test 2-3 times)
- Never assume impact — test what the attacker can actually achieve
- Never report IDOR without proving access to ANOTHER user's data (not your own)
- Never report XSS without confirming the payload is in an executable context (not encoded, not commented)
