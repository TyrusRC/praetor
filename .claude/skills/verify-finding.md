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

## Evidence Requirements

Each vulnerability type needs SPECIFIC proof. Without meeting these requirements, the finding is NOT confirmed.

### SQL Injection
- **Time-based:** Response time > 3x baseline (e.g., SLEEP(3) causes 3+ second delay). Test 2-3 times to rule out network jitter.
- **Error-based:** SQL error string in response (unclosed quotation, syntax error, ORA-, mysql_fetch, pg_query)
- **Blind OOB:** Collaborator DNS/HTTP interaction via `auto_collaborator_test`
- **NOT sufficient:** Status code change alone. Generic error page. Different response length without error strings.

### XSS (Cross-Site Scripting)
- **Reflected:** Payload appears UNENCODED in response body (exact string match of `<script>`, `onerror=`, etc.)
- **Stored:** Payload appears on a DIFFERENT page after submission
- **NOT sufficient:** Payload appears URL-encoded (%3Cscript%3E) or HTML-encoded (&lt;script&gt;)

### SSRF (Server-Side Request Forgery)
- **Confirmed:** Collaborator HTTP or DNS interaction received via `auto_collaborator_test` or `get_collaborator_interactions`
- **Partial:** Internal service response content (internal IPs, error messages from internal services)
- **NOT sufficient:** Different status code alone. Timeout without Collaborator interaction.

### Open Redirect
- **Confirmed:** Collaborator interaction (server followed redirect to Collaborator URL) via `test_open_redirect`
- **Partial:** Location header contains external URL (client-side redirect — still reportable but lower severity)
- **NOT sufficient:** Parameter reflected in page body but no redirect headers

### LFI / Path Traversal
- **Linux:** Response contains `root:x:`, `daemon:`, `/bin/bash`, `/bin/sh`
- **Windows:** Response contains `[fonts]`, `[extensions]`, `for 16-bit app`
- **PHP wrappers:** Base64-encoded file contents (long alphanumeric string starting with PD9, PCFE, etc.)
- **NOT sufficient:** Different error message. Status code change. Generic "file not found".

### IDOR / Broken Access Control
- **Confirmed:** `compare_auth_states` shows same response (>90% similarity) with DIFFERENT user credentials
- **Confirmed:** Accessing another user's data with lower-privilege credentials
- **NOT sufficient:** Same status code with completely different content. Admin-only endpoint returning 200 with "access denied" in body.

### File Upload
- **Confirmed:** Uploaded file is ACCESSIBLE at a URL AND server processes it (PHP executes, SVG renders with XSS)
- **Partial:** Upload accepted (200) but file location unknown — still reportable if dangerous extensions accepted
- **NOT sufficient:** Upload rejected with 200 status. Upload accepted but file stored with safe extension.

## Decision

### If VERIFIED:

Save with full evidence:
```
save_target_intel(domain, "findings", {
  "endpoint": "...",
  "vulnerability_type": "...",
  "parameter": "...",
  "status": "confirmed",
  "severity": "HIGH/MEDIUM/LOW",
  "evidence": {payload, baseline response, exploit response, collaborator proof},
  "poc_request": {method, path, headers, expected_behavior},
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
