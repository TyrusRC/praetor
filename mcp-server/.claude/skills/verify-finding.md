---
name: verify-finding
description: Verify a suspected vulnerability is real with reproducible evidence before marking confirmed
---

# Verify Finding — Evidence-Based Confirmation

You are verifying a suspected vulnerability. Do NOT mark anything as confirmed unless it meets the evidence requirements below.

## Step 1: Load the Finding

Load the finding details from memory or from the current session context. You need:
- The exact request (method, path, headers, body) that triggered the anomaly
- The parameter under test
- The payload used
- The observed anomaly (timing, error, reflection, status code change)

If any of these are missing, reconstruct them before proceeding.

## Step 2: Establish Baseline

Send a **clean request** (no payload) using `session_request(session, method, path, ...)` and record:
- Response time (for timing-based checks)
- Response length
- Status code
- Key response content

This is your baseline for comparison.

## Step 3: Re-send the PoC

Send the **exact same request** that produced the anomaly using `session_request`. Compare against baseline.

## Step 4: Check Evidence Requirements

Each vulnerability type has specific evidence requirements. The finding is **confirmed** only if the requirement is met.

### SQL Injection
- **Time-based blind:** Response time is **>3x the baseline** on a `SLEEP`/`WAITFOR`/`pg_sleep` payload, AND returns to normal on a non-sleeping payload. Test at least 2 different delay values.
- **Error-based:** Response contains a **database error string** (e.g., `You have an error in your SQL syntax`, `ORA-`, `unterminated quoted string`, `pg_query`).
- **Out-of-band:** Call `generate_collaborator_payload("dns")`, inject it via SQL (e.g., `LOAD_FILE`, `UTL_HTTP`, `xp_dirtree`), then call `get_collaborator_interactions()` and confirm a DNS lookup arrived.
- **Union-based:** Injected `UNION SELECT` returns controlled data in the response.

### XSS (Reflected/Stored)
- The payload is **reflected in the response without encoding**. Verify the exact payload string (e.g., `<script>`, `onerror=`) appears in the HTML response body, not inside an attribute that is HTML-encoded.
- For stored XSS: confirm the payload persists by requesting the page again without the payload in the URL/body.

### SSRF
- Call `generate_collaborator_payload("http")` or `generate_collaborator_payload("dns")`.
- Inject the Collaborator URL as the SSRF payload.
- Call `get_collaborator_interactions()` and confirm an **HTTP or DNS interaction** from the target server (not your own IP).

### Open Redirect
- Inject a Collaborator URL or external domain as the redirect target.
- Confirm the response is a **3xx redirect** with the `Location` header pointing to the injected URL, OR the page performs a client-side redirect to it.

### LFI / Path Traversal
- The response contains **recognizable file contents**:
  - Linux: `root:x:0:0:` (from `/etc/passwd`)
  - Windows: `[fonts]` or `[extensions]` (from `win.ini`)
  - Application files: known config patterns

### IDOR
- Call `compare_auth_states(session, method, path, ...)` with two different user contexts.
- Confirmed if **User A can access User B's resource** — the response contains User B's data, not an error or empty response.

### File Upload
- Upload a test file (e.g., a file with a benign marker string).
- Confirm the file is **accessible at the returned URL** and the content is served (not rejected or sanitized).
- For RCE via upload: confirm the server **executes** the file (e.g., PHP code returns computed output, not raw source).

### Race Condition
- Use `test_race_condition(session, ...)` to send concurrent requests.
- Confirmed if the operation succeeds **more times than it should** (e.g., double-spend, duplicate vote, extra coupon use).

### SSTI
- The response contains the **computed result** of a template expression (e.g., injecting `{{7*7}}` returns `49`, not `{{7*7}}`).

### XXE
- **Out-of-band:** Inject an external entity with a Collaborator URL. Confirm DNS/HTTP interaction via `get_collaborator_interactions()`.
- **In-band:** Injected entity resolves and file contents appear in the response.

### CORS Misconfiguration
- Use `test_cors(session)` results. Confirmed if the server reflects an **arbitrary origin** in `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`.

## Step 5: Record the Result

### If CONFIRMED:
1. Call `save_finding(title, severity, evidence)` with:
   - The exact request/response pair
   - The evidence that meets the requirement above
   - Impact assessment (what an attacker can do)
2. Update target intel: `save_target_intel(domain, "findings", updated_findings)` with status `"confirmed"`.

### If NOT confirmed:
1. Load current finding data and increment `verification_failures` count.
2. If `verification_failures >= 2`: mark the finding as `"likely_false_positive"` and move on.
3. If `verification_failures == 1`: mark as `"stale"` — it may work under different conditions (different session, timing, etc.).
4. Update target intel with the new status.

## Rules

- **NEVER mark a finding as confirmed without meeting the evidence requirements above.** "Interesting behavior" is not a finding.
- If the evidence is ambiguous (e.g., timing is 2.5x baseline instead of 3x), record it as `"suspected"` with notes, not `"confirmed"`.
- Always test with at least one **negative control** (a payload that should NOT trigger the vulnerability) to rule out coincidence.
- If verification requires Collaborator and it is not available, note this limitation and mark the finding as `"needs_collaborator"`.
