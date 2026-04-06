---
name: resume
description: Resume bug bounty testing from a previous session with re-verification and coverage gaps
---

# Resume Testing

You are continuing a bug bounty engagement from a previous session. Your priority: restore context efficiently, verify nothing changed, and identify the highest-value next actions.

## Step 1: Load Context

1. Ask the user for the target domain (or detect from Burp scope/active session)
2. Call `load_target_intel(domain, "all")` to get the full summary
3. If no intel exists: "No previous session data found for {domain}. Start fresh with the hunt skill."

## Step 2: Create/Restore Session

1. Check `list_sessions` for an existing session targeting this domain
2. If no session exists: `create_session` with the target base URL from profile
3. If auth is stored in profile:
   - Check if session cookies are still valid by sending a quick authenticated request
   - If 401/403: re-authenticate using the stored login flow (`run_flow` with the auth steps from profile)
   - If 200: session is still valid, proceed
4. Verify scope is configured: `get_scope` — if empty, re-apply from profile's scope_rules

## Step 3: Check Freshness

1. Call `check_target_freshness(domain, session)`
2. Parse the staleness report into three buckets:
   - **FRESH sections** — trust memory, skip re-scanning
   - **STALE sections** — need partial re-scan (only changed pages/endpoints)
   - **UPDATED knowledge** — new probes available, re-test previously "clean" params

## Step 4: Re-verify Findings (prioritized by severity)

Sort confirmed findings by severity (CRITICAL first, then HIGH, etc.) and re-verify:

For each finding with status `confirmed`:

1. **Skip if FRESH and recently verified (< 24h):** Trust memory, don't waste requests
2. **Re-verify if endpoint changed OR last_verified > 24h ago:**
   - Re-send the `poc_request` from the finding via `session_request`
   - Check if the expected behavior still occurs
   - If YES: update `last_verified` timestamp in memory
   - If NO: mark as `stale`, increment `verification_failures`
   - If `verification_failures >= 2`: mark as `likely_false_positive`
3. **Priority rule:** Always re-verify CRITICAL/HIGH findings before spending time on new testing

Save updated findings: `save_target_intel(domain, "findings", updated_data)`

## Step 5: Detect Attack Surface Changes

If the freshness check showed STALE endpoints:

1. Run `discover_attack_surface(session)` to get current endpoints
2. Compare against stored `endpoints.json`:
   - **New endpoints** — high priority for testing (new code = new bugs)
   - **Removed endpoints** — mark related findings as stale
   - **Changed parameters** — re-test even if previously clean
3. Save updated endpoints: `save_target_intel(domain, "endpoints", new_data)`

If knowledge version changed:
1. Load `coverage.json` — identify parameters tested with OLD knowledge version
2. These are candidates for re-probing with NEW probes (new detection techniques available)
3. Prioritize high-risk parameters that were previously clean

## Step 6: Present Dashboard

Show the user a clear status report:

```
TARGET: example.com (PHP 8.1 / Apache / MySQL)
SESSION: target1 (active, authenticated)

FINDINGS:
  2 confirmed (last verified: just now)
    [CRITICAL] SQL Injection in GET /api/users?id — time-based blind, 3.2s delay
    [HIGH] Reflected XSS in GET /search?q — unencoded in HTML body
  1 stale (endpoint changed — needs re-verification)
    [HIGH] IDOR in GET /api/orders?order_id — compare_auth_states showed identical
  1 likely false positive (2 verification failures)
    [LOW] Open redirect in /login?next — no Collaborator interaction

ATTACK SURFACE CHANGES:
  3 new endpoints found (NEW — test these first):
    POST /api/v2/users — has 'role' param (mass assignment risk)
    GET /api/export — has 'format' param (SSTI risk)
    POST /api/upload/avatar — file upload endpoint
  1 endpoint removed: GET /api/legacy/users

COVERAGE: 15/42 endpoints tested (36%)
  sqli:         8/15 high-risk params tested
  xss:          5/15 tested
  idor:         2/15 tested
  lfi:          0/15 tested  <-- UNTESTED
  file_upload:  0/3 forms tested  <-- UNTESTED
  ssti:         0/5 template params  <-- UNTESTED
  jwt:          not tested  <-- AUTH USES JWT

FRESHNESS:
  profile:   FRESH
  endpoints: STALE (root page changed — re-crawl recommended)
  knowledge: UPDATED (new probes available for sqli, xss — v{old} -> v{new})

NOTES (from last session):
  "Try IDOR on /api/v2/ — less hardened than v1"
  "WAF only on /admin paths — other paths unprotected"
  "JWT uses HS256 — try weak secret brute force"
```

## Step 7: Suggest Next Actions (ranked by expected value)

Based on the dashboard, suggest prioritized actions:

### Tier 1: Quick wins (1-5 requests each, high value)
1. **Re-verify stale findings** — cheap to confirm, high value if still valid
2. **Test new endpoints** — new code is most likely to have bugs
3. **Check new upload endpoint** — file upload vulns are high-severity

### Tier 2: Coverage gaps (10-30 requests each)
4. **Test untested categories** — LFI and SSTI are 0% coverage, high priority given PHP stack
5. **JWT analysis** — if auth uses JWT, `test_jwt` is a single call with high payoff
6. **Run new knowledge base probes** — re-test previously clean params with updated probes

### Tier 3: Deep investigation (30+ requests)
7. **Hidden parameter discovery** on new endpoints — `discover_hidden_parameters`
8. **Race condition testing** on state-changing endpoints
9. **Follow notes from last session** — user and Claude observations about promising targets
10. **JS secret re-scan** if new JS files appeared in attack surface delta

Ask the user: **"What would you like to focus on?"**

Then hand off to the hunt skill for execution (start at the relevant phase).
