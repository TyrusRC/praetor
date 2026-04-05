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
3. If auth is stored in profile: re-authenticate using the stored login flow

## Step 3: Check Freshness

1. Call `check_target_freshness(domain, session)`
2. Note which sections are stale vs fresh

## Step 4: Re-verify Findings

For each finding with status `confirmed`:

1. Check if its endpoint is on a changed page (from freshness report)
2. If endpoint changed OR `last_verified` is more than 24 hours ago:
   - Re-send the `poc_request` from the finding via `session_request`
   - Check if the expected behavior still occurs
   - If YES: update `last_verified` timestamp in memory
   - If NO: mark as `stale`, increment `verification_failures`
   - If `verification_failures >= 2`: mark as `likely_false_positive`
3. If endpoint is fresh AND recently verified (< 24h): skip re-verification

Save updated findings: `save_target_intel(domain, "findings", updated_data)`

## Step 5: Present Dashboard

Show the user a clear status report:

```
TARGET: example.com (PHP 8.1 / Apache / MySQL)
SESSION: target1 (active, authenticated)

FINDINGS:
  2 confirmed (last verified: just now)
    [HIGH] SQL Injection in GET /api/users?id
    [MEDIUM] Reflected XSS in GET /search?q
  1 stale (endpoint changed — needs re-verification)
    [HIGH] IDOR in GET /api/orders?order_id
  1 likely false positive (2 verification failures)
    [LOW] Open redirect in /login?next

COVERAGE: 15/42 endpoints tested (36%)
  sqli:    8/15 high-risk params tested
  xss:     5/15 tested
  idor:    2/15 tested
  lfi:     0/15 tested  <-- UNTESTED
  upload:  0/3 forms tested  <-- UNTESTED

FRESHNESS:
  profile:   FRESH
  endpoints: STALE (root page changed — re-crawl recommended)
  knowledge: UPDATED (new probes available for 5 params)

NOTES (from last session):
  "Try IDOR on /api/v2/ — less hardened than v1"
  "WAF only on /admin paths"
```

## Step 6: Suggest Next Actions

Based on the dashboard, suggest prioritized actions:

1. **Re-verify stale findings** — cheap (1-2 requests each), high value
2. **Test untested categories** — LFI and upload are 0% coverage, high priority
3. **Re-crawl changed endpoints** — if endpoints section is stale, discover new attack surface
4. **Run new knowledge base probes** — if knowledge version changed, test with new payloads
5. **Follow notes from last session** — user and Claude observations about promising targets

Ask the user: **"What would you like to focus on?"**

Then hand off to the hunt skill for execution (start at the relevant phase).
