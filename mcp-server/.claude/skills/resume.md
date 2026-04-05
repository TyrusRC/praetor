---
name: resume
description: Resume bug bounty testing from a previous session with re-verification and coverage gaps
---

# Resume — Continue Bug Bounty Testing

You are resuming a bug bounty session on a target that was previously tested. Follow this procedure to re-orient, re-verify, and continue.

## Step 1: Load Full Target Memory

Load all stored intel:
- `load_target_intel(domain, "recon")` — tech stack, endpoints, parameters, secrets
- `load_target_intel(domain, "coverage")` — what was tested, what remains
- `load_target_intel(domain, "findings")` — all findings with statuses

If any of these fail or return empty, inform the user that memory is incomplete and suggest starting a fresh hunt instead.

## Step 2: Check Freshness

Call `check_target_freshness(domain, session)` to determine if the target has changed since the last session.

If stale:
- Note which sections are stale (recon, specific endpoints, etc.)
- These will need re-testing even if previously marked as covered

## Step 3: Re-verify Confirmed Findings on Changed Endpoints

For each finding with status `"confirmed"` where the endpoint is stale or changed:

1. Re-create or reuse a session: `create_session(name, base_url)`
2. Re-send the original PoC request using `session_request(session, method, path, ...)`
3. Check if the vulnerability still exists using the evidence requirements from the verify-finding skill
4. Update finding status:
   - Still works: keep `"confirmed"`, update `last_verified` timestamp
   - No longer works: mark `"patched"`, note the change
   - Uncertain: mark `"needs_recheck"`
5. Save updated findings: `save_target_intel(domain, "findings", updated_findings)`

## Step 4: Present Dashboard

Show the user a structured dashboard:

```
Target: example.com
Tech Stack: PHP 8.1 / Apache / MySQL
Session: returning (last tested: YYYY-MM-DD)

Findings:
  Confirmed:  2 (1 high, 1 medium)
  Suspected:  1
  Patched:    1
  False pos:  0

Coverage:
  SQLi:           85% (12/14 params)
  XSS:            60% (9/15 params)
  Auth/IDOR:      not started
  SSRF:           100%
  ...
  Overall:        45%

Stale Sections: recon endpoints (>7 days old)

Notes from last session:
  - "Admin panel at /admin requires IP whitelist"
  - "Rate limiting on /api/login after 5 attempts"
```

## Step 5: Re-authenticate if Needed

If the previous session used authentication:
1. Check if stored session tokens are still valid with a quick `session_request`
2. If expired, ask the user for fresh credentials or use `run_flow` to re-authenticate
3. Call `create_session(name, base_url)` with fresh auth if needed

## Step 6: Suggest Next Actions

Present prioritized options based on the state:

1. **Re-verify stale findings** — if any confirmed findings are on changed endpoints
2. **Test untested categories** — sorted by tech-stack priority (see hunt skill)
3. **Increase coverage on started categories** — finish partially-tested parameter sets
4. **Probe new endpoints** — if recon found new endpoints since last session
5. **Run new knowledge probes** — `auto_probe` may have new detection rules since last session
6. **Edge-case tests** — `test_cors`, `test_jwt`, `test_graphql`, `test_cloud_metadata` if not yet run

Format as a numbered list with brief rationale for each.

## Step 7: Hand Off

Ask the user: **"What would you like to focus on?"**

Based on their answer:
- If they pick a specific category or action, proceed directly with that work following the hunt skill methodology (Phase 3).
- If they say "continue" or "keep going", pick the highest-priority untested category and proceed.
- If they want a full re-hunt, start the hunt skill from Phase 2.

## Rules

- **Do not assume findings are still valid.** Always re-verify on stale endpoints before counting them.
- **Respect user corrections.** If the user previously noted something as a false positive or out of scope, honor that.
- **Save progress immediately** after re-verification, before starting new testing.
- **Show the dashboard before doing anything.** The user needs to orient before deciding next steps.
