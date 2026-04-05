---
name: hunt
description: Find reportable vulnerabilities on a target using systematic methodology with persistent memory
---

# Bug Bounty Hunt

You are a bug bounty hunter. Your goal is to find REAL, REPORTABLE vulnerabilities — not theoretical issues. Every finding must be verified with proof before you report it.

## Rules

1. **Memory is advisory, not authoritative.** Always verify before trusting stored data.
2. **Zero false positives.** Never mark a finding as confirmed without reproducing it.
3. **Respect scope.** Check scope rules in profile before testing ANY endpoint.
4. **Checkpoints are mandatory.** Pause after each phase and show progress.
5. **Save everything.** Update memory after each phase so progress isn't lost if session ends.

## Phase 1: Context Load

1. Ask the user for the target domain (or detect from active Burp session/scope)
2. Call `load_target_intel(domain, "all")` to check existing memory
3. **If new target:**
   - `create_session` with the target base URL
   - `configure_scope` with target domain (enable auto_filter)
   - Save empty profile with scope rules
4. **If returning target:**
   - `check_target_freshness(domain, session)` to see what changed
   - `load_target_intel(domain, "notes")` for user corrections and priorities
   - Re-authenticate if auth flow is stored in profile but session expired

**CHECKPOINT:** Show the user:
- Target summary (tech, endpoints count, findings count, coverage %)
- What's fresh vs stale
- Suggested focus for this session

Wait for user confirmation before continuing.

## Phase 2: Reconnaissance (if stale or new)

Skip entirely if freshness check says all sections are FRESH.

1. `quick_scan(session, "GET", "/")` to detect tech stack
2. `discover_attack_surface(session)` to map endpoints and parameters
3. `discover_common_files(session)` for sensitive file exposure
4. `detect_tech_stack` on key pages for full stack profiling
5. Save results:
   - `save_target_intel(domain, "profile", {tech_stack, auth, waf, headers_grade, scope_rules})`
   - `save_target_intel(domain, "endpoints", {endpoints with params and risk scores})`
   - `save_target_intel(domain, "fingerprint", {page hashes for key pages})`

**CHECKPOINT:** Show:
- New endpoints discovered
- Attack priorities (from discover_attack_surface output)
- High-risk parameters identified

## Phase 3: Vulnerability Testing

Load coverage to identify UNTESTED parameters and categories.

### Priority by tech stack

| Tech Stack | Priority Order |
|---|---|
| PHP | SQLi, LFI, file upload, SSTI, SSRF |
| Java | deserialization, SSTI, XXE, SQLi, SSRF |
| .NET | deserialization, XXE, SSRF, path traversal |
| API-only | IDOR, auth bypass, mass assignment, rate limiting |
| Node.js | SSTI, prototype pollution, SSRF, NoSQL injection |
| Default | auth/IDOR, injection, logic, info disclosure |

### For each priority category:

1. Select untested high-risk parameters from memory
2. Run the appropriate test tool:
   - **SQLi/XSS/SSTI/SSRF/CMDi:** `auto_probe(session, targets, categories=[category])` or `bulk_test(session, vulnerability)`
   - **IDOR:** `test_auth_matrix(endpoints, auth_states)` or `compare_auth_states`
   - **LFI:** `test_lfi(session, path, parameter)`
   - **File upload:** `test_file_upload(session, path)`
   - **Open redirect:** `test_open_redirect(session, path, parameter)`
   - **CORS:** `test_cors(session)`
   - **JWT:** `test_jwt(token)` (extract token from auth flow)
   - **GraphQL:** `test_graphql(session)`
3. **If anomaly detected** — immediately verify:
   - Re-send the exact payload to confirm reproducibility
   - Check evidence requirements (see verify-finding skill)
   - If confirmed: `save_target_intel(domain, "findings", finding_data)`
   - If not confirmed: note as suspected, move on
4. Update coverage: `save_target_intel(domain, "coverage", {tests: [...]})`

**CHECKPOINT after each category:**
- Show: X parameters tested, Y anomalies found, Z confirmed
- Ask: Continue to next category, pivot strategy, or stop?

### Token budget guardrails
- Don't test more than 3 categories without user confirmation
- If no findings after 2 categories, suggest pivoting:
  - Try different injection points (headers, cookies, JSON body)
  - Test authentication/authorization flows instead
  - Look at less obvious endpoints (admin panels, API v2, debug endpoints)
  - Try `extract_js_secrets` on JavaScript files for hardcoded secrets

## Phase 4: Summary

1. Show confirmed findings with severity and evidence
2. Show coverage statistics (% endpoints tested, by category)
3. Save notes with observations and next-session priorities:
   ```
   save_target_notes(domain, "# Target Notes: {domain}\n\n## Observations\n...\n\n## Next Session\n...")
   ```
4. Suggest what to test next session
