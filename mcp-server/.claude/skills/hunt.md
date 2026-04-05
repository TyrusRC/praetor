---
name: hunt
description: Find reportable vulnerabilities on a target using systematic methodology with persistent memory
---

# Hunt — Systematic Bug Bounty Methodology

You are conducting a bug bounty hunt against a target. Follow this methodology exactly.

## Phase 1: Load Memory and Orient

1. Call `load_target_intel(domain, "recon")` and `load_target_intel(domain, "coverage")` and `load_target_intel(domain, "findings")` to load all prior knowledge.
2. Call `check_target_freshness(domain, session)` to see if recon data is stale.
3. If memory exists, read any `user_corrections` or `notes` sections — these override your assumptions.

**CHECKPOINT:** Show the user a summary:
- Target domain
- Memory status (new / returning with N findings / stale)
- Last session date and what was tested
- Any user corrections on file

Wait for user confirmation before proceeding.

## Phase 2: Reconnaissance (if new or stale)

Skip this phase if memory is fresh and recon is complete.

1. Call `create_session(name, base_url)` to establish a working session.
2. Call `configure_scope(include=[target_pattern], auto_filter=true)` to set scope and filter noise.
3. Run in sequence:
   - `quick_scan(session, "GET", "/")` — baseline the application
   - `discover_attack_surface(session)` — map endpoints, parameters, methods
   - `discover_common_files(session)` — find robots.txt, .env, backups, admin panels
   - `detect_tech_stack(session)` — identify server, framework, language
   - `extract_js_secrets(session)` — scan JS files for API keys, tokens, credentials
4. Save results: `save_target_intel(domain, "recon", { tech_stack, endpoints, parameters, secrets, common_files })`.
5. Save coverage: `save_target_intel(domain, "coverage", { tested: {}, untested: [...categories] })`.

**CHECKPOINT:** Show the user:
- Tech stack detected
- Number of endpoints and parameters found
- Any secrets or sensitive files discovered
- Suggested testing priority based on tech stack

Wait for user confirmation before proceeding.

## Phase 3: Vulnerability Testing

Prioritize test categories based on detected tech stack:

| Tech Stack | Priority Order |
|---|---|
| **PHP** | SQLi, LFI (`test_lfi`), file upload (`test_file_upload`), SSTI, SSRF |
| **Java** | deserialization, SSTI, XXE, SQLi, SSRF |
| **.NET** | deserialization, XXE, SSRF, path traversal |
| **API-only** | IDOR (`compare_auth_states`), auth bypass, mass assignment |
| **Node.js** | SSTI, prototype pollution, SSRF, NoSQL injection |
| **Default** | auth/IDOR, injection (SQLi/XSS/SSTI), logic flaws, info disclosure |

For each category:

1. **Select targets:** Use `find_injection_points(session)` to pick untested, high-risk parameters. Prefer parameters that accept user input, have no validation, or handle sensitive data.
2. **Get payloads:** Call `get_payloads(category, context)` to get curated payloads appropriate for the tech stack and WAF status.
3. **Probe:** Use `auto_probe(session, targets, categories)` for broad coverage, or `probe_endpoint(session, method, path, parameter)` for targeted testing of specific parameters.
4. **Verify anomalies immediately:** Any anomaly (timing difference, error string, reflection) must be verified before moving on. Use `session_request` to re-send with variations. If it looks real, invoke the verify-finding skill.
5. **Update coverage:** Call `save_target_intel(domain, "coverage", updated_coverage)` after each category.

**Run edge-case tests where applicable:**
- `test_cors(session)` — on every target
- `test_jwt(session)` — if JWT detected in headers/cookies
- `test_graphql(session)` — if GraphQL endpoint found
- `test_cloud_metadata(session)` — if cloud-hosted
- `test_auth_matrix(session, ...)` — if multiple roles exist
- `test_race_condition(session, ...)` — on state-changing operations (purchases, transfers, votes)
- `auto_collaborator_test(session, ...)` — for blind SSRF/XXE/injection

**CHECKPOINT after each category:** Show:
- Category tested
- Endpoints covered
- Findings (confirmed / suspected / none)
- Cumulative coverage %

## Phase 4: Wrap-Up

1. Show final summary:
   - All confirmed findings with severity
   - Overall coverage percentage
   - Categories tested vs remaining
   - Recommended priorities for next session
2. Save everything:
   - `save_target_intel(domain, "findings", all_findings)`
   - `save_target_intel(domain, "coverage", final_coverage)`
   - `save_target_notes(domain, session_summary)`
3. For each confirmed finding, call `save_finding(...)` with full evidence.
4. Offer to `export_report()` if the user wants a report.

## Token Guardrails

- Test a maximum of **3 categories** before pausing for user confirmation. After 3, show progress and ask whether to continue or pivot.
- If **2 consecutive categories** produce zero findings, suggest pivoting to a different area or running `smart_analyze(session)` to look for missed attack surface.
- Prefer `auto_probe` (batch) over individual `probe_endpoint` calls when testing more than 3 parameters in the same category.

## Rules

- **Memory is advisory, not authoritative.** The application may have changed since last session. Always verify before assuming.
- **Zero false positives.** Never report a finding as confirmed unless evidence requirements are met (see verify-finding skill). Suspected findings are fine to record but must be labeled as such.
- **Respect scope.** Never test endpoints outside the configured scope. If you discover new subdomains, ask the user before adding them.
- **Always save progress.** If the session is interrupted or you hit a token limit, save current state so the resume skill can pick up.
- **Do not spray.** This is not a brute-force tool. Select targets intelligently based on analysis. Quality over quantity.
