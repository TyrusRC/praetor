---
name: hunt
description: Find reportable vulnerabilities on a target using systematic methodology with persistent memory
---

# Bug Bounty Hunt

> **Rule reference (R12):** scope/safety/save-finding behavior is governed by `.claude/rules/hunting.md` Rules 1–10 (HARD tier). Evidence/coverage/reporting by Rules 11–21 (DEFAULT). This skill describes WORKFLOW, not rule text. When workflow text disagrees with a rule number, the rule wins.

You are a bug bounty hunter. Your goal is to find REAL, REPORTABLE vulnerabilities — not theoretical issues. Every finding must be verified with proof before you report it.

## Rules

1. **Memory is advisory, not authoritative.** Always verify before trusting stored data.
2. **Zero false positives.** Never mark a finding as confirmed without reproducing it.
3. **Respect scope.** Check scope rules in profile before testing ANY endpoint.
4. **Checkpoints are mandatory.** Pause after each phase and show progress.
5. **Save everything.** Update memory after each phase so progress isn't lost if session ends.
6. **Think like an attacker.** Prioritize what matters for real-world impact, not checkbox coverage.

## Mode is per-call (Rule 28)

Mode mindset is NOT locked at session start. Re-evaluate per tool call:

- **Has session cookies / Authorization header?** → Use the GREY-BOX mindset for THIS call regardless of session-start mode. A black-box session that acquired credentials mid-engagement should immediately test for IDOR / BFLA / business-logic / authenticated-only attack surface.
- **Pass `session_name=<name>` to `assess_finding`** when active session is authenticated — the gate will boost IDOR / BFLA / authorization / business_logic impact (+10%) per Rule 28.
- **White-box (source available)** → read controllers, routes, middleware FIRST; trace data flow (input → controller → service → sink); craft payloads from actual code, not generic lists.

Locking into one mode after session start is a primary cause of missed findings.

## Phase 0: Edition Gate + State Hydration (once per session)

Two calls at the start of every hunt session:

1. `check_pro_features()` — confirms Pro vs Community. On Community, route to MCP-side equivalents (auto_probe + run_nuclei + run_dalfox + run_sqlmap; interact.sh wildcard for OOB; browser_crawl + run_katana). Don't burn tokens hitting Pro-only endpoints that will 4xx.
2. `hydrate_burp_findings(domain="all")` — Burp's in-memory FindingsStore empties on every extension reload. This re-populates the UI Findings tab from `.burp-intel/<domain>/findings.json` so what's on disk matches what's visible. Safe to run repeatedly (duplicate-skips). If skipped: previously-saved findings disappear from the Burp UI even though they're still on disk.

Sessions (cookies, auth tokens, extracted variables) DO NOT auto-restore on extension reload — they're in-memory only with no on-disk mirror yet. Re-establish via `create_session` + `session_request` (login flow) or `run_flow`.

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

**PARALLEL DISPATCH (see dispatch-agents skill):** Launch recon-agent and js-analyst simultaneously:

**Agent 1 — recon-agent (background):**
> Map the attack surface for {domain}. Session: {session}.
> Run: discover_attack_surface, discover_common_files, discover_hidden_parameters on /.
> Return: endpoint list with risk scores, sensitive files, hidden params.

**Agent 2 — js-analyst (background):**
> Analyze JavaScript for {domain}. Session: {session}.
> Run: quick_scan on / to get index, fetch_page_resources, extract_js_secrets on each JS file, analyze_dom.
> Return: secrets found, DOM XSS flows, hidden API endpoints.

**If not using agents (sequential fallback):**
1. `quick_scan(session, "GET", "/")` to detect tech stack
2. `discover_attack_surface(session)` to map endpoints and parameters
3. `discover_common_files(session)` for sensitive file exposure (.git, .env, actuator, phpinfo)
4. `detect_tech_stack` on key pages for full stack profiling
5. `fetch_page_resources` + `extract_js_secrets` + `analyze_dom` for JS analysis

**Option C — Browser-assisted recon (for JS-heavy targets):**
1. `browser_crawl(url, max_pages=20)` — auto-crawl through Burp proxy, populates proxy history
2. `browser_interact_all(url)` — click every button/link/toggle on the page
3. `get_proxy_history(limit=50)` — review all captured traffic
4. `smart_analyze(index)` on key pages from proxy history

**One-call alternative:** `run_recon_phase(target_url)` executes session creation + tech detection + analysis + sensitive file checks in a single call.

**After agents complete (or sequential steps finish):**
- Merge endpoint list + JS-discovered endpoints
- Merge secrets into suspected findings
- Save results:
   - `save_target_intel(domain, "profile", {tech_stack, auth, waf, headers_grade, scope_rules})`
   - `save_target_intel(domain, "endpoints", {endpoints with params and risk scores})`
   - `save_target_intel(domain, "fingerprint", {page hashes for key pages})`

**CHECKPOINT:** Show:
- New endpoints discovered (from both agents)
- JS secrets found (API keys, tokens, internal URLs)
- DOM XSS sink-to-source flows
- Attack priorities (from discover_attack_surface output)
- High-risk parameters identified

## Phase 3: Vulnerability Testing

**ADVISOR SHORTCUT:** Call `get_hunt_plan(target_url)` or `get_next_action(target_url, completed_phases=['recon'])` to get pre-computed testing priorities instead of reasoning about what to test next.

Load coverage to identify UNTESTED parameters and categories.

**PARALLEL DISPATCH (see dispatch-agents skill):** Split targets by vulnerability category and dispatch up to 6 vuln-scanner agents simultaneously (Java thread pool cap). Each agent gets non-overlapping targets. Example:
- vuln-scanner (SQLi): endpoints with id/uid/num params
- vuln-scanner (XSS): endpoints with search/comment/name params
- auth-tester (IDOR): all authenticated endpoints with auth_matrix
- vuln-scanner (LFI): endpoints with file/path/include params

**Critical:** No two agents should hit the same endpoint. After all complete, merge findings and investigate anomalies.

### Priority by tech stack

Choose the right attack order based on detected technology. Test in this order — highest-impact vulns first.

| Tech Stack | Priority Order |
|---|---|
| PHP / Apache | SQLi, LFI/path traversal, file upload, SSTI (Twig/Blade), deserialization, SSRF |
| Java / Spring / Tomcat | deserialization, SSTI (Thymeleaf/FreeMarker), XXE, SQLi, SSRF, Spring actuator |
| ASP.NET / IIS | deserialization (ViewState), XXE, SSRF, path traversal, SQLi (MSSQL) |
| Python / Flask / Django | SSTI (Jinja2/Mako), SQLi, SSRF, command injection, deserialization |
| Ruby / Rails | deserialization (Marshal), SSTI (ERB), mass assignment, SQLi, SSRF |
| Node.js / Express | SSTI, prototype pollution, SSRF, NoSQL injection, deserialization (node-serialize) |
| Go / Rust | SSRF, path traversal, command injection, race conditions, auth bypass |
| API-only (REST/GraphQL) | IDOR, auth bypass, mass assignment, rate limiting, GraphQL introspection, BOLA |
| WordPress | SQLi (plugins), file upload, XXE (xmlrpc), user enumeration, plugin vulns |
| Single-Page App (React/Angular/Vue) | DOM XSS, API IDOR, JWT attacks, CORS misconfig, prototype pollution |
| Unknown / Default | auth/IDOR, injection (SQLi/XSS), business logic, info disclosure, CORS/CSRF |

### For each priority category:

1. Select untested high-risk parameters from memory
2. Run the appropriate test tool:
   - **SQLi/XSS/SSTI/SSRF/CMDi/LFI:** `auto_probe(session, targets, categories=[category])` or `bulk_test(session, vulnerability)`
   - **IDOR/Broken Access Control:** `test_auth_matrix(endpoints, auth_states)` or `compare_auth_states`
   - **LFI/Path Traversal:** `test_lfi(session, path, parameter)`
   - **File upload:** `test_file_upload(session, path)`
   - **Open redirect:** `test_open_redirect(session, path, parameter)`
   - **CORS:** `test_cors(session)`
   - **JWT:** `test_jwt(token)` (extract token from auth flow first)
   - **GraphQL:** `test_graphql(session)`
   - **Cloud metadata SSRF:** `test_cloud_metadata(session, parameter, path)`
   - **Race condition:** `test_race_condition(session, request)` on state-changing endpoints (payments, coupons, votes)
   - **HPP:** `test_parameter_pollution(session, path, parameter, value, variants)`
   - **Mass assignment:** Add extra fields (`role`, `is_admin`, `price`) to registration/profile update requests
   - **CRLF:** Test redirect/header params with `%0d%0a` payloads
   - **Deserialization:** Look for serialized objects in cookies/params (base64 starting with `rO0AB`, `O:`, `gASV`)
   - **Hidden params:** `discover_hidden_parameters(session, method, path)` on interesting endpoints
3. **If anomaly detected** — immediately verify:
   - Re-send the exact payload to confirm reproducibility
   - Check evidence requirements (see verify-finding skill)
   - If confirmed: `save_target_intel(domain, "findings", finding_data)`
   - If not confirmed: note as suspected, move on
4. Update coverage: `save_target_intel(domain, "coverage", {tests: [...]})`

**CHECKPOINT after each category:**
- Show: X parameters tested, Y anomalies found, Z confirmed
- Ask: Continue to next category, pivot strategy, or stop?

### Token budget guardrails (Rule 19 — full coverage is mandatory)
- **DO NOT skip categories to save tokens.** Rule 19 makes full coverage mandatory; the failure mode is missed findings, not over-spending. Token economy comes from `auto_probe(skip_already_covered=True)`, pagination, and `discover_attack_surface` pre-scoping — NOT from skipping categories.
- **Pivot WITHIN a category, not away from it.** If standard payloads in a category are blocked, change WHERE you inject (headers/cookies/body), HOW you encode (transform_chain), or WHEN you test (race / OOB / blind variants). Do NOT abandon the category.
- Re-test ALL categories when knowledge_version changes (set `skip_already_covered=False`).
- If a finding score 30-49 surfaces during a category, FIRST check `chain-findings.md` for chain candidates with already-saved findings BEFORE dropping into investigate.md.

### Pivot strategies (when standard tests fail)

**Change WHERE you inject:**
- Move from query params to headers (Host, Referer, X-Forwarded-For, X-Forwarded-Host)
- Try injection in cookies, JSON body keys (not just values), path segments
- Test multipart/form-data boundary injection
- Try parameter pollution (same param in query AND body)

**Change WHAT you target:**
- Switch from public endpoints to authenticated-only endpoints
- Look for admin panels, debug endpoints, API versioning (/api/v2/ vs /api/v1/)
- Check for undocumented endpoints via `discover_hidden_parameters`
- Try legacy/deprecated endpoints (often less hardened)

**Change HOW you test:**
- If WAF blocks standard payloads: `get_payloads(category, waf_bypass=True)`
- Try encoding variations: double URL-encode, unicode, mixed case
- Test blind variants: time-based instead of error-based, OOB via Collaborator
- Chain findings: open redirect + SSRF, XSS + CSRF, info disclosure + auth bypass

**Think about business logic:**
- Price manipulation (negative quantities, zero prices, coupon reuse)
- Workflow bypass (skip steps in multi-step processes)
- Rate limit bypass (race conditions on one-time actions)
- Privilege escalation (modify role/permission fields in profile updates)

**Mine JavaScript for leads:**
- `extract_js_secrets` on all JS files for hardcoded API keys, internal URLs
- `analyze_dom` for source-to-sink XSS flows
- Look for commented-out features, debug flags, staging URLs in JS

## Phase 3.5: WebSocket Testing (if applicable)

If `get_websocket_history` shows WebSocket traffic:

1. Check for Cross-Site WebSocket Hijacking (missing Origin validation)
2. Test for injection in WebSocket messages (SQLi, XSS in JSON messages)
3. Check authentication — does the WebSocket upgrade require auth?

## Phase 4: Severity Assessment

For each confirmed finding, classify severity using real-world impact:

| Severity | Criteria | Examples |
|---|---|---|
| **CRITICAL** | Full system compromise, mass data breach, RCE | SQLi with data extraction, RCE via SSTI/deserialization, SSRF to cloud credentials |
| **HIGH** | Significant data access, account takeover, privilege escalation | IDOR reading other users' data, stored XSS in admin panel, JWT alg:none bypass |
| **MEDIUM** | Limited data exposure, user-targeted attacks | Reflected XSS, CSRF on state-changing actions, open redirect, information disclosure |
| **LOW** | Minimal direct impact, requires chaining | Self-XSS, verbose error messages, missing security headers, clickjacking |
| **INFO** | No direct security impact but noteworthy | Version disclosure, internal path disclosure, debug mode indicators |

**Impact amplifiers** (bump severity up):
- Affects all users (not just attacker's own account)
- No user interaction required (wormable XSS, automatic CSRF)
- Bypasses existing security controls (WAF bypass, CSP bypass)
- Chains with another finding for greater impact

## Phase 5: Summary

1. Show confirmed findings with severity and evidence
2. Show coverage statistics (% endpoints tested, by category)
3. Save notes with observations and next-session priorities:
   ```
   save_target_notes(domain, "# Target Notes: {domain}\n\n## Observations\n...\n\n## Next Session\n...")
   ```
4. Suggest what to test next session
