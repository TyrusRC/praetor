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

## Phase 2.5: Capture Business Context (mandatory before testing)

Run **once per engagement** before any vuln testing. Skips if already populated
this engagement (`get_business_context(domain)` returns a record).

```
capture_business_context(
    domain="<domain>",
    app_type="ecommerce|banking|fintech|healthcare|saas|...",
    money_flow="payments|payouts|subscriptions|none",
    sensitive_data=["pii", "pci", "phi", "financial", ...],
    user_roles=["admin", "user", "merchant", "support", ...],
    kill_switches=["delete_account", "transfer_funds", "create_api_key", ...],
    key_workflows=[{"name": "checkout", "steps": ["cart", "review", "pay", "confirm"]}],
    threat_actors=["criminal", "competitor", "insider"],
    notes="<regulatory regime, third-party integrations, anything else>",
)
```

What this unlocks:

- `assess_finding` auto-loads `business_context` on every gate call. SQLi on a
  `app_type=banking` target gets +10% impact boost without you re-passing it.
- `playbook-business-logic.md` walks every workflow / kill_switch / role pair
  systematically. **Loading this skill is mandatory** when business context is
  set — logic flaws are the highest-paying class on any business-relevant
  target.
- Reports cite real impact ("attacker drains $5k/day in coupon stacking")
  instead of generic technical class.

If you cannot answer the structured fields, **stop and read the app**:
- `browser_crawl` the main flows
- Read 3-5 high-value pages with `smart_analyze`
- Click through signup, checkout, settings, admin (if accessible)

Without business_context, you will miss every business-logic bug and
under-score every other class.

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

## Phase 3.6: Deep-Dive (auto-triggered)

**Trigger:** auto — `playbook-router.md` "Deep-dive auto-trigger" matrix evaluates recon output + intel (`load_target_intel`, `get_business_context`, `get_findings`) at end of Phase 2 AND end of Phase 3. Any signal hit → corresponding round fires automatically. No operator prompt needed. Standard hunt catches ~20% of real bugs; the rest live in the rounds below.

Five rounds. Each round runs ONLY if its triggering signal matched; each has a stop condition.

### Round 1 — Surface (assumed done in Phase 3)

### Round 2 — Business Logic
- `get_business_context(domain)` must return data; if empty, run `capture_business_context` FIRST
- load `playbook-business-logic.md`; walk every `key_workflow` + `kill_switch` + (low, high) `user_role` pair
- expected yield: 3-8 logic findings on a target with `money_flow` / `kill_switches` set

### Round 3 — Chain Hunting
- load `chain-findings.md`; inventory every saved finding (status=confirmed AND status=suspected)
- for each, check the escalation table; prove chains end-to-end with `run_flow`
- save chains as separate findings; severity = highest-impact step (see chain-findings.md)

### Round 4 — Forgotten Surface

The surface most scanners miss. Run when Rounds 2-3 done:

| Surface | Probe |
|---|---|
| Webhooks | replay; strip signature; race-on-delivery; rotate-during-flight |
| Admin / internal URLs | grep JS + sitemap.xml + robots.txt + swagger.json for `/admin`, `/internal`, `/debug`, `/actuator`, `/api/internal/` |
| API versioning | `/v1/`, `/v2/`, `/api/internal/`, `/api/private/`, `/api/legacy/` — older versions less hardened |
| HTTP method tampering | GET↔POST↔PUT↔DELETE↔PATCH↔OPTIONS↔TRACE per endpoint via `resend_with_modification` |
| Path normalization | `/Admin` vs `/admin`, `/admin/..;/`, `/admin%2f`, trailing dot/slash, double-encoding |
| Subdomain takeover | `test_subdomain_takeover` on every subdomain from `query_crtsh` |
| Sourcemaps | fetch `*.js.map` (Network tab of browser_crawl); reconstruct original paths + dev URLs |
| CI/CD artifacts | `.github/`, `Jenkinsfile`, `.gitlab-ci.yml`, `.npmrc`, `package-lock.json`, `vendor/`, `composer.lock` |
| Cloud assets | S3 bucket list+read, public Lambda function URLs, exposed Firebase, public GCS / Azure blob |
| Audit recent | `audit_recent_traffic` for endpoints in proxy history but never tested |
| Beta / staging | `beta.<domain>`, `stage.<domain>`, `dev.<domain>`, `qa.<domain>`, `*-internal.<domain>` |
| Mobile-only paths | `/api/mobile/`, `/m/`, `/api/app/`, `X-Platform` headers — load `playbook-mobile-backend.md` |

### Round 5 — Cross-Class Meta-Passes

| Class | Pivot |
|---|---|
| Second-order injection | user stores X; admin/back-office processes it later (support-ticket XSS, comment-moderation SSRF) |
| Deserialization | every binary blob in cookies / params / JSON values (`rO0AB`, `O:`, `gASV`, msgpack header) |
| OAuth / SAML / OIDC mix-up | 3+ IdPs in flow → cross-IdP code/assertion swap, account-linking confusion (load `playbook-payment-and-auth.md` §1) |
| Recovery flows | every "forgot X" path — password, 2FA, passkey, email, phone (load `playbook-payment-and-auth.md` §10) |
| DNS rebinding | SSRF-flagged endpoints with DNS-resolver caching gap; SVCB/HTTPS records |
| Prototype pollution | every JSON body; recursive `__proto__` / constructor depth |
| HTTP smuggling | TE.CL / CL.TE / H2.CL / H2.TE / TE.0 / CL.0 via `test_request_smuggling` |
| Cache poisoning | `test_cache_poisoning` on every CDN-fronted path; X-Forwarded-Host / X-Original-URL |
| WebSocket smuggling | per-message-deflate compression oracle, frame fragmentation |

### Stop conditions for deep-dive
- 50 tool calls across Rounds 2-5 with **<2 new findings** → pivot to a different target
- >2h session time with no new chain identified → diminishing returns; checkpoint and move on

## Phase 4: Severity — Business Impact, Not CVSS

Severity tracks payout. The advisor (`assess_finding`) applies this rubric automatically when `domain` is passed AND `capture_business_context(domain)` has run — pass both.

**Formula:** `severity = base_class × business_context_multiplier ± evidence_floor/ceiling`

### Base by class
| Class | Base |
|---|---|
| Verified RCE / pre-auth data exfil / no-interaction ATO | CRITICAL |
| 1-click ATO, mass PII IDOR, JWT `alg:none`, sandbox-payment-on-prod, OAuth `redirect_uri` to attacker, password reset → attacker email | CRITICAL |
| Single-user IDOR, stored XSS admin context, SSRF to cloud creds, leaked live AWS/GCP root key | HIGH |
| Reflected XSS, CSRF on state-change, open redirect with chain, exploitable info disclosure | MEDIUM |
| Self-XSS, missing headers, verbose errors, version disclosure | LOW |

### Business-context multipliers (from `get_business_context`)
| Trait | × |
|---|---|
| `money_flow != "none"` AND auth-relevant class | 1.5 |
| `sensitive_data` contains pci / phi / financial | 1.4 |
| `app_type` in {banking, fintech, healthcare, gov} | 1.3 |
| Affects all users vs only attacker | 1.5 |
| Pre-auth exploitable | 1.3 |
| Requires admin role to exploit | 0.5 |
| Requires victim social engineering | 0.7 |

Round up to next tier if combined multiplier ≥1.3; down if ≤0.7.

### Floors (always-MAX, ignore multiplier)
Sandbox payment token on prod, `alg:none` JWT accepted, password reset → attacker-supplied email, mass PII via no-auth endpoint, ATO without any interaction, leaked AWS/GCP root key with verified write → **CRITICAL minimum**.

### Ceilings (capped, ignore boost)
- Reflected XSS without admin/sensitive context → MEDIUM max
- Open redirect alone → MEDIUM max
- Self-XSS without chain → INFO (NEVER SUBMIT per Rule 17)
- Missing security headers / verbose errors alone → INFO (Rule 17)

### Expected payouts (BBH-pragmatic)
| Tier | Public avg | Aim per engagement |
|---|---|---|
| CRITICAL | $5k–$50k | 0-1 |
| HIGH | $1k–$5k | 1-3 |
| MEDIUM | $200–$1k | 2-5 |
| LOW | $50–$300 | report only if chain-eligible |
| INFO | $0 | don't submit |

If rubric says HIGH but program-history shows LOW pays for that class, downgrade with `severity=` override on `save_finding` and note `program-pays-low`. Don't inflate — triagers downgrade, reputation hit costs more than the bonus.

## Phase 5: Summary

1. Show confirmed findings with severity and evidence
2. Show coverage statistics (% endpoints tested, by category)
3. Save notes with observations and next-session priorities:
   ```
   save_target_notes(domain, "# Target Notes: {domain}\n\n## Observations\n...\n\n## Next Session\n...")
   ```
4. Suggest what to test next session
