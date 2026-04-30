---
description: Always-active behavioral rules for bug bounty hunting. Apply on every turn when interacting with Burp Suite MCP tools.
globs:
---

# Hunting Rules

These rules are ALWAYS active. They override conflicting behavior. Each rule has ONE job — read every rule before assuming overlap.

## Scope (1–4)

1. **Never send requests to out-of-scope domains.** Before any request to a new domain call `check_scope(url)`. If not in scope, STOP.
2. **Never follow redirects to out-of-scope domains.** Note the redirect; don't follow.
3. **Respect excluded paths** (`/logout`, `/delete-account`, etc. per program policy).
4. **When in doubt about scope, ASK.** Don't assume a subdomain or API is in scope.

## Safety (5–9)

5. **Never send destructive payloads** (`DROP TABLE`, `rm -rf`, `shutdown`, `format`, `DELETE FROM`, `TRUNCATE`). Use benign detection payloads (SLEEP, math expressions, Collaborator callbacks).
6. **Never brute-force credentials.** Default/common creds (admin:admin, test:test) are fine. Dictionary attacks are not.
7. **Never exfiltrate real user data.** SQLi PoC = `SELECT version()` / `SELECT current_user()`, not `SELECT * FROM users`.
8. **Never modify or delete other users' data.** Prove IDOR with READ access, not WRITE.
9. **Prefer Collaborator for blind testing** over payloads with visible side effects.

## The Save-Finding Pipeline (10) — single canonical rule

10. **`save_finding` requires three phases, in order:**
    - **a) Replay (Step 0 of `verify-finding.md`):** fetch the candidate Logger/Proxy entry, `resend_with_modification(index)` to confirm the anomaly persists. The Logger index of the **confirming replay** (not the original suspicion) is what goes into `evidence.logger_index`. For timing/blind classes (`*_blind`, `sqli_time`, `race_condition`, `request_smuggling`), replay 2 more times — capture `{logger_index, elapsed_ms, status_code}` per replay → `reproductions[]` (≥3 entries total).
    - **b) Assess (`assess_finding`):** call `assess_finding(vuln_type, evidence, endpoint, parameter, domain)` BEFORE `save_finding`. Verdict `DO NOT REPORT` or `NEEDS MORE EVIDENCE` → do NOT save. The advisor handles scope, duplicate, NEVER-SUBMIT, weak-evidence, and triager-mass-report checks.
    - **c) Save:** `save_finding` with `evidence` containing at least one of `logger_index` / `proxy_history_index` / `collaborator_interaction_id` (each must resolve in live Burp data). For NEVER-SUBMIT vuln_types, supply `chain_with[]`. Server hard-rejects violations with 400.

## Evidence (11–13)

11. **Always compare against a recorded baseline.** Capture `{status, length, response_hash}` of the clean request before any probe sequence. Anomaly claims = deltas from baseline ("500 vs baseline 200, len delta +1842, error 'pg_query'"), not absolute observations. Without a baseline, evidence is unfalsifiable.
12. **Save evidence BEFORE further exploitation.** Annotate + Organize the moment something is interesting (Rule 18). Targets get patched.
13. **Verified evidence > theory.** Stack traces / parsing errors / status changes are clues, not proof. Match the per-class bar in `verify-finding.md` (e.g., XSS needs payload in executable context, not just reflection).

## Reporting (14–17)

14. **Never inflate severity.** Reflected XSS is not CRITICAL. Info disclosure is not HIGH. Open redirect alone is not MEDIUM. Cap honestly.
15. **Never submit findings requiring absurd victim action** ("user pastes a 500-char payload into devtools"). Self-XSS, victim-side-only DoS, etc. fail this gate.
16. **Reports are TRUE-POSITIVES-ONLY. Delete false positives, don't track them.** `generate_report` includes only `status='confirmed'` findings AND hard-deletes `likely_false_positive` entries from `.burp-intel/<domain>/findings.json` (no tombstones, no removed-FP lists, no audit trail). Tracking dead findings re-loads them every session and burns tokens forever.
17. **NEVER SUBMIT list (informative-alone, see table below)** can only be reported when CHAINED with another finding for real impact (`chain_with[]`).

## Coverage Strategy (18–21)

18. **Annotate + Organize as you work.** Every interesting captured request gets `annotate_request(index, color='RED|ORANGE|YELLOW|GREEN|CYAN|BLUE|PINK|MAGENTA|GRAY', comment='<f-id> | <vuln> | <evidence>')` AND `send_to_organizer(index)`. Color convention: RED=confirmed crit/high, ORANGE=strong suspicion, YELLOW=anomaly, GREEN=baseline/pass, CYAN=chain candidate, GRAY=noise. Without these, reporting time has to re-search the entire history.
19. **Coverage-first noise budget — skip impossible work, never skip real coverage.** Cut tokens on tech-mismatch CVEs (PHP CVE on Laravel), wrong-runtime payloads (Windows LFI on Linux), encoding-defeated reflections (3+ encoded → switch technique, not skip class), and exhausted suspicions (3/3 verification fails). Framework-wide vuln classes (React DOM XSS, Node prototype pollution, Java deserialization, JWT confusion, mass assignment, IDOR matrix, race conditions) get FULL sweeps even when expensive. Stop only when (a) class is impossible for the stack, (b) knowledge-base matchers cleared AND no param-name signal otherwise, (c) negative result documented in `coverage.json`. See `noise-budget.md`.
20. **Check coverage before testing.** Don't re-test parameters already covered this session. `load_target_intel(domain, "coverage")`.
21. **Save progress at every checkpoint.** Session ends → resume without re-doing work. `save_target_intel(domain, ...)` after each phase.

## Tool Selection (22–25)

22. **One smart tool call > five chatty ones.** `smart_analyze`, `auto_probe`, `run_flow`, `discover_attack_surface` over many individual calls. `extract_regex/json_path/css_selector` over `get_request_detail(full_body=True)`.
23. **For EVIDENCE retrieval, prefer captured-first.** `search_history` / `get_proxy_history` / `get_logger_entries` / `extract_*` against existing indices. Don't re-fetch with `curl_request` what's already captured — captured requests carry real session state.
24. **Match the tool to the work — every Burp surface is on the table.** Pick by intent, not ranking:
    - One-shot tweak of captured request → `resend_with_modification(index, modify_*)` or `probe_with_diff(index, ...)` for auto-diff
    - Iterate visibly in Burp UI → `send_to_repeater(index, tab_name='<f-id>-<vuln>')` + `repeater_resend`
    - Volume tied to captured baseline → `send_to_intruder_configured`
    - Custom volume / brute / spam / rate-limit with branching/decoding logic Intruder can't express → `concurrent_requests(requests=[...], concurrency=N)` (parallel) or sequential `curl_request`/`session_request` loops
    - Race condition (server-side latch) → `test_race_condition`
    - Multi-step business-logic flow → `run_flow` (linear) or explicit `session_request` chain (branchy)
    - Multi-param fuzz with anomaly detection → `fuzz_parameter`
    - Knowledge-driven vuln sweep → `auto_probe`
    - Fresh first-touch / fully-controlled request → `curl_request`/`send_raw_request`/`session_request`
25. **Default to a realistic header profile when LOOKING like the real client; bare headers when TESTING the server.**
    - Realistic mode (default for normal traffic): `get_target_headers(domain)` once → pass via `headers=`. Default httpx signatures get WAF-blocked.
    - Bare/custom mode (intentional): WAF detection, header injection, smuggling, CRLF, malformed-input — bare/hand-crafted is correct. Don't auto-mimic when the test is about NOT looking like a browser.
    - Build profile once via `build_target_header_profile(domain)` after first browser_crawl.

## Visibility (26)

26. **Know which tools hit Proxy history.** `browser_crawl`/`browser_navigate` populate **Proxy → HTTP history**. Burp HTTP-client tools (`send_http_request`, `curl_request`, `send_raw_request`, `session_request`, probes, scans) appear in **Logger** + MCP store (not Proxy history) unless explicitly proxied. External recon (`run_nuclei`, `run_katana`, `run_subfinder`) routes through Burp proxy (127.0.0.1:8080) → Proxy history. Analysis tools that take an `index` read Proxy history only.

## Creative Hunting (27) — anti-checklist mandate

27. **Hunt for the unknown, not just the catalogued.** ≥20% of every session must be open-ended exploration that goes outside the knowledge-base categories:
    - **Chain reasoning.** Walk the saved findings list and ask "what does each finding ENABLE?" — open redirect → token theft → ATO; CSRF on email-change → ATO; info-disclosure → recon → IDOR. Use `chain-findings.md`. Many programs only pay for chained impact.
    - **Business-logic flaws specific to THIS target.** Read 3–5 of the highest-value endpoints (`smart_analyze`) and ask: what's the trust assumption? What if the steps are reordered? Skipped? Run twice? Run with stale state? Run with another user's resource ID swapped in one step but not another? `auto_probe` does NOT find these.
    - **Outside-class anomalies.** Any unexplained delta vs baseline (status, length, hash, header, latency) is a candidate even if no class matches. Don't dismiss because "it doesn't fit a pattern" — open `investigate.md` and dig.
    - **Attacker-perspective questions.** What would an attacker WANT here? Money, account control, data exfiltration, privilege escalation, denial-of-service for competitors? Then work backwards from the goal to find the path.

   Following the checklist gets you info-disclosure and self-XSS. Real bugs and high-impact chains live outside it. Budget tokens explicitly for unstructured time.

## 7-Question Validation Gate (called by `assess_finding`, Rule 10b)

Before any finding is `confirmed`, all 7 must pass. One "NO" = do not report.

1. **In scope?** Per program policy, not just domain.
2. **Reproducible?** Trigger again from scratch right now?
3. **Real impact?** What can an attacker actually DO? (Not theoretical.)
4. **Not a duplicate?** Saved findings + common public reports for this target.
5. **Meets evidence requirements?** Per-class bar in `verify-finding.md`.
6. **Not in NEVER SUBMIT list?** See below.
7. **Would you mass-report this if you were the triager?** If you'd mark it informative — don't submit.

## NEVER SUBMIT List

Standalone reports of these are noise. Reportable only when CHAINED for real impact (Rule 17).

| Finding | Why not reportable alone |
|---|---|
| Missing security headers (X-Frame-Options, CSP, HSTS) | No direct exploit |
| Cookie without Secure/HttpOnly | Requires MitM or XSS to exploit |
| Clickjacking on non-sensitive pages | No state-changing action |
| Self-XSS | Victim must paste payload |
| CSRF on logout / non-state-changing endpoints | No real impact |
| Open redirect alone | Low impact without chain |
| Mixed content | Browser mitigates |
| Rate-limit absence on non-sensitive endpoints | No security impact |
| Stack traces / verbose errors alone | Info disclosure, not exploitable |
| Username / email enumeration on public sign-up | Often by design |
| Missing `Referrer-Policy` | Extremely minor |
| SPF/DMARC/DKIM | Email security, usually OOS |
| Content spoofing without XSS | Minimal impact |
| Host-header injection without cache poisoning | No exploit path |
| CORS without credentials + sensitive data | Browser blocks credentialed |
| SSL/TLS config (unless critical) | Scanner noise |
| Software version disclosure alone | Need exploit chain |
| Reverse tabnabbing | Low impact, disputed |
| Text injection (non-HTML) | No code execution |
| IDN homograph attacks | Browser-mitigated |
| Missing `autocomplete=off` | Password managers handle this |
| OPTIONS method enabled | Normal HTTP behavior |

**Exception:** chain with another finding → reportable. Use `chain-findings.md`.

## Testing Mode Selection (28)

28. **Adapt approach to engagement type.** Determine mode at session start and follow the corresponding mindset:

**Black box** (no internal access — URL/IP only):
- Recon-heavy: `browser_crawl` → `discover_attack_surface` → `full_recon` → `query_crtsh` → `fetch_wayback_urls`
- Fingerprint everything: `detect_tech_stack`, `extract_js_secrets`, `analyze_dns`
- Enumerate: `discover_common_files`, `discover_hidden_parameters`
- Probe blind: `auto_collaborator_test`, `auto_probe` with all categories
- Chain low findings into impact: `chain-findings.md`
- Mindset: assume nothing, map everything, then attack. Every response is intelligence.

**Grey box** (credentials, API docs, limited source):
- Session-first: `create_session` → `session_request` for all subsequent calls
- Auth boundaries: `test_auth_matrix` across roles — highest ROI test
- API-focused: `parse_api_schema`, `batch_probe`, `test_mass_assignment`
- Business logic: `test_business_logic`, `test_race_condition`, `run_flow`
- Authenticated scanning: `auto_probe` with session reaches hidden endpoints
- Mindset: go deeper not wider. Authorization, business logic, and state manipulation yield critical bugs.

**White box** (full source access):
- Source-first: read controllers, routes, middleware. Find unsanitized paths.
- Trace data flow: input → controller → service → sink. Every unsanitized path is a candidate.
- Targeted payloads: craft based on actual code, not generic lists. `get_payloads` with specific context.
- Coverage-driven: `save_target_intel(domain, "coverage", ...)` to track tested paths.
- Mindset: don't discover what you can read. Go straight to dangerous functions.

**Hybrid** (default for bug bounty — grey box app + black box infra):
- Start black box: `browser_crawl` → `full_recon` → `detect_tech_stack`
- Create accounts: `create_session` per role
- Switch grey box: `test_auth_matrix` → `auto_probe` with session → `test_business_logic`
- Verify and chain: `verify-finding.md`, `chain-findings.md`
