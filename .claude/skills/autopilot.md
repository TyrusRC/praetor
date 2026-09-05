---
name: autopilot
description: Autonomous hunt loop with circuit breaker, rate limiting, checkpoint modes, and safety controls
---

# Autopilot Hunt

You are running an autonomous vulnerability hunt. This skill wraps the hunt methodology with safety controls, progress tracking, and configurable checkpoint modes.

## Activation

User says: "autopilot [domain]" or "auto-hunt [domain]"
Optional flags:
- `--paranoid` — stop at every finding for review (default)
- `--normal` — batch findings, stop after each phase
- `--aggressive` — minimal stops, only pause on critical findings
- `--max-iterations N` — hard limit on tool calls (default: 100)
- `--categories [list]` — only test specific vuln categories

## Safety Controls

### Circuit Breaker
Track consecutive error responses. If triggered, STOP and report.

```
Rules:
- 5 consecutive 403 responses → STOP: "WAF is blocking us. Pausing to avoid IP ban."
- 3 consecutive 429 responses → STOP: "Rate limited. Wait 60 seconds, then resume."
- 10 consecutive timeouts → STOP: "Target unresponsive. Check if target is up."
- Connection refused → STOP immediately: "Target port closed or firewall active."
```

Reset the counter on any successful (2xx/3xx) response.

### Rate Limiting
Enforce delays between requests to avoid detection:

```
Mode        | Delay       | When
------------|-------------|---------------------------
recon       | 0.5-1s      | discover_attack_surface, common_files
testing     | 1-2s        | auto_probe, fuzz_parameter
aggressive  | 0s          | test_race_condition (needs speed)
cooldown    | 5-10s       | After circuit breaker near-trigger (3/5 errors)
```

### Safe Method Policy
Default restrictions on autonomous requests:

```
ALWAYS SAFE (no confirmation needed):
- GET, HEAD, OPTIONS requests
- Read-only MCP tools (get_*, search_*, load_*, extract_*, detect_*, analyze_*)

REQUIRES CONFIRMATION in --paranoid mode:
- POST, PUT, PATCH, DELETE requests to non-read endpoints
- fuzz_parameter with high payload counts
- Any request that modifies server state

NEVER IN AUTOPILOT:
- Requests to out-of-scope domains
- Destructive payloads (DROP TABLE, rm -rf, shutdown)
- Requests that could cause data loss on target
```

### Scope Guard
Before EVERY request, verify target is in scope:
```
1. check_scope(url) → must return true
2. If URL contains a new subdomain not seen before → pause and confirm
3. Never follow redirects to out-of-scope domains
```

## Autonomy Modes (risk-tiered action gate — Burp AT parity)

Three named autonomy levels, mapped to the existing checkpoint flags. Same
graduated dial Burp AT ships (Manual / Smart / Autonomous), but the gate is
enforced at the **tool layer** (HARD Rules 1–10, `confirm_*` gates, scope mode)
— architecturally separate from the model, so a prompt-injected agent still
cannot exceed it.

| Mode | Flag | Behavior |
|---|---|---|
| **Manual** | `--paranoid` | Ask before every state-changing action; auto-run only ALWAYS-SAFE reads. |
| **Smart** | `--normal` | Act independently on safe + low-impact probes; **pause for approval on any HIGH-IMPACT action** (list below). |
| **Autonomous** | `--aggressive` | Run without asking — **except the ALWAYS-APPROVAL list, which pauses in every mode including this one.** |

**ALWAYS-APPROVAL high-impact actions (pause even in Autonomous):**
- Any state-changing write proven exploitable (account takeover PoC, privilege change, data write to another user's object).
- OOB exfil that would move real data off-target (blind SQLi dump, XXE file read beyond a version banner).
- `msf_exploit` / `msfrpc_module_execute` / any RCE-confirming payload beyond a benign `id`/`whoami` marker.
- `save_finding` submission-format export / platform push (`format_finding_for_platform`, report generation for delivery).
- First request to a newly-discovered in-scope subdomain (Scope Guard §2).
- Anything on the destructive denylist (HARD Rules 5–9) — this is a hard BLOCK, not an approval prompt.

Smart/Autonomous never relax Rules 1–10. The mode only governs *how often the loop stops to check in* on already-permitted actions — it cannot grant a permission the tool layer denies.

### Impact-First Category Order (Rule 29)

Test in this order; earlier classes pay more and are where MEDIUM+ concentrates:
1. Authorization — IDOR/BOLA/BFLA/BOPLA (test_auth_matrix, probe_* idor family)
2. AuthN & session (test_login_bypass, test_mfa_bypass, test_session_lifecycle, jwt/oauth/saml)
3. Business logic & race (test_business_logic, test_race_condition, probe_* logic family)
4. Injection reaching a sink (auto_probe + test_* : sqli/rce/ssti/ssrf/xxe)
5. Mass assignment (test_mass_assignment)
6. Recon-shaped classes (headers/TLS/version) — RECORD, do not hunt (Rule 29)

## Autopilot Loop

> **Definition of Done per finding:** verified (replayed) → assessed
> (assess_finding passed) → saved with impact + evidence. Rules 10, 14, 29.
> An unescalated LOW or an unassessed suspicion is a note, never a report entry.

```
INITIALIZE:
  iteration = 0
  max_iterations = 100 (or user-specified)
  findings = []
  errors_consecutive = 0
  phase = "recon"

LOOP:
  while iteration < max_iterations:
    iteration += 1

    // Circuit breaker check — distinguish WAF block from auth-control 403.
    // Generic 403 during IDOR/BFLA/auth-matrix testing is the EXPECTED control
    // response (server is enforcing access control correctly on the negative
    // case). Only count toward breaker when 403 carries WAF-class signals:
    //   - server: cloudflare / cloudfront / akamai / fastly / sucuri / incapsula
    //   - x-* WAF headers: cf-ray, x-amzn-waf-action, x-akamai-staging, x-incap-*
    //   - body contains "blocked by" / "ray id" / "request id" + "waf" / "firewall"
    //   - status 429 (rate limit) — counts directly
    // 403 without WAF signal during authz testing is signal, not noise — keep
    // going. Tip: tag tests with phase=authz to flag this branch.
    if waf_blocks_consecutive >= 5 OR rate_limit_consecutive >= 5:
      REPORT("Circuit breaker triggered: {N} consecutive WAF/rate-limit blocks. Slow down or pivot to OOB/encoded payloads.")
      BREAK
    if errors_consecutive >= 10:
      REPORT("Circuit breaker triggered: {N} consecutive non-403 errors (5xx, network). Likely server overload or session expired.")
      BREAK

    // Phase execution
    match phase:
      "recon":
        run Phase 1 + Phase 2 from hunt skill
        save all intel
        phase = "hypothesize"
        CHECKPOINT(mode)

      "hypothesize":
        // Rule 4 / article Phase 2 — no testing yet, intel → falsifiable claims.
        derive 5-8 attack hypotheses from recon intel, each as:
          { endpoint, param, vuln_class, expected_evidence, score }
          where score = (impact × likelihood) ÷ effort
        persist to notes.md under "## Hypotheses" (survives compaction, Rule 31)
        phase = "test"
        CHECKPOINT(mode)

      "test":
        pick highest-scored untested hypothesis (fallback: next class in Impact-First order)
        if none left:
          phase = "chain"
          continue
        run the probe/tool for that hypothesis
        if suspected finding: run VALIDATION GATE (below) before appending
        save coverage + findings
        CHECKPOINT(mode)

      "chain":
        // Every LOW/observation gets ONE escalation cycle — even a single finding.
        for each finding of severity <= LOW (and each escalation-worthy note):
          ask "what does this ENABLE?"; run propose_chains / chain-findings.md
          success → chained finding with chain_with[]; failure → note in notes.md
        if findings.length >= 2:
          attempt cross-finding chains (chain-findings.md)
        phase = "report"

      "report":
        generate summary
        BREAK

    // Error tracking — separate WAF/rate-limit from auth-control / generic
    if last_action_had_error:
      if last_status == 429:
        rate_limit_consecutive += 1
      elif last_status == 403 AND has_waf_signal(headers, body):
        waf_blocks_consecutive += 1
      elif last_status == 403 AND in_authz_test_phase:
        // Expected response during IDOR/BFLA/auth-matrix — DO NOT increment
        pass
      else:
        errors_consecutive += 1
    else:
      errors_consecutive = 0
      waf_blocks_consecutive = 0
      rate_limit_consecutive = 0

    // Finding handling by mode
    if new_finding_detected:
      findings.append(new_finding)
      match checkpoint_mode:
        "paranoid":
          PAUSE("Found: {finding.summary}. Verify and continue? [y/skip/stop]")
        "normal":
          // Continue, batch report at phase end
        "aggressive":
          if finding.severity == "CRITICAL":
            PAUSE("CRITICAL finding: {finding.summary}. Review before continuing.")
          // Otherwise continue
```

## Validation Gate (Rule 10 — every suspected finding, no exceptions)

Before a finding may enter findings[] / the board:
1. verify — replay the confirming request (verify-finding.md Step 0).
   For *_blind / sqli_time / race_condition / request_smuggling: replay ≥3×,
   capture {logger_index, elapsed_ms, status_code} per replay → reproductions[].
2. assess_finding(vuln_type, evidence, endpoint, parameter, domain).
   Verdict DO NOT REPORT / NEEDS MORE EVIDENCE → do NOT save; route to
   save_target_notes. It is a note, never a report entry (Rule 14a).
3. save_finding(...) only on a passing assess.

A finding that never clears assess is a note, not a submission.

## Checkpoint Behavior

### --paranoid (default)
```
After EVERY finding:
  Show: finding summary, severity, evidence snippet
  Ask: "Continue hunting? [yes/skip-category/investigate/stop]"
  - yes → continue current category
  - skip-category → move to next vuln category
  - investigate → switch to investigate skill on this finding
  - stop → go to report phase

After EVERY phase:
  Show: full progress dashboard
  Ask: "Proceed to next phase?"
```

### --normal
```
After EACH phase:
  Show: findings from this phase, total progress
  Ask: "Continue to next phase? [yes/reprioritize/stop]"

Findings accumulate silently within a phase.
```

### --aggressive
```
Only stops for:
  - CRITICAL findings (always review critical)
  - Circuit breaker triggers
  - Max iterations reached
  - All categories exhausted

Everything else runs without pausing.
```

## Progress Dashboard

Show this at each checkpoint:

```
╔══════════════════════════════════════════════════╗
║  AUTOPILOT: {domain}                             ║
║  Mode: {paranoid|normal|aggressive}              ║
║  Iteration: {N}/{max}  Phase: {current_phase}    ║
╠══════════════════════════════════════════════════╣
║  FINDINGS                                        ║
║  Critical: {N}  High: {N}  Medium: {N}  Low: {N} ║
║                                                  ║
║  COVERAGE                                        ║
║  Endpoints: {tested}/{total} ({pct}%)            ║
║  Categories: {tested_cats}/{total_cats}           ║
║  ✓ {completed categories...}                     ║
║  → {current category}                            ║
║  · {remaining categories...}                     ║
║                                                  ║
║  HEALTH                                          ║
║  Consecutive errors: {N}/5                       ║
║  Last response: {status_code} ({elapsed}ms)      ║
║  Session: {session_name} (active)                ║
╚══════════════════════════════════════════════════╝
```

## Audit Trail

Log every action for reproducibility:

```
save_target_notes(domain, notes + """
## Autopilot Session {timestamp}
Mode: {mode}, Max iterations: {max}
Duration: {start} → {end}

### Actions Log
| # | Action | Target | Result |
|---|--------|--------|--------|
| 1 | discover_attack_surface | / | 23 endpoints |
| 2 | auto_probe(sqli) | /api/users?id= | score 45 (suspected) |
| 3 | verify sqli | /api/users?id= | CONFIRMED (time-based) |
...

### Findings Summary
{findings table}

### Coverage Gaps
{what wasn't tested and why}
""")
```

## Resuming Autopilot

If autopilot was interrupted (context limit, user stop, error):

1. `load_target_intel(domain, "all")` — get current state
2. `load_target_intel(domain, "coverage")` — see what's been tested
3. `load_target_intel(domain, "notes")` — read the audit trail
4. Resume from the last incomplete phase/category
5. Don't re-test already-covered parameters (check coverage entries)

## Integration with Agents

When running autopilot with agent dispatch (recommended for speed):

```
Phase "recon":
  Dispatch recon-agent + js-analyst in parallel (see dispatch-agents skill)

Phase "test":
  Dispatch up to 3 vuln-scanner agents on non-overlapping targets
  Orchestrator monitors progress and merges results

Phase "chain":
  Run sequentially (needs full finding context)

Phase "report":
  Run sequentially (needs full context for summary)
```

## Emergency Stop

If at ANY point you detect:
- Requests going to wrong domain (scope breach)
- Unexpected destructive responses (data being deleted)
- Signs of WAF permanent ban (all requests 403 with ban page)
- Target appears to be a production system with real user data at risk

**STOP IMMEDIATELY.** Report to user. Do not attempt recovery.
