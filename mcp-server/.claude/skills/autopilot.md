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

## Autopilot Loop

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

    // Circuit breaker check
    if errors_consecutive >= 5:
      REPORT("Circuit breaker triggered after {errors_consecutive} consecutive errors")
      BREAK

    // Phase execution
    match phase:
      "recon":
        run Phase 1 + Phase 2 from hunt skill
        save all intel
        phase = "test"
        CHECKPOINT(mode)

      "test":
        select next untested category from priority list
        if no categories left:
          phase = "chain"
          continue
        run testing for selected category
        save coverage + findings
        CHECKPOINT(mode)

      "chain":
        if findings.length >= 2:
          attempt chain-findings skill on low/medium findings
        phase = "report"

      "report":
        generate summary
        BREAK

    // Error tracking
    if last_action_had_error:
      errors_consecutive += 1
    else:
      errors_consecutive = 0

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
