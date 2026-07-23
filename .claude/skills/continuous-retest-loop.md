---
name: continuous-retest-loop
description: Re-test a target on every change instead of once per engagement — detect drift, then re-run ONLY the affected (endpoint,class) tuples. Matches the XBOW/NodeZero/Detectify "test on every change" frontier (Spec F4).
---

# Continuous Re-Test Loop (Spec F4)

Goal: when a target changes, re-test only what changed — not a full re-scan. Every tool exists; this wires them into a driver.

## Loop

```
1. DETECT DRIFT:
     check_target_freshness(domain, session)      # baseline vs now
     easm_monitor_loop(...)  / visual_easm_diff(...)   # surface new/changed assets
     → if nothing changed: sleep / exit. Do NOT re-scan an unchanged target.
2. SCOPE THE DELTA:
     scope_targets_to_diff(...)                    # new + changed endpoints only
     findings_diff(domain)                         # what moved since last round
     coverage.json                                 # which (endpoint,class) tuples exist
     → affected = changed endpoints × applicable classes NOT already covered-at-this-knowledge-version
3. RE-RUN (surgical):
     auto_probe(session, targets=affected, skip_already_covered=True)
     # only the affected tuples — the whole point is NOT a full sweep
4. TRIAGE DELTA:
     new finding      → verify pipeline (finding-verifier) → assess → save
     regressed (fixed→present again) → record_retest(fid, domain, 'regressed', date)
     fixed (present→gone)            → record_retest(fid, domain, 'fixed', date)
5. SURFACE: write_checkpoint(domain, progress={...}) + notify operator of the delta only.
```

## Hard rails
- **Stay in scope + budget.** Consult `check_cost_budget` each cycle; pause on breach. Respect the engagement scope mode.
- **Don't re-scan the world.** If `check_target_freshness` says unchanged, the correct action is to do nothing. Re-running full coverage on an unchanged target is the anti-pattern this loop exists to avoid.
- **Retests are additive.** Use `record_retest` (status ∈ confirmed|reopened|fixed|regressed) — it appends to `findings.json.retests[]` and writes an immutable snapshot; never rewrite history.

## Scheduling
This is a driver you re-enter, not a always-on daemon. Pair with a cron/loop at a cadence matched to how fast the target actually changes (daily for active dev, weekly for stable). The `ScheduleWakeup`/loop harness or an external cron drives re-entry; each entry is one cheap DETECT → (maybe) surgical re-run.
