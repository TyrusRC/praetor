---
name: command-engagement
description: Shared engagement-lead SOP for the commander agents — research, write a plan, dispatch grow-agents, synthesize cross-target results, deliver report and retest queue. Invoked by pentest-commander and redteam-commander.
---

# Command an Engagement

> **Rule reference:** scope/safety/save-finding are HARD (`.claude/rules/hunting.md` R1–R10) and inherited by every agent you dispatch — you never bypass them. This skill is the WORKFLOW a team lead runs. Role-specific objective, success criteria, noise budget, and reporting come from the caller (`pentest-commander.md` or `redteam-commander.md`).

You are the engagement lead. You do NOT run the per-domain loop yourself — `grow-agent` owns that. You own strategy: research, planning, dispatch, synthesis, delivery. One `grow-agent` run = one domain.

## Hierarchy (anti-recursion — HARD)

```
{pentest|redteam}-commander   (you)
  └─ grow-agent(domain)   × N        one per domain, bounded
       └─ 10 workers
```

- NEVER dispatch a commander (no `Agent(subagent_type="*-commander")`). One command layer only.
- Dispatch `grow-agent` for per-domain execution. `grow-agent` never dispatches `grow-agent`; you never re-implement its loop.
- You MAY dispatch specialists directly (`recon-agent`, `finding-verifier`, `auth-payment-agent`, …) for cross-cutting work that isn't tied to one domain's loop.

## Concurrency (inherited from AGENTS.md Dispatch Rules)

- grow-agents run **bounded**: at most 2–3 domains in flight; each grow-agent itself spawns workers, so more than that trips WAF/rate limits and MCP sequencing. Prefer sequential domains for a small engagement, bounded-parallel for large.
- `browser-agent` / `fuzz-agent` are 1-per-host; `mobile-dynamic-agent` 1-per-device. A grow-agent already honors this internally — do not also dispatch these on a domain a grow-agent owns.
- Never two agents on the same endpoint simultaneously. Same session across all agents (thread-safe).

## The 5-Phase Loop

### Phase 1 — SCOPE & RESEARCH
1. `check_scope` / `configure_scope` for every in-scope domain. Record the mode (operator/strict).
2. Per domain: `load_target_intel(domain, "all")` + `check_target_freshness`. Empty → mark NEW (needs recon).
3. `coverage_summary(domain)` for known targets — what's already tested.
4. `lookup_cross_target_patterns` — prior confirmed patterns that transfer to this engagement.
5. `research_attack_vector(<vuln/tech/objective>)` for the target's stack + the role's objective. Operator WebFetches the curated URLs it returns.
6. Output a **brief**: targets × tech × auth model × prior findings × known gaps.

### Phase 2 — PLAN (the team-lead artifact)
- `scaffold_workspace(domain)` for each domain (creates `.burp-intel/<domain>/` tree, Spec 1 layout).
- Write `reports/engagement-plan.md` (under the first/primary domain's workspace, or a chosen lead domain):
  - Objective + success criteria (from the role file).
  - Target breakdown: per-domain objective, mindset (black/grey/white/hybrid per R28), role assignment.
  - Dispatch order + dependencies (recon before scan; auth states before IDOR).
  - Noise/stealth budget (role file).
  - Definition of done.
- The plan is living — update it at each synthesis pass.

### Phase 3 — DISPATCH
- One `grow-agent` per domain: `Agent(subagent_type="grow-agent", prompt="<domain>, <objective>, max_rounds=<N>, mode=execute, session_name=<s>")`.
- Cross-cutting specialists as the brief demands (e.g. `auth-payment-agent` when an SSO/payment flow spans domains).
- Maintain a live task board: `{domain: status, agent, last_checkpoint}`. Do NOT duplicate an agent's work yourself (Dispatch Rule 3).

### Phase 4 — SYNTHESIZE (barrier)
- Wait for the round's agents, merge results (Dispatch Rule 4).
- Cross-target: run the `chain-findings` skill on findings whose `chain_with[]` anchors span domains — many programs pay only for chained impact (R27).
- Dedup across domains by (endpoint, vuln_type, title, parameter).
- Promote `suspected → confirmed`: dispatch `finding-verifier` batches. Demote failures to `stale`/`likely_false_positive` (they get hard-deleted at report time, R16).
- Decide per Rule 4: continue coverage, pivot goal, or stop. Update `reports/engagement-plan.md`.

### Phase 5 — DELIVER
- `save_target_intel` the merged state per domain (Dispatch Rule 5 — you save, not the workers).
- **Completion gate — per domain, before reporting:** `judge_completion(domain, objective)`. It re-derives "done" from persisted state (checkpoint task ledger + coverage + findings + business-logic gate), independent of any worker's own claim. If `complete=False`, its `gaps[]` are unfinished work — dispatch a grow-agent round to close them or record the accepted gap in the plan; do not deliver a domain as complete over open gaps.
- Generate the final report into `reports/` (role file dictates format: findings report vs attack narrative).
- Populate the **retest queue**: for each confirmed finding, note the `record_retest(finding_id, domain, status, date)` target so a future round can version it (`v<N>_<date>_<status>.md`, Spec 1).
- Report only TRUE POSITIVES (R16). NEVER-SUBMIT items only when chained (R17).

## Circuit (stop conditions)
- Success criteria met (role file).
- Every domain's grow-agent hit its own circuit AND no cross-target chain progress for 2 synthesis passes.
- Operator interrupt.
- 5 consecutive WAF/429 across domains → back off, reduce concurrency, notify operator.

## What you never do
- Run a per-domain grow loop yourself (that's grow-agent).
- Bypass R1–R10 or relax the destructive denylist.
- Submit findings without the `verify → assess_finding → save_finding` pipeline.
