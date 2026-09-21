---
name: swarm-hunting
description: Stigmergic multi-agent hunting — coordinate specialists through the .burp-intel blackboard with pheromone-weighted leads, trigger-predicate routing, and decay, so attack chains emerge concurrently instead of running a fixed recon→scan→report pipeline. Reactive upgrade to dispatch-agents.
---

# Swarm Hunting — stigmergic coordination

`dispatch-agents.md` runs FIXED patterns (recon fanout → category split → verify
batch) that the orchestrator sequences. This skill is the REACTIVE upgrade: the
swarm coordinates through shared state, not a script — a new finding wakes whichever
specialist it is relevant to, lead priorities decay, and attack chains emerge instead
of being scripted. Use it once recon has seeded the board and there are many live
leads to work at once.

> Converted from Pentest-Swarm-AI's swarm model. Praetor doesn't own the agent loop
> (the host runtime does), so the "swarm" here is a coordination DISCIPLINE over
> Praetor's existing shared stores — not a new runtime.

## The primitives → Praetor substrate

| Swarm primitive | Praetor substrate |
|---|---|
| **Blackboard** (shared state agents read/write) | `.burp-intel/<domain>/` — `findings.json`, `coverage.json`, `engagement.json`, `notes.md`. Every agent reads via `target_brief(domain)` first and writes via `save_finding` / `record_fact` / `save_target_intel`. |
| **Pheromone weight** (a lead's pull; strongest first) | lead priority = anomaly/finding score × class value. Rank with `rank_attack_targets` / `risk_rank_endpoints` / `route_signals`; MEDIUM+ and injection-reaching-a-sink outrank recon noise (Rule 29). |
| **Decay** (stale paths die) | `check_target_freshness` + coverage's `knowledge_version`: a tuple already covered-negative at the current KB version loses its pull (Rules 19/20). `next_untested_targets` surfaces what still has weight. |
| **Trigger predicate** (a finding auto-routes to one specialist) | the routing table below — a NEW fact of a given shape wakes exactly one agent, with no central plan. |
| **Emergence** (chains no one scripted) | `propose_chains` + `plan_attack_paths` over the board fold a fresh finding into new leads (open-redirect → OAuth token theft; leaked cred → auth-tester). |

## The loop (grow-agent runs it; a commander seeds it)

1. **Read the board.** `target_brief(domain)` + `coverage_summary` + `get_findings(severity_min='medium', summary_only=True)`.
2. **Rank live leads by pheromone.** `rank_attack_targets` / `route_signals` → highest score × class-value, minus decayed (covered) tuples.
3. **Fire trigger predicates.** For each top lead, match its SHAPE to the routing table → dispatch that one specialist. ≤6 concurrent, non-overlapping endpoints (dispatch-agents cap). No fixed phase order — whatever the board makes hottest goes first.
4. **Fold results back.** Persist to the board (`record_fact` links the intent; `save_finding` gates + persists). A new finding re-weights the board and may fire a NEW predicate — emergence: a leaked token wakes `auth-tester`, an SSRF wakes cloud-metadata testing.
5. **Decay + repeat.** Covered-negative tuples lose weight; `next_untested_targets` shows remaining pull. Loop until no lead clears the MEDIUM+ floor — that is the signal to change approach, not to file noise (Rule 29).

## Trigger-predicate routing (a finding SHAPE → the agent it wakes)

| New fact on the board | Predicate fires → agent |
|---|---|
| leaked credential / token / secret | `auth-tester` (reuse → IDOR / privesc); `auth-payment-agent` if OAuth/JWT |
| SSRF / internal host / metadata reachable | `vuln-scanner` → `test_cloud_metadata` / `test_ssrf` chain |
| open redirect / reflected param | `auth-payment-agent` (redirect_uri → token theft) — never file alone (Rule 17) |
| new endpoints / params discovered | `vuln-scanner`, partitioned by param risk (id→sqli, search→xss, file→lfi) |
| JS bundle / source map | `js-analyst` → secrets + hidden API + DOM sinks |
| auth state acquired (cookies / bearer) | `auth-tester` → `test_auth_matrix` across roles (Rule 28 grey-box switch) |
| suspected finding, unproven | `finding-verifier` → `confirm_*` + `assess_finding` (verifier never saves) |
| WAF / filter blocks a payload | `payload-crafter` → `mutate_payload` bypass |

This is the dispatch-agents routing table, but driven by what LANDS on the board
rather than by a phase you chose in advance.

## Guardrails (a swarm does not relax them)

- Concurrency cap **6** (the Java `ApiServer` thread pool); never two agents on one endpoint (WAF).
- Least-privilege (Spec E2.3): recon / js agents RETURN intel; only the orchestrator gates + persists (`save_finding` / `confirm_*`).
- Cost: `check_cost_budget` before ≥4 workers; decay + the MEDIUM+ floor keep the swarm off covered ground.
- Every dispatched agent gets the dispatch-agents **Mandatory Briefing Block** verbatim.

## When to use vs dispatch-agents

- **dispatch-agents** — fresh target / a known phase (recon fanout, verify batch). Fixed, predictable.
- **swarm-hunting** — a warm target with many live leads, where you want reactive, emergent coverage at breadth. The board is hot; let the pheromones route.
