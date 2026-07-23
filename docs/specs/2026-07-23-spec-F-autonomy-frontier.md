# Spec F — Autonomy Frontier

**Date:** 2026-07-23
**Status:** Design, pending implementation plan. Largest of the three; each item is independently shippable.
**Scope:** Close the four axes where the autonomous-pentester frontier (XBOW, Horizon3 NodeZero, Terra, Alias CAI) leads — autonomy loop, validation rigor, KB-freshness speed — WITHOUT abandoning Praetor's evidence-provenance and operator-gate moats. Depends conceptually on Spec E (progress ledger, cost-in-loop) and the agent-council spec (Tier-2 panel).

## Problem

Praetor's coverage and evidence discipline beat commercial DAST, but three structural gaps define the frontier:
1. **KB freshness** is weekly-hand-authored; Nuclei-AI ships templates hours after disclosure (Spec D closes today's gaps by hand — this spec stops them re-opening).
2. **Validation** is a heuristic 7-question gate; the frontier runs deterministic provers decoupled from the explorer and documents LLMs *cheating* (fabricated proof, reflected≠executed).
3. **Autonomy** is operator-triggered per session; the frontier re-tests continuously on target change.

## Goals

- Generate runnable probes from natural language and from fresh CVEs, schema-validated and fail-closed.
- Add an adversarial validator that re-derives proof deterministically and rejects known LLM shortcuts, raising the true-positive rate triagers pay for.
- Wire existing diff/monitor primitives into a scheduled continuous re-test driver.

## Non-Goals

- No weakening of HARD safety rules 5–9 or the destructive denylist. Generated probes are detection-only; a generated payload that trips the denylist is rejected at generation time.
- No submission automation — the `assess_finding`/`save_finding` gate and operator approval stay mandatory. Autonomy runs *exploration*; submission still blocks on a human.
- No internal-network/AD lateral module (separate strategic bet).

## F1 — NL→probe generator **[highest strategic ROI]**

- **Gap:** Nuclei `-ai` / PDCP generate templates from natural language; Praetor's KB is hand-authored JSON on a weekly cadence.
- **Design:** `generate_probe(description)` → Claude emits KB-schema matcher JSON → **validated against the `MatcherEngine` matcher-type set** (`status`/`word`/`regex`/`length_delta`/`collaborator`/`differential_timing`/… — unknown types fail closed, matching the engine's existing behavior) → runnable immediately via `auto_probe` without a KB-file drop.
- **Guards:**
  - Schema validation rejects malformed/unknown-matcher output (fail-closed).
  - **Safety filter:** the generated payload set passes the same destructive-denylist check as `confirm_*` before it can run (Rule 5). A generated `DROP TABLE`/`rm -rf` is rejected, not run-and-flagged.
  - OOB variants require a real Collaborator subdomain (Rule 9a).
  - Generated probes are **ephemeral by default**; promotion to a persistent KB file goes through the existing operator-gated `proposals/` merge path — so autonomy proposes, the operator curates. This is the freshness engine behind Spec D.
- **Build:** new `tools/` module + `@mcp.tool()`; reuse `MatcherEngine` type list as the validation authority; wire into `pick_tool`.

## F2 — Auto CVE→probe pipeline **[extends F1]**

- **Gap:** fresh-CVE coverage takes days (hand-built variant packs); the frontier is hours.
- **Design:** KEV/EPSS feed (`kev_epss_enrich` already wired) selects high-signal fresh CVEs → F1's generator emits a variant pack → runs via `probe_cve_with_variants`. First-CONFIRMED short-circuit (existing behavior).
- **Guards:** same hallucination guard as Spec D — a CVE with no authoritative advisory is not auto-probed. The pipeline consumes KEV/NVD, not content-farm feeds.
- **Build:** a scheduled driver over `kev_epss_enrich` → `generate_probe` → `probe_cve_with_variants`; operator-review queue before any generated CVE probe is persisted.

## F3 — Adversarial validator agent **[extends confirm_with_clean_room + council Tier-2]**

- **Gap:** the assess gate is heuristic; XBOW documents LLMs fabricating proof (`javascript:alert` pseudo-proto, `console.log("666")`, history-rewrite fakery, reflected-but-not-executed XSS).
- **Design:** split explorer from prover. A `validator` role re-derives proof **deterministically per vuln class** and rejects the catalogued LLM cheats. Decompose confirmation into a find→verify chain (XBOW's IDOR pattern: find endpoint → verify → find object ref → verify access → verify no-access-when-logged-out). Extends `confirm_with_clean_room` from a single second-pass replay into a class-specific proof chain; runs as the council's Tier-2 prover.
- **Guard:** the validator has no `save_finding` authority — it returns a verdict; the existing pipeline still gates the save. Preserves the evidence moat rather than replacing it.
- **Build:** validator agent definition (least-privilege tools per Spec E2.3) + per-class proof-chain recipes; a "known-cheat" reject list.

## F4 — Continuous diff re-test loop **[wires existing primitives]**

- **Gap:** agent runs are operator-triggered per session; the frontier re-tests on every target change (XBOW/NodeZero/Detectify).
- **Design:** wire `easm_monitor_loop` + `findings_diff` + `scope_targets_to_diff` + `coverage.json` into a scheduled driver: on detected target change, re-run only the affected `(endpoint,class)` tuples — not a full re-scan. Results diff into `findings.json`; regressions/new findings surface to the operator queue.
- **Guard:** stays within scope mode + cost cap; the loop consults `check_cost_budget` (Spec E cost-in-loop) and pauses on breach.
- **Build:** an orchestrating loop over primitives that already exist + a cron/schedule entry point; no new probe logic.

## Deferred (strategic bets, not in this spec)

Cross-scanner correlation / mini-ASPM (normalize nuclei/sqlmap/Burp/SAST into one `(endpoint,class)` model + reachability from `inventory_source_routes`); source-based shadow-API discovery (source-derived vs proxy-observed diff, StackHawk-style); learned pre-scan prioritization (lightweight logistic model over historical `findings.json`/`coverage.json`, replacing heuristic `rank_attack_targets`); distilled probe-router on a local model. Each is independently justified but gated on measured need / target market.

## Testing

- F1 generator — unit tests: valid description → schema-valid runnable probe; unknown-matcher output → fail-closed reject; destructive payload → safety reject. This is the core logic and must be well-tested.
- F3 validator — per-class fixtures asserting each catalogued LLM-cheat is rejected and a genuine proof passes.
- F4 loop — integration test: a simulated target change re-runs only the affected tuple, not the full set.
- F2 — assert a CVE with no advisory is not auto-probed.

## Sources

XBOW platform + strengths/weaknesses blog + benchmark (arXiv 2508.20816); NodeZero (Horizon3); Invicti proof-based scanning; Nuclei-templates-ai; ProjectDiscovery. Full URLs in the research archive. Vendor claims (Invicti "99.98%", XBOW cheat catalogue) flagged where not independently verified.
