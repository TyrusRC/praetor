# Spec 1 — Agent Council + Real-Eyes/Handoff

**Date:** 2026-07-21
**Status:** Design, pending implementation plan
**Scope:** This spec covers the peer-council collaboration layer and its two hard prerequisites (real vision + human handoff). Two follow-on specs are referenced but OUT of scope here: **Spec C — Offensive Depth** (RCE→foothold→lateral), **Spec D — KB/Payload/Technique Refresh**.

## Problem

The agent architecture is strictly top-down: `commander → grow-agent → 10 workers`. Workers return findings only. Strategy — and every technique idea — flows one direction: down. The single "beyond-KB" path today (`proposals/`) is confirmed-only and operator-gated. Consequences:

1. **No peer proposal.** A worker that spots a novel multi-step chain has no channel to raise it; the commander is the sole strategist and the sole bottleneck.
2. **Guesses, not observations.** Claude is blind to rendered reality — `browser_screenshot` returns a *file path*, not an image to Claude's vision; the CloakBrowser CDP session (network/console/a11y) is unused. Technique ideas are reasoned from DOM text.
3. **No human peer.** No operator-handoff tool exists (only an internal `_manual_or_failed` helper). The team cannot ask the operator to click, describe the app, or run an out-of-band step.

Result: creative, high-impact chains (the Rule 27 ≥20% budget) under-fire, and the ones that do fire are ungrounded.

## Goals

- Any agent (pentest OR redteam worker) can **propose a technique**, including ones outside the knowledge base.
- Peers **vote**; a deterministic tally decides pursue / refine / reject.
- The **human is a first-class voting peer**, invited when a proposal needs a manual action, app knowledge, an OOB step, or when the vote splits.
- Proposals are **grounded in real observations** (screenshots Claude actually sees, CDP signals, baseline deltas) — not guesses.
- The commander/grow-agent shifts from sole strategist to **convener + tally + tie-break + budget-enforcer**.
- **Token-optimized by default:** cheap self-debate is the default; real multi-agent panels fire only where the payoff justifies the spend.

## Non-Goals

- No weakening of HARD safety rules 5–9 or the destructive denylist. Novelty ≠ bypass. Every proposal that becomes a finding still routes `verify → assess_finding → save_finding`.
- No offensive post-exploitation primitives (Spec C).
- No KB content authoring here (Spec D) — this spec builds the *loop* that feeds Spec D.
- No peer-to-peer live messaging between subagents (MCP is sequential; impossible). Coordination is file-backed.

## Design Constraints (from the codebase)

- **MCP is sequential; subagents return a final report to the parent and cannot talk mid-run.** The council is therefore **file-backed** — a shared ledger is the only medium agents share.
- **Praetor tools are deterministic.** `debate_triage` deliberately hands the *calling* model a scaffold rather than running an LLM jury. Voting follows the same model: either the convener reasons through structured positions, or real voter subagents return votes that a deterministic tool tallies. No hidden juries.
- **Reuse existing infra:** `debate_triage`, `proposals/`, `record_probe_outcome`/`recall_probe_outcomes`, `research_attack_vector`. No parallel machinery.

## Architecture

### Council ledger (data model)

Lives under the existing per-domain workspace (gitignored):

```
.burp-intel/<domain>/council/
  ledger.jsonl                 # append-only event log
  proposals/<id>.json
  votes/<id>/<voter>.json
  verdicts/<id>.json
```

**`proposals/<id>.json`**
```json
{
  "id": "cp-<seq>",
  "author_agent": "js-analyst",
  "created": "<iso8601 from server>",
  "mode": "coverage | objective",
  "hypothesis": "one sentence: what and why it could work",
  "target": {"endpoint": "...", "parameter": "...", "domain": "..."},
  "beyond_kb": true,
  "steps": ["ordered probe steps"],
  "expected_signal": "the observable that would confirm",
  "trial_cost": "cheap | moderate | expensive",
  "safety_selfcheck": "confirms no destructive payload / no real-data exfil / in scope",
  "grounding_evidence": ["logger_index:412", "screenshot:...", "cdp_network:...", "baseline_delta:..."]
}
```
`grounding_evidence[]` is **required and non-empty** — a proposal with no cited real observation is rejected at write time. This is the mechanism that forces observation over guessing.

**`votes/<id>/<voter>.json`**
```json
{"voter": "red|blue|scout|judge|operator|<agent>",
 "verdict": "pursue|refine|reject",
 "confidence": 0.0,
 "rationale": "...",
 "risk_flag": "none|scope|noise|safety|dedup",
 "dedup_against": "finding_id or proposal_id or null"}
```

**`verdicts/<id>.json`**
```json
{"id": "cp-<seq>", "decision": "pursue|refine|reject",
 "tally": {"pursue": n, "refine": n, "reject": n},
 "assigned_trialer": "payload-crafter|vuln-scanner|...|null",
 "reason": "quorum rule that fired"}
```

### Roles

- **Proposer** — *any* worker agent, at the end of its run, emits 0..N proposals alongside its findings. Enforced by a new **PROPOSE** section in each worker agent file.
- **Voters** — panel generalized from `debate_triage`:
  - **Red** — why it works / what it unlocks.
  - **Blue** — noise / FP / already-covered / out-of-scope.
  - **Scout** — is it genuinely beyond-KB and worth the token spend, backed by `research_attack_vector`.
  - **Judge** — applies the rubric, records the tally.
- **Human peer (operator)** — invited via `request_operator` when a proposal needs a manual click, app knowledge, an OOB step, or when the vote splits (no clear quorum).
- **Trialer** — the appropriate specialist runs the top-voted proposal as a bounded experiment; result → ledger.
- **Promoter** — a trial that confirms AND generalizes (≥2 domains, or a strong single-domain novel win) is written to the existing operator-gated `proposals/` KB-merge path. This closes the loop into Spec D.

### Two voting tiers (token discipline)

- **Tier 1 — default, cheap.** The convener runs the structured self-debate scaffold (generalized `debate_triage`), records Red/Blue/Scout/Judge positions to the ledger itself, and calls `council_tally`. **Zero extra agent dispatches.** Human invited only on split or manual-step. This is the default for `trial_cost: cheap|moderate`.
- **Tier 2 — real panel.** For `trial_cost: expensive` OR `beyond_kb: true` with a split Tier-1 tally, dispatch actual **Red / Blue / Scout** voter subagents (3 dispatches, bounded), each returning a structured vote; `council_tally` decides deterministically. This is the literal "all agents vote as a peer council," reserved for where it pays off.

Quorum rule (deterministic, in `council_tally`):
- `pursue` if pursue-weight ≥ 2 and no unresolved `safety`/`scope` risk_flag.
- `refine` if the only blocker is a `refine` majority or a single `noise`/`dedup` flag → author revises and re-submits once.
- `reject` if any `safety`/`scope` flag stands, or reject-weight ≥ 2.
- **split** (no ≥2 majority) → escalate: Tier-1 → Tier-2, or Tier-2 → `request_operator`.

### Engagement modes

- **Coverage mode (pentest):** council convenes when coverage plateaus or an anomaly fits no KB class. Votes prioritize *which gap to close first*.
- **Objective mode (redteam):** council convenes when the kill chain stalls 3 rounds (Rule 4 pivot). Votes weight *advances-toward-objective × remaining noise budget*.
- **Convening is lazy** (token discipline): the council does NOT run every round. It fires only on the plateau/stall/anomaly triggers above, keeping the common path unchanged.

## Real-Eyes + Human Handoff (prerequisites)

Small, self-contained additions that make proposals grounded:

- **`browser_screenshot(..., return_to_model=True)`** — new flag returns the PNG as an image block to Claude's vision (default stays disk-path for report use, preserving current callers). Now Claude *sees* the rendered page.
- **`browser_devtools(signal="network|console|a11y|dom_snapshot")`** — opens a CDP session on the existing CloakBrowser page (`new_cdp_session`), returns the requested structured signal. No new browser process.
- **`request_operator(action, reason, options=[])`** — human-handoff. Emits a structured ask ("click the Export button and tell me what URL fires", "describe the checkout flow", "run this OOB step", "provide a callback URL"), pauses for the operator's reply, records it to the ledger as an `operator` vote or as `grounding_evidence`. This is the copilot channel.

## New MCP tools (build surface)

| Tool | Purpose |
|---|---|
| `council_propose(domain, hypothesis, target, steps, expected_signal, grounding_evidence, beyond_kb, trial_cost, mode)` | Write a proposal + ledger event. Rejects empty `grounding_evidence`. |
| `council_vote(proposal_id, voter, verdict, confidence, rationale, risk_flag, dedup_against)` | Record a vote. |
| `council_tally(proposal_id)` | Deterministic quorum decision → verdict file + ledger event. |
| `council_status(domain)` | Board of open proposals, tallies, verdicts (token-lean summary). |
| `request_operator(action, reason, options)` | Human-in-loop handoff. |
| `browser_screenshot(return_to_model=True)` | Return image to Claude's vision (flag on existing tool). |
| `browser_devtools(signal)` | Surface CDP network/console/a11y/dom_snapshot. |

## Process layer (no code)

- **`.claude/skills/agent-council.md`** — the council SOP: when to convene (triggers per mode), how to propose, the Tier-1/Tier-2 decision, the quorum rule, and the promote-to-KB handoff. Referenced by number from the rules where relevant.
- **PROPOSE section** added to each worker agent file (`recon-agent`, `js-analyst`, `vuln-scanner`, `auth-tester`, `payload-crafter`, `browser-agent`, `finding-verifier`, `auth-payment-agent`, `mobile-dynamic-agent`, `fuzz-agent`): at run end, emit grounded proposals via `council_propose`.
- **grow-agent** gains a **CONVENE** step in its loop (lazy triggers) and calls `council_status` at synthesis; the commanders' `command-engagement.md` Phase 4 references the council for cross-domain proposals.

## Data flow

```
worker run ─► finds anomaly / gap / stall
           ─► council_propose(grounded)                 [proposals/<id>.json + ledger]
convener   ─► Tier-1 self-debate ─► council_vote ×4     [votes/<id>/*]
           ─► council_tally                              [verdicts/<id>.json]
             ├─ pursue  ─► assign trialer ─► bounded experiment ─► verify pipeline
             ├─ refine  ─► author revises once
             ├─ reject  ─► ledger close
             └─ split   ─► Tier-2 panel OR request_operator (human vote)
trial win + generalizes ─► proposals/ (operator-gated KB merge)  [→ Spec D]
```

## Error handling & edge cases

- **Empty grounding** → `council_propose` returns error; no file written.
- **Duplicate proposal** (same target + hypothesis hash already open) → `council_propose` returns the existing id, no duplicate.
- **Safety/scope risk_flag on any vote** → `council_tally` can only return `reject` or (if unresolved) hold for `request_operator`; never `pursue`.
- **Operator unavailable** (no reply to `request_operator`) → proposal parked as `deferred` in the ledger; loop continues, does not block.
- **Ledger write race** (bounded-parallel agents) → append-only JSONL + per-proposal directories avoid clobber; `council_tally` reads the latest state.
- **Trial produces a finding** → normal `assess_finding`/`save_finding` gate applies; the council does not shortcut it.

## Testing

- `council_tally` quorum rules — unit tests over the decision table (pursue / refine / reject / split, safety-flag override, weights). This is real logic that can break.
- `council_propose` grounding + dedup rejection — unit tests.
- `browser_devtools` signal extraction — one integration test per signal against a known page.
- `request_operator` round-trip — records reply to ledger.
- Skip trivial wiring (registration, `council_status` formatting) per project testing rules.

## Token-optimization summary (explicit, per operator directive)

- Tier-1 self-debate is default → most proposals cost **zero extra dispatches**.
- Lazy convening → council fires only on plateau/stall/anomaly, not every round.
- `council_status` returns a token-lean board, not full proposal bodies.
- `return_to_model=True` is opt-in → screenshots hit vision only when a decision needs it.
- Real Tier-2 panels bounded to 3 voters and gated on `expensive`/split only.
- Reuses `debate_triage` / `research_attack_vector` rather than new reasoning scaffolds.

## Follow-on (out of scope)

- **Spec C — Offensive Depth:** `confirm_rce` → managed foothold → lateral-movement orchestration via the msf bridge, inside HARD rails. Depends on this spec (council convenes chains) + Real-Eyes.
- **Spec D — KB/Payload/Technique Refresh:** consumes promoted proposals from this spec's loop; audits coverage gaps surfaced by the council.
