# grow-agent Design

**Date:** 2026-05-22
**Status:** Approved (operator brainstorm 2026-05-22)
**Scope:** Project-only. No cross-project surface.

## 1. Goal

Single dispatchable orchestrator that owns the full pentest session lifecycle for one domain. Consolidates Rule 20a (session-start gate) + Rule 4 (goal-driven loop) + Rule 22 (decision compaction) + Rule 21 (checkpointing). Improves over time by promoting confirmed cross-target patterns into KB/skill proposals.

Inspired by Hermes (Nous Research): persistent memory + auto-generated skills + isolated subagents + zero-context pipelines. This project already has the persistent memory (`.burp-intel/`) and the subagent roster (`AGENTS.md`). grow-agent is the missing orchestrator that ties them together.

## 2. Architecture

```
Operator
  │
  ▼
Agent(subagent_type="grow-agent", prompt=<domain + objective + max_rounds>)
  │
  ▼
grow-agent (one-shot run, on-demand)
  │
  ├─► load_target_intel(domain, "all") + check_target_freshness
  │   (Rule 20a session-start gate)
  │
  ├─► [per round, ONE of:]
  │   ├─► Agent(subagent_type="<role>") — dispatches recon-agent / vuln-scanner / etc.
  │   ├─► Direct MCP call — auto_probe / test_* / session_request / chain-findings
  │   ├─► Proposal write — .burp-intel/_growth/proposals/<ts>-*.json
  │   ├─► Chain attempt — chain-findings skill on candidates
  │   └─► Stop — write checkpoint, return summary
  │
  ├─► save_target_intel(domain, ...) [after each round]
  │
  └─► .burp-intel/_growth/patterns.json [auto-write on confirmed finding]
```

### 2.1 Form Factor

- `.claude/agents/grow-agent.md` — YAML frontmatter + markdown body. Auto-discovered by Claude Code's `Agent` tool.
- Sub-agents in `.claude/agents/<name>.md` (10 files total post-plan): grow-agent + 9 from AGENTS.md.
- No new MCP tool. No Python/Java changes. All behavior lives in the agent definition files (markdown) + uses existing MCP tools.

### 2.2 Storage

New directory `.burp-intel/_growth/` (project-relative, gitignored):

| Path | Mode | Schema |
|---|---|---|
| `_growth/patterns.json` | **AUTO-WRITE** | `{ patterns: [{vuln_type, tech_fingerprint, evidence_signature, confirmed_count, domains[], first_seen, last_seen}] }` |
| `_growth/proposals/<ts>-kb-<vuln>.json` | **PROPOSE-ONLY** | matches `mcp-server/.../knowledge/<vuln>.json` schema; adds `_proposal_meta: {confirmed_count, domains_seen, evidence_template, source_finding_ids}` |
| `_growth/proposals/<ts>-skill-<name>.md` | **PROPOSE-ONLY** | matches `.claude/skills/*.md` format; adds frontmatter `_proposal_meta:` |
| `_growth/proposals/<ts>-matcher-fix-<vuln>.json` | **PROPOSE-ONLY** | `{file: "<existing kb path>", matcher_path: "contexts.<ctx>.matchers[N]", current: {...}, proposed: {...}, reason: "<why>"}` |

`<ts>` = ISO-8601 compact (`20260522T143012Z`).

## 3. Inputs

| Param | Type | Default | Notes |
|---|---|---|---|
| `domain` | string | required | Target slug (matches `.burp-intel/<domain>/`) |
| `objective` | string | `"broad coverage"` | Engagement focus — guides round-2+ decisions |
| `max_rounds` | int | 20 | Hard circuit breaker |
| `mode` | `"plan"`/`"execute"`/`"reflect"` | `"execute"` | `plan` returns decision tree without acting; `reflect` analyzes prior session, no act |
| `session_name` | string | optional | Burp session name; required for grey-box mindset |

## 4. The Grow Loop

One round = one atomic decision. Rule 22 enforced.

```
LOAD intel
  load_target_intel(domain, "all")
  check_target_freshness(domain, session_name)
  IF empty → RECON PHASE FIRST:
    Agent(subagent_type="recon-agent", prompt="<domain>, full surface")
    Agent(subagent_type="js-analyst", prompt="<domain>, secrets+DOM")
    (parallel; orchestrator merges)

ASSESS gap
  - coverage_delta = (endpoint × vuln_class) tuples filtered by tech stack, minus coverage.json hits at current knowledge_version
  - chain_candidates = findings with chain_with[] anchors available + at least one CONFIRMED anchor
  - promotion_candidates = scan _growth/patterns.json for (confirmed_count ≥ 2 AND domains_seen ≥ 2) NOT yet in proposals/

DECIDE — pick ONE:
  a) dispatch_subagent — pick from .claude/agents/<role>.md by AGENTS.md mapping
  b) direct_tool       — single MCP call (auto_probe / test_* / session_request / ...)
  c) write_proposal    — generate proposals/<ts>-{kb,skill,matcher-fix}.* from promotion_candidates
  d) chain_attempt     — invoke chain-findings skill on chain_candidates
  e) stop              — circuit hit OR no gap remaining OR objective satisfied

EXECUTE
  - State hypothesis: "I expect <observable> if <vuln-class> exists at <param>"
  - Call the chosen action
  - Baseline diff: compare against recorded `{status, length, response_hash}` from coverage.json or fresh baseline
  - Outcome: {covered: yes/no, finding: yes/no, evidence_signature: <hash>}

PROMOTE
  AUTO-WRITE (low risk):
    - coverage.json entries via save_target_intel (existing pipeline)
    - _growth/patterns.json: on assess_finding verdict='confirmed', append/increment pattern row
  PROPOSE-ONLY (higher risk surfaces):
    - When (vuln_type, fingerprint_signature) in patterns.json crosses threshold,
      write proposals/<ts>-kb-<vuln>.json
    - When confirmed chain (anchors[N] sequence) repeats across ≥2 domains,
      write proposals/<ts>-skill-<chain-name>.md
    - When MatcherEngine fails-closed on a manually-confirmed finding,
      write proposals/<ts>-matcher-fix-<vuln>.json

CHECKPOINT
  save_target_intel(domain, ...) — coverage + findings + notes
  Append round audit line to .burp-intel/<domain>/notes.md:
    "Round N | <action> | <target> | hypothesis: <h> | outcome: <o>"
  Update auto-memory entry IF lesson is global (applies_to: global per R21)

CIRCUIT
  STOP if any:
    - round_count >= max_rounds
    - 3 consecutive rounds with coverage_delta == 0 AND no chain progress
    - 5 consecutive WAF/429 responses (autopilot.md circuit-breaker)
    - operator interrupt
```

## 5. Decision Compaction (Rule 22 Per-Round)

Each round MUST produce exactly one action. No compound dispatches in a single round.

| Round phase | Allowed |
|---|---|
| Load + Assess | Reads only — no writes, no requests |
| Decide | One menu item |
| Execute | One MCP call OR one Agent dispatch OR one file write |
| Promote + Checkpoint | Writes to intel + _growth (mechanical, no decisions) |

A round dispatching `recon-agent + js-analyst` in parallel IS allowed as ONE action — the canonical "Recon Fanout" pattern from AGENTS.md is a single decision unit.

## 6. Subagent Integration

grow-agent dispatches by name. All 10 `.claude/agents/*.md` files MUST exist post-plan.

| Trigger | Subagent | Pattern (AGENTS.md) |
|---|---|---|
| Empty intel | `recon-agent` + `js-analyst` (parallel) | Recon Fanout |
| Recon done, uncovered classes | up to 3 × `vuln-scanner` non-overlapping | Vulnerability Parallel |
| Auth states ≥ 2 | `auth-tester` | — |
| Anomaly with filter signal | `payload-crafter` | Investigation + Continued Scanning |
| Suspected → needs replay | `finding-verifier` | Verify Batch |
| SPA / heavy JS | `browser-agent` | Constraint: 1 at a time |
| OAuth/payment surface | `auth-payment-agent` | Auth + Payment Sweep |
| Hidden-path tier | `fuzz-agent` | Constraint: 1 per host |
| Mobile engagement | `mobile-dynamic-agent` | Mobile Pipeline (sequential) |

grow-agent does NOT duplicate work that an agent is doing. Per AGENTS.md Rule 3: "if you dispatch an agent to scan for SQLi, don't also scan for SQLi yourself."

## 7. Growth Mechanism — Pattern Promotion

### 7.1 Auto-Write (Low Risk)

`_growth/patterns.json` is updated on every `assess_finding` verdict='confirmed'. Operation:

```
on confirmed_finding(domain, vuln_type, evidence):
  fingerprint = hash(tech_stack + endpoint_template + parameter_role)
  evidence_sig = hash(evidence_normalized)
  key = (vuln_type, fingerprint, evidence_sig)
  patterns[key].confirmed_count += 1
  patterns[key].domains.add(domain)
  patterns[key].last_seen = utc_now()
```

Coverage updates use existing `save_target_intel` pipeline — no change.

### 7.2 Propose-Only (Higher Risk)

When a pattern row crosses threshold (`confirmed_count ≥ 2 AND domains_seen ≥ 2`) AND no existing proposal targets the same key, grow-agent writes one of:

- **New KB probe** (`<ts>-kb-<vuln>.json`): generated from `evidence_template` + matcher inferred from `evidence_signature`. Schema validated against existing `mcp-server/.../knowledge/*.json` shape.
- **New skill / playbook** (`<ts>-skill-<name>.md`): generated when a chain pattern (anchors[N]) repeats across domains. Frontmatter + markdown body describing the chain.
- **Matcher fix** (`<ts>-matcher-fix-<vuln>.json`): generated when a confirmed finding's evidence didn't fire the existing KB matcher. Points to the file + matcher path + proposed change.

Operator merges proposals manually. No automatic write to `mcp-server/.../knowledge/` or `.claude/skills/`.

### 7.3 Threshold Rationale

Single-domain patterns are intel, not knowledge. KB entries shipped to all users must generalize. Two domains is the minimum non-trivial cross-target signal.

## 8. Outputs Per Run

| Output | Path | Mode |
|---|---|---|
| Intel updates | `.burp-intel/<domain>/{profile,endpoints,coverage,findings,fingerprint,patterns,notes}.json` | Existing tool layer (save_target_intel) |
| Round audit log | `.burp-intel/<domain>/notes.md` (append) | grow-agent |
| Pattern aggregate | `.burp-intel/_growth/patterns.json` | grow-agent (auto-write) |
| Proposals | `.burp-intel/_growth/proposals/<ts>-*.{json,md}` | grow-agent (propose-only) |
| Auto-memory | `~/.claude/projects/<slug>/memory/` | grow-agent (when lesson is global per R21) |

## 9. Rule Alignment

| Rule | How grow-agent honors it |
|---|---|
| R1 (scope) | Every action goes through tool layer — `check_scope` enforced upstream. grow-agent never bypasses. |
| R5–R9 (safety) | Inherited; never overridden. No destructive payloads in proposals. Collaborator-only for blind OOB. |
| R10 (save-finding pipeline) | grow-agent always invokes `verify → assess_finding → save_finding`. Never writes `findings.json` directly. |
| R11–R13 (evidence) | Baseline diff is part of EXECUTE step. Verified evidence required before promoting to patterns.json. |
| R14–R17 (reporting) | grow-agent does not generate reports; defers to `generate_report`. NEVER-SUBMIT list checked by `assess_finding`. |
| R18 (annotate + organize) | grow-agent calls `annotate_request` + `send_to_organizer` after every interesting captured request. |
| R19 (full coverage) | Skip class only when (impossible-for-stack ∧ KB+param-name cleared ∧ documented-negative). No token-economy skip path. |
| R20a (session-start gate) | grow-agent IS the gate when invoked first. |
| R21 (checkpoint) | Every round ends with `save_target_intel`. |
| R22 (one smart call) | Enforced per-round in DECIDE. |
| R26 (volume work routed through Burp) | grow-agent never writes raw `requests`/`httpx`. All volume via MCP tools. |
| R27 (creative hunting) | ≥20% of rounds budget for open-ended exploration. grow-agent tracks `unstructured_rounds / total_rounds` and steers DECIDE accordingly. |
| R28 (mode per call) | grow-agent re-evaluates black/grey-box per round when session state changes. |

## 10. Anti-Patterns

| Anti-pattern | Why forbidden |
|---|---|
| Multi-decision rounds | Violates R22; muddles audit log |
| Re-testing covered (endpoint, vuln, knowledge_version) | Wasted tokens; R19 documented-negative check |
| Direct write to `knowledge/*.json` or `skills/*.md` | Propose-only surface; operator review required |
| Promoting single-domain patterns | Insufficient cross-target signal |
| Skipping `assess_finding` | Bypasses 7-question gate; R10 violation |
| Calling grow-agent recursively | One run = one domain; no nested orchestration |

## 11. Out of Scope (Follow-Ups)

- `/grow-merge` slash command to apply approved proposals into `knowledge/` and `skills/` (separate spec)
- Multi-domain orchestration in a single run
- Cron / background firing (Hermes scheduler) — explicitly rejected per operator answer (on-demand only)
- Cross-project pattern sharing (project-scoped per operator answer)
- Auto-generated MatcherEngine matchers beyond fail-closed repairs

## 12. Success Criteria

- `Agent(subagent_type="grow-agent", prompt={domain})` runs to completion without orchestrator intervention up to `max_rounds`
- After a session, `.burp-intel/_growth/patterns.json` reflects confirmed findings
- A simulated 3-domain test produces at least one `proposals/<ts>-kb-<vuln>.json` candidate
- Total round count for "broad coverage" on a fresh target ≤ 20 (default `max_rounds`)
- Existing tests still pass (367 Python, 24 Java)

## 13. Risk Register

| Risk | Mitigation |
|---|---|
| Subagent definition files diverge from AGENTS.md | Plan task explicitly cross-references; CLAUDE.md update mentions agents/ |
| Proposals dir grows unbounded | `.gitignore` excludes; operator merges + deletes by hand. Future `/grow-merge` will clean. |
| Pattern fingerprint hash collides | `evidence_signature` includes raw normalized evidence string; collision = same finding (fine) |
| grow-agent recursion | Explicitly forbidden in §10; grow-agent prompt instructs "do not Agent(subagent_type='grow-agent')" |
| Subagent file not yet defined | Plan creates all 10 files; falls back to `general-purpose` with inlined role prompt only if a future role is missing |
| Token blow-up from long sessions | `max_rounds=20` default; circuit-breaker on 3 zero-delta rounds |

## 14. Rollback

`.claude/agents/grow-agent.md` and 9 sub-agent files are pure markdown. Rollback = `git revert <commit>`. No code, no schema, no DB migrations. `.burp-intel/_growth/` directory is gitignored — deleting it removes all state.
