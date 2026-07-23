# Spec E — Token & Agent-Team Efficiency

**Date:** 2026-07-23
**Status:** Design, pending implementation plan.
**Scope:** Two parts sharing the token-discipline theme. **Part 1 (Phase 0):** near-zero-risk token-return plumbing. **Part 2 (Phase 2):** file-backed agent-team orchestration upgrades drawn from OSS multi-agent frameworks. Both preserve HARD safety and evidence provenance.

---

# Part 1 — Token quick wins (Phase 0)

Findings from a return-path audit of ~20 tools across the 386-decorator surface. All cite real `file:line`. Ordered by ROI. Reference implementation to copy: `tools/intel/checkpoint.py` (W37-C) — `_render` prints open tasks in full, collapses done tasks to a bare id list.

## E1.1 — `load_target_intel(findings)` field projection **[highest ROI]**
- **Waste:** `tools/intel/save_load.py:216,254` — `json.dumps(data, indent=2, default=str)` of the entire findings array (every `poc_request`, `evidence`, `reproductions[]`, `description`, `remediation`, `references`, `attack_walkthrough`). Rule 20a mandates this load at **every session start**, so every session and every agent dispatch pays it; it grows unbounded through an engagement. Has `limit/offset/sort_by/status_filter` but **no `fields=` projection**.
- **Fix:** add a `fields=[...]` whitelist mirroring `read.py:_slice_request_detail` (`read.py:87-123`). Default the Rule-20a session-start load to `["id","title","severity","status","endpoint","vuln_type"]`. Full body only when explicitly requested.
- **Effort:** low (~30 lines). Single biggest per-session saver.

## E1.2 — Kill the `VerdictResult` double-encode **[trivial, 71-tool blast radius]**
- **Waste:** `tools/testing/_verdict.py:55-71` — `make_verdict()` writes the human summary to **both** `details.summary` (line 57) and top-level `human_summary` (line 71). Every verdict from all 71 assessment tools ships the prose twice. Also emits `logger_indices`/`proxy_indices`/`collaborator_interactions`/`reproductions` as empty lists even on FAILED/ERROR.
- **Fix:** drop the `details.summary` duplicate (keep top-level `human_summary`); omit empty evidence-list keys. One helper edit propagates to all callers.
- **Effort:** trivial (~10 lines).

## E1.3 — Strip `indent=2` from machine-consumed returns **[trivial, broad]**
- **Waste:** `save_load.py:214,254`, `scan/auto_probe.py:274`, and ~10 other modules return `json.dumps(..., indent=2)` straight to the model. Indentation is ~15–30% pure overhead on nested structures for output no human reads mid-hunt.
- **Fix:** return the dict directly (FastMCP serializes compact) or use `separators=(",",":")`. Reserve indentation for `notes.md` / report artifacts only.
- **Effort:** trivial.

## E1.4 — `verbose=False` default on smart-tool `human_summary`
- **Waste:** `smart_js_analyze.py:513-543` and `smart_request_triage.py` return `attack_plan` (rich dicts: `suggested_call`, `rationale`, `canary`) **and** a `human_summary` that re-renders every row as text (`smart_js_analyze.py:526-530` loops `plan[:max_targets*2]`). Two encodings of identical data; ~20 tools co-return `human_summary` next to structured data.
- **Fix:** make `human_summary` opt-in (`verbose=False` default), or cap the text render to top-3 and let the structured list carry the rest.
- **Effort:** low.

## E1.5 — Extend `summary_only` to the top ~10 heavy returners
- **Waste:** `summary_only` is wired to only 3 of ~90 heavy tools (`analyze.py:210`, `discovery.py:17`, `recon_full.py:73`). The 48 `probe_*` + 35 `test_*` + 73 `run_*` OSS wrappers have no lean path; `run_nuclei`/`run_sqlmap`/`web_llm_sweep` can dump large output.
- **Fix:** standardize the flag (reuse `summary_only` or the `verbose` flag from E1.4) on the top ~10 volume returners: recon/nuclei/sqlmap/web_llm/graphql.
- **Effort:** medium.

**Batch order:** E1.2, E1.3 first (trivial, widest reach, near-zero risk), then E1.1 (biggest win), then E1.4, E1.5.

**Patterns already solved — do not touch:** `get_request_detail` field/body slicing (`read.py:87-123`), `extract_*` caps + `extract_*_batch` dedup, `load_target_intel` pagination, Haiku cost-tiering on no-exploit workers, lazy KB/skill loading (no always-loaded bloat found), `coverage_summary`/`next_untested_targets` cheap dashboards.

---

# Part 2 — Agent-team orchestration (Phase 2)

Drawn from Anthropic multi-agent research, Microsoft Magentic-One, Alias CAI, PentAGI, OpenHands, LangGraph, Hermes. **Constraint held throughout:** MCP is sequential; subagents return one final report and cannot message each other mid-run; all shared coordination is **file-backed** (`.burp-intel/<domain>/`). Items flagged **[net-new]**, **[extends council]** (`2026-07-21-agent-council-design.md`), or **[extends existing]**.

## E2.1 — Per-round Progress Ledger **[net-new, cheapest high-value]**
- **From:** Magentic-One's Task-Ledger / Progress-Ledger split.
- **Design:** each `grow-agent` CHECKPOINT round writes one structured line into `write_checkpoint`: `{request_satisfied, in_loop, progress_made, next_action, stall_reason}`. Finer than the current "3 zero-delta rounds" circuit — it names *why* progress stalled and detects thrash before the counter trips. Feeds the council's convene-on-stall trigger deterministically.
- **Build:** extend the checkpoint ledger schema (`tools/intel/checkpoint.py`); add the ledger-write step to `grow-agent.md`'s loop.

## E2.2 — Effort-scaling ladder **[net-new]**
- **From:** Anthropic (token usage explained 80% of eval variance; over-dispatch ≈ 15× tokens).
- **Design:** Praetor caps concurrency at 6 but has **no floor**. Add a routing rule to `grow-agent` DECIDE + `dispatch-agents.md`: trivial → direct tool, no agent; single class on ≤3 endpoints → 1 worker; broad coverage → partition to ≤6. Tie the decision to `check_cost_budget`.
- **Build:** process-only (skill + agent-file edits) + a `check_cost_budget` consult.

## E2.3 — Least-privilege `tools:` frontmatter per worker **[net-new, high impact / low effort]**
- **From:** PentAGI (per-role tool assignment), CAI (output guardrails at tool layer).
- **Design:** every worker is currently `Tools: All tools` (~368 surface). Scope each `.claude/agents/*.md` via `tools:` frontmatter — recon-agent gets discovery tools, NOT `save_finding`/`msf_*`; vuln-scanner gets probes, not report/export. Payoffs: fewer mis-tool selections (the exact failure Tier-1 targets), a **structural** scope guard (recon literally cannot call destructive tools), less selection ambiguity.
- **Build:** pure frontmatter. No code. Requires deciding per-worker tool sets — the one design task.

## E2.4 — Blackboard read at worker run-start **[extends council]**
- **From:** CAI — shared typed-finding exchange produced a 27% relative benchmark gain (self-reported), the single most evidence-backed idea in the study.
- **Design:** the council handles *proposals*; CAI's quantified win came from workers reading each other's *typed findings mid-engagement*. `.burp-intel/<domain>/` already IS the blackboard. Add to each worker's FIRST-MOVE: `load_target_intel` + `council_status(domain)` (uses E1.1's lean projection) before acting, so a round-N worker benefits from round N-1 peers without waiting for orchestrator merge.
- **Build:** FIRST-MOVE section edit in each worker `.md`; folds into the agent-council spec.

## E2.5 — Supporting items
- **Reference-return discipline [extends existing]** — mandate in `dispatch-agents.md`: workers persist full output to `.burp-intel` and return only lightweight references (finding ids, logger indices, top-N ranked), never full dumps. Protects the orchestrator's context across a 20-round loop.
- **Handoff artifact [extends council]** — formalize implicit handoffs (mobile→recon→vuln→verifier) as a written `handoff.json` `{from,to_specialist,context_refs,reason}` — a first-class replayable routing event, file-backed.
- **Skill-fix proposals [extends existing]** — when a worker follows a skill/playbook that proves wrong mid-run, emit a `<ts>-skill-fix-<name>.md` proposal. Detection only; stays operator-gated (do NOT adopt Hermes's auto-patch-during-use).
- **Output-QA gate at merge [extends existing]** — grow-agent confirms every claimed finding cites a resolvable `logger_index` before accepting a worker report; reject-for-rework otherwise. Deterministic, no second LLM jury (consistent with `debate_triage`'s no-hidden-juries principle).
- **Cost-in-loop [extends existing]** — the progress ledger (E2.1) records per-round cost delta; grow-agent consults `check_cost_budget` before a Tier-2 panel or 6-agent fanout.

## Anti-patterns — do NOT port
- **Live peer-to-peer / group chat** (AutoGen, CAI swarm) — impossible under sequential MCP. File-backed ledger is the correct adaptation.
- **Auction / bidding handoff** (CAI) — needs live negotiation; chatty/expensive. Keep the deterministic dispatch map.
- **LLM-manager free-form delegation** (CrewAI hierarchical) — documented to mis-route and re-run all tasks, inflating tokens. Keep the rule-based table.
- **Fully-autonomous no human gate** (PentAGI) — CAI's own research shows semi-autonomous + HITL wins. Keep `request_operator` + operator-gated merge.
- **Time-travel / checkpoint forking** (LangGraph) — low value for pentest; forked Burp/proxy state doesn't cleanly reconstruct. Keep linear resume.
- **Auto-patching skills during use** (Hermes) — conflicts with propose-only discipline. Adopt the drift *detection*, not the auto-write.

## Testing
- E1.1 field projection — unit test: projected load omits heavy fields, full load includes them.
- E1.2 verdict shape — assert no `details.summary` and no empty evidence-list keys on FAILED.
- E2.1 progress ledger — unit test the loop/stall boolean transitions.
- E2.3 tools frontmatter — assert each worker's declared tool set parses and excludes the forbidden tools.
- Skip trivial wiring (indent stripping, frontmatter that only narrows an existing allow-list) per project testing rules.

## Sources
Anthropic multi-agent research; Magentic-One (arXiv 2411.04468); CAI (Vilches 2026); PentAGI; OpenHands (ICLR 2025); CrewAI processes + manager-failure analysis; LangGraph interrupts; Hermes agent docs. Full URLs in the research archive. Unverified: CAI 27%/57.6% self-reported; PentAGI role count from secondary write-ups; Hermes auto-patch from project docs.
