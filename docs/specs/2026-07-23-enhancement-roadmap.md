# Enhancement Roadmap — 2026-07-23

**Status:** Design. Master index for Specs D/E/F.
**Source:** Four parallel research tracks (token-economy audit, competitive gap analysis, OSS agent-framework study, 2026-H2 technique refresh). Findings and sources archived in the specs below.

## Thesis

Praetor's **per-attack-class depth and evidence provenance already beat commercial DAST**. The competitive frontier — XBOW, Horizon3 NodeZero, Terra, Alias CAI — leads on four axes Praetor lags:

1. **Autonomy loop** — continuous find→exploit→validate, re-run on target change.
2. **Validation rigor** — deterministic provers decoupled from the explorer (anti-LLM-cheat).
3. **KB-freshness speed** — Nuclei-AI ships templates hours after disclosure; Praetor is on a weekly hand-authored cadence.
4. **Per-decision token cost** — competitors amortize with fine-tuned/distilled models.

Every item below **builds on primitives Praetor already ships**. No green-field.

## Moats — defend, do not trade away for autonomy

- **Evidence provenance.** Every finding is Burp-captured + `logger_index`-replayable. XBOW's own research documents LLMs fabricating proof; Praetor's replay + `VerdictResult` + NEVER-SUBMIT gate is the structural counter. This is the strongest moat — every autonomy feature must preserve it.
- **AI-agent attack surface.** ASI Top 10, MCP schema-drift, A2A card audit, CUA injection, FastMCP SSRF. The autonomous-pentester frontier does not test the agent-infra layer. Genuine 2026 lead.
- **Business-logic + race depth**, **payment/auth specialization** ($5k–$50k lane), **persistent cross-session memory + coverage**, **breadth** (web + API + mobile + desktop + cloud/k8s in one toolkit).

## Phases (recommended sequence)

| Phase | Spec | Content | Risk | Why here |
|---|---|---|---|---|
| 0 | E (Part 1) | Token quick wins: `load_target_intel` field projection, verdict double-encode kill, strip `indent=2` | Near-zero | Batch-first; immediate per-session savings; unblocks cheaper everything-else |
| 1 | D | KB P0 refresh (4 techniques) + P1 intake | Low | The headline "enhance KB" ask; concrete, high-value |
| 2 | E (Part 2) | Agent-team efficiency: progress ledger, effort-scaling ladder, least-privilege tools, blackboard-read | Low | "Treat as AI agent" upgrade; folds toward the pending agent-council spec |
| 3 | F | Autonomy frontier: NL→probe generator, adversarial validator, continuous diff loop | Med | Strategic gap closure vs XBOW/NodeZero; larger builds |

## Spec index

- **Spec D** — `2026-07-23-spec-D-kb-refresh-2026h2.md` — knowledge-base + probe refresh (Phase 1). Forecast as a follow-on in Spec 1.
- **Spec E** — `2026-07-23-spec-E-token-and-agent-efficiency.md` — token-return plumbing (Phase 0) + agent-team orchestration (Phase 2).
- **Spec F** — `2026-07-23-spec-F-autonomy-frontier.md` — autonomy/validation/freshness frontier (Phase 3).

## Cross-spec dependencies

- Spec F's **adversarial validator** extends `confirm_with_clean_room` and the agent-council spec's Tier-2 panel.
- Spec E's **blackboard-read** and **handoff artifact** fold into `2026-07-21-agent-council-design.md`.
- Spec F's **NL→probe generator** is the automation engine behind Spec D's cadence problem — Spec D closes today's gaps by hand; Spec F stops the gap from re-opening weekly.

## Excluded

- Fabricated CVE IDs surfaced from AI-content-farm domains (see Spec D "Hallucination guard"). No KB context is minted around any CVE without an authoritative vendor/NVD advisory.
- Live peer-to-peer agent chat, auction handoff, LLM-manager free-form delegation, fully-autonomous no-gate operation, auto-patching skills — anti-patterns incompatible with sequential MCP and/or the operator-gated safety model (see Spec E "Anti-patterns").
- Internal-network / AD lateral-movement module — strategic bet gated on target market; not in these three specs.
