# Competitive Gap-Closure Roadmap (W33+)

Date: 2026-07-20
Status: proposed
Scope basis: full-codebase review (371 tools / 197 files / 138 KB / 53 skills / 14 agents) + competitive recon against 13 AI-pentest projects and OWASP Nettacker / Google Sec-Gemini.

## Out of scope (operator decision)

- **Detection-accuracy benchmark** (labeled-corpus precision/recall, OWASP Benchmark / WAVSEP / Juice-Shop FP tables). Explicitly dropped. `benchmark.py` stays CTF-flag-capture only.

## Framing

Two findings shape priorities:

1. **Tool-surface token cost is already handled.** The Claude Code transport auto-defers tool schemas >10% context (CLAUDE.md, Tier-1 note). Adding server-side lazy registration saves little token budget. The real defect is **selection accuracy**: `pick_tool` is a hand-ordered 55-bucket first-match substring matcher (`advisor/pick_tool.py:8-286`) covering ~55 of 371 tools; any miss drops to a 22-tool Tier-1 hint and the model free-selects over the rest. Fix routing quality, not token count.
2. **Praetor's verification + export surface already exceeds commercial DAST.** No competitor reviewed beats its 7-question gate / NEVER-SUBMIT taxonomy / SARIF+JUnit+4-platform+CVSS4.0+KEV/EPSS export. Do not rebuild these. Adopt only what fills a real hole.

Waves ordered by (impact against a named gap) × (low effort / fits existing pattern). Lazy-senior default: deletion and KB-drop-in over new subsystems.

---

## W33 — Efficiency & selection accuracy (no new coverage)

### W33-a — Replace `pick_tool` first-match with tag-scored routing
- **Gap:** fragile 55-bucket ordering; `["cve-2"]→msf_search` (`pick_tool.py:181`) shadows specific CVE routes; ~349 tools unrouted.
- **Fix:** give every `@mcp.tool()` a `tags=[...]` + one-line `intent` in its registration metadata. `pick_tool` scores tag+keyword overlap across the full set and returns top-3 ranked, not first-match. Deterministic, no LLM, no embeddings.
- **Source:** Anthropic-Cybersecurity-Skills (frontmatter-scan-then-load), ClaudeBrain (`triggers.json` prompt→skill hook).
- **Effort:** medium. Touches `advisor/pick_tool.py` + a tag field on registrations. No transport change.

### W33-b — Disambiguate near-duplicate tools (NOT merge — inspection reversed this)
- **Inspection finding (2026-07-20):** the "redundant" tools are distinct engines/transports, not duplicates. Deleting any removes real capability:
  - `msf_*` shells out to `msfconsole` (works out-of-box); `msfrpc_*` is a client for the separate `msfrpcd` JSON-RPC daemon (fast, opt-in). The msfrpc module is *"purely additive for ops that justify the daemon setup."*
  - 403 trio = 3 different bypass engines (in-process `probe_40x_bypass` + `dontgo403` + `byp4xx` binaries), graceful-degrade.
  - `extract_*_batch` has a distinct dedup-synthesis output contract, not a rename of the single-index tools.
- **Action taken:** did NOT delete. Added the missing `msfrpc` route to `pick_tool` so the fast-daemon path is selectable. Selection-accuracy — the real problem — is addressed by W33-a alternatives, not by shrinking a surface whose token cost the transport already defers.
- **Effort:** done (one routing add).

### W33-c — Runaway guard + cost-budget wiring + cleanup registry
- **Loop guard:** abort/re-plan when the same tool+args fires ≥N times (source: PentAGI mentor @5 identical calls). Praetor has no runaway backstop.
- **Wire the dead rail:** `check_cost_budget` (`intel/cost_cap.py:123`) is defined but has zero callers. Call it at entry of the 4 expensive tools (`auto_probe`, `run_recon_pipeline`, `browser_crawl`, `concurrent_requests`); early-exit on cap.
- **Cleanup registry:** reverse-order teardown of sessions / collaborator pools / repeater tabs on abort/budget-exhaustion (source: Pentest-Swarm-AI).
- **Effort:** low-medium.

### W33-d — `<UNTRUSTED_TOOL_OUTPUT>` delimiter wrapping
- Wrap external-tool stdout (nuclei/ffuf/subfinder/katana) in delimiters before it enters model context — currently ingested raw. Blunts prompt injection from attacker-controlled scan output.
- **Source:** Guardian-CLI. **Effort:** low. Touches the `_run_cmd` recon wrapper path.

---

## W34 — Coverage: highest real-world impact, fits existing KB pattern

### W34-a — Edge-appliance version→CVE module pack
- **Gap:** KB skews to modern web frameworks; misses internet-facing appliance RCEs that dominate real breaches.
- **Fix:** KB drop-ins (existing `auto_probe` pattern) + `map_tech_to_cves` fingerprints for: Ivanti (ICS/EPMM/CSA), Citrix (CVE-2019-19781, 2023-4966 Bleed), F5 BIG-IP (2020-5902), PAN-OS GlobalProtect (2025-0108/0133), MOVEit, CrushFTP (2025-31161), SonicWall SSLVPN (2024-53704), Exchange ProxyLogon/ProxyShell, Confluence, TeamCity, GeoServer, Log4Shell.
- **Source:** OWASP Nettacker vuln/ modules. **Effort:** low — JSON KB files, no new tool code.

### W34-b — Framework tagging on KB files + findings
- Add `attack_ck` (MITRE ATT&CK technique ID), `atlas` (AI/ML), `wstg` IDs to KB context metadata; surface in `assess_finding` output and reports.
- Unlocks coverage-as-% (of ATT&CK/WSTG) and MITRE-mapped client reports — a differentiator, and a real coverage lens vs the current class list.
- **Source:** Anthropic-Cybersecurity-Skills 6-framework mapping. **Effort:** medium (mechanical KB annotation + report field).

### W34-c — Threat-actor / campaign attribution enrichment
- Extend `kev_epss_enrich` (`cve/_register_kev_epss.py`): "is-exploited/EPSS" → add "who exploits this" (actor/campaign) for business-impact framing (Rule 16a).
- **Source:** Google Sec-Gemini (Mandiant/GTI grounding). **Effort:** medium — needs a free/available actor-CVE feed; degrade gracefully if none.

---

## W35 — Internal-network / AD (scope decision required)

This is a genuine build, not an adoption — no reviewed project ships the tooling, only references it. **Decision needed before starting:** does Praetor stay web/API/cloud-scoped, or expand into internal-network/AD? Recommend documenting as an explicit non-goal in README unless an engagement demands it.

If pursued (mirrors existing `run_*` wrapper + subagent pattern):
- Wrapper module: `netexec`, `bloodhound-python`, `kerbrute`, `impacket`, `nmap`/`masscan`.
- Non-HTTP service **default-cred** checks (SSH/FTP/SMB/SMTP/telnet) — bounded, non-dictionary, Rule-6-safe (source: Nettacker brute/ modules).
- New subagents `ad-agent` / `network-agent` under the existing tier.
- **Source:** Guardian-CLI, pentest-ai-agents, Nettacker. **Effort:** high.

---

## W36 — Frontier gap-closure (2026-07-21 research pass)

Sources: BH USA 2026 briefings, QUIC-er Races (Springer IJIS 2026), AI-pentest-agent evals (ARTEMIS / "From Controlled to the Wild"), Burp 2026.6, Invicti 20260416. Only items NOT already shipped. Already-covered and excluded: Unicode WAF split (`probe_unicode_normalize_split`), MCP rug-pull (`detect_mcp_schema_drift`), HTTP/2 single-packet race (`probe_race_singlepacket`).

### W36-P1 — Business-logic completion gate (highest ROI)
- **Gap:** ARTEMIS — top human 13 bugs via business logic/chaining vs best agent 9; "~70% of critical web vulns live in business logic, the one class no agent detects reliably." Praetor's `test_business_logic` / `infer_business_invariants` / `capture_business_context` / Rule 27 are advisory — nothing enforces they ran. Recon gate (Rule 20a) is enforced; the business-logic pass is not.
- **Fix:** promote business-context capture + invariant inference to a completion gate. `generate_report` warns and the engagement is not "done" until `testcases/business-logic-matrix.json` exists for the domain. Turns Rule 27's soft 20% into a measured pass. Reuses existing tools; no new engine.
- **Effort:** medium.

### W36-P2 — HTTP/3 single-datagram race
- **Gap:** QUIC-er Races / BH 2026 SSRO — single UDP datagram lands 20-30 requests simultaneously, N≈100 saturates the QUIC parser; 87% vuln rate top-10k domains, 96.4% precision. Distinct from `probe_race_singlepacket` (TCP/h2) and `probe_http3_downgrade` (forces h3→h2).
- **Fix:** `transport='h3'` datagram mode on `probe_race_singlepacket` or sibling `probe_race_http3_datagram`. VerdictResult, fits the `probe_race_*` family.
- **Effort:** low-medium.

### W36-P3 — AI-assistant attack classes (KB drop-ins, dispatch under `run_owasp_asi_top10`)
- Remote Prompt Execution (RPE / ChatMate): file upload → prompt executes in assistant sandbox → host escape. Distinct from `probe_cua_injection_surface` (DOM channel).
- Agentic trust-handoff / stage confusion: early stage marks state "safe," later stage over-trusts. Complements `probe_workflow_reorder` + `confirm_with_clean_room`.
- LLM-gateway execution blindness: gateway inspects prompt/response, misses tool execution.
- **Fix:** 3 new KB contexts + ASI recipes. No new engine.
- **Effort:** low.

### W36-P4 — Source-code API route inventory (Invicti parity)
- **Gap:** Invicti discovers APIs from source; Praetor only from crawl/proxy/JS. Grey/white-box hole.
- **Fix:** extend `sast_to_endpoint_risk` (opengrep already wrapped) to parse framework route defs (Flask/FastAPI/Express/Spring `@RequestMapping`) into `endpoints.json`. Skip eBPF (out of Claude Code's lane).
- **Effort:** medium.

### W36-P5 — Rank-driven `auto_probe` ordering (Burp 2026.6 parity)
- **Gap:** Burp 2026.6 continuously reprioritizes the audit queue, highest-value first. Praetor's `rank_attack_targets` / `risk_rank_endpoints` don't drive `auto_probe` order.
- **Fix:** wire `rank_attack_targets` as the default probe order in `auto_probe`.
- **Effort:** low.

### Noted, not built
- Hallucination / "imagined output" loops — countered by Rule 10a live-`logger_index` resolution + W33-c loop guard; no-tool-call streak detection is harness-level, not in-tool. Known ceiling.
- WSUS / non-HTTP appliance backdoors (BH 2026) — under the W35 internal-network non-goal.

---

## W37 — Large-context engagement state (MiMo-Code pass, 2026-07-21)

Source: `XiaomiMiMo/MiMo-Code` — checkpoint.md task-tree + independent goal/stop judge. Mapping showed Praetor covers roles / skill-discovery / memory distillation / structured per-agent status already; the two real gaps were durable task state and an independent completion check. Both file-based, no new deps, reuse existing `.burp-intel/` + `business_logic_gate`.

### W37-A — Durable engagement checkpoint + task ledger (SHIPPED)
- **Gap:** engagement task state lived only in prose (`notes.md`) + model context; a compacted/resumed agent re-derived it. No hierarchical plan tree, no single durable `next_action`.
- **Fix:** `write_checkpoint` / `load_checkpoint` → `.burp-intel/<domain>/checkpoint.json` (phase, round, next_action, hierarchical task tree, open_threads). Merges by task id (field-level; a status flip never drops a title/note). `intel/checkpoint.py`. Wired: grow-agent Round 0 LOAD + CHECKPOINT step, resume.md step 1b.
- **Effort:** low. Done.

### W37-B — Independent completion judge (SHIPPED)
- **Gap:** grow-agent's stop condition is mechanical (rounds / coverage_delta / WAF). Nothing verified the engagement was actually finished — open tasks, un-revisited threads, or a skipped business-logic pass all passed the circuit breaker.
- **Fix:** `judge_completion(domain, objective)` — deterministic verdict re-derived from persisted state (checkpoint tasks + coverage + findings + `business_logic_gate`), independent of the agent's own narrative. complete only when all gates clear; zero findings does NOT block (a fully-worked clean target is done). `report/completion_judge.py`. Wired: grow-agent STOP GATE, command-engagement Phase 5 per-domain gate.
- **Effort:** low. Done.

Tests: `tests/test_w37_checkpoint_judge.py` (13). Routing: `pick_tool` W37 block.

---

## Backlog — adopt opportunistically

| Idea | Source | Note |
|---|---|---|
| Multi-agent debate triage (Red/Blue/Judge) before `assess_finding` | Guardian-CLI | Claimed ≥5pt F1; test before committing agent cost |
| CVSS-vector re-computation validator | Guardian-CLI | `compute_cvss` exists; cross-check operator severity vs vector math |
| Episodic action→outcome memory + selective recall + cred-redact | PentAGI, PentesterFlow | Avoid repeating dead-end probes; extends `.burp-intel` intel |
| Active untested-class next-move surfacer from `coverage.json` | ClaudeBrain | Rank untested (endpoint×class) tuples in `get_next_action` |
| Portable proof capsule (one-command replay bundle) | pentest-ai | Extends `export_poc_bundle`; NOT a benchmark |
| Paired Sigma/SPL/KQL + ATT&CK ID per technique | pentest-ai-agents | Purple-team deliverable upgrade |
| Diff-scoped CI review mode (probe only changed endpoints) | Strix | Maps to `findings_diff` |
| Structured JSON agent status schema | VoltAgent | Replace prose returns in grow-agent orchestration |
| Lite-mode Haiku routing for advisory/triage subagents | pentest-ai-agents | Cost cut, no methodology loss |
| RSA/local-key-encrypted OAST payloads | pentest-ai | Provider sees metadata only |

## Explicitly NOT adopting

- Docker-per-agent sandbox (Strix/PentAGI) — Praetor runs in Claude Code, not a server; sandbox is the harness's job.
- Vector-DB/Neo4j memory (PentAGI Graphiti) — over-engineered vs the file-based `.burp-intel` intel that already works.
- Auto-fix / PR-patch generation (Strix) — out of a pentest tool's lane; scope creep.
- Push-time / CI leak-scan + frontmatter linter (ClaudeBrain, pentest-ai-agents) — Praetor is a local tool; engagement findings live in gitignored `.burp-intel/` and are never pushed, so a pre-push gate solves a problem this project doesn't have.
```
