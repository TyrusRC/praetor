---
description: Run a coverage-driven pentest and produce the full scoped checklist markdown (WSTG + Top 10 + API/Mobile/LLM + KB edge cases)
argument-hint: <target-domain> [scope: web api mobile llm]
---

You are running `/checklist` — a **full-coverage pentest** on `$ARGUMENTS`.

Goal: full-coverage testing against the latest OWASP standards + Praetor's KB
edge cases, ending in a single markdown checklist file the operator can read and
a client report. Follow `.claude/rules/hunting.md` and the `command-engagement`
skill throughout.

## Phase 0 — confirm (R28/R32, ask once if unstated)
1. Parse the target domain from the arguments. If no domain is given, ask for it.
2. Determine **scope**: which surfaces are in play — `web`, `api`, `mobile`,
   `llm` (any combination). If the arguments don't say, ASK the operator (state a
   default of `web`). This decides which standards go in the checklist.
3. Determine **objective/depth**: full-coverage-with-notes (default here) vs a
   named subset. Confirm mode (black/grey/white/hybrid) and whether creds / a
   second role / an API schema exist.

## Phase 1 — recon gate (R20a)
`load_target_intel(domain, "all")` + `check_target_freshness`. If the workspace
is empty, run a recon pass (`browser_crawl` → `full_recon` →
`discover_attack_surface`) and `save_target_intel` before testing.

## Phase 2 — build the checklist deliverable
Call `build_engagement_checklist(domain, scope="<scope>")`. This writes
`.burp-intel/<domain>/reports/<domain>-checklist.md` — the combined full list:
OWASP Top 10 (2025) + WSTG v4.2 for web, API Top 10 (2023) if api, MASVS/MASTG if
mobile, AI Testing Guide if llm, **plus every applicable KB test class as edge
cases**. Report the path to the operator.

## Phase 3 — auto-execute ALL open items (ONE CALL)
Run `checklist_autorun(domain, session, standard)`. This single tool:
- Reads all open checklist items
- Runs auto_probe for KB-category items (batch, all categories at once)
- Runs individual test/confirm tools for specific items
- Records all results to the checklist automatically
- Returns a gap summary

```
checklist_autorun(domain, session, standard)
```

If items remain (blockers, missing session/Collaborator), the summary says
what to unblock. Fix the blocker and re-run `checklist_autorun`. Repeat
until `checklist_gaps(domain, standard, show='missing')` returns 0 missing.

Every confirmed finding from the autorun goes through the save pipeline:
`assess_finding → save_finding`. After autorun completes, review the
findings and escalate (escalate_ssti, escalate_sqli, etc.) where impact
classes were confirmed.

**Manual follow-up for INCONCLUSIVE items:** `checklist_autotest` returns the
remaining open items with their mapped tool. Run each manually, grade on the
response body (Rule 13a), and `checklist_update` with the result.

## Phase 4 — deliverables
- `checklist_gaps(domain, standard, show='all')` — the full tested-vs-missing table.
- `test_journal(domain)` — every test that ran, with verdict and evidence index.
- The regenerated `reports/<domain>-checklist.md` (full list + status).
- `generate_report(audience='client')` for the findings report.
- `coverage_status(domain)` for the standards roll-up.

Prefer dispatching `pentest-commander` for a multi-domain / large engagement;
otherwise drive the loop directly.
