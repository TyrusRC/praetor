# Large-File Split + Gap Fixes — Design Spec

**Date:** 2026-05-21
**Status:** Approved
**Scope:** Critical + High splits (7 files, ~7000 lines) + 4 gap fixes + 2 doc updates

## Goal

Reduce per-file complexity to enable focused reasoning and faster edits. Eliminate the four known gap items: Java test infrastructure, audit-log unbounded growth, collaborator-placeholder wiring confidence, recon-module overlap.

Behavior-preserving. No public API change. No new features.

## Motivation

Top 7 files by line count carry 60%+ of recent edit churn. SessionHandler alone is 2021 lines doing 9 distinct responsibilities. Reading-window saturation slows correct edits and increases regression risk. Java side has no test infrastructure — `not_status` matcher and ScopeHandler cold-start path are inspection-only.

## Non-Goals

- No behavior changes. No new MCP tools. No new KB files. No new HTTP routes.
- No performance optimization.
- No edits to files outside the 7 splits and 4 gap-fix paths.
- Files in 300-500 line range stay untouched unless directly involved.
- No headless Swing testing for ConfigTab — manual smoke only.

## Architecture

### Java handler split pattern (applies to A1, A6, A7)

- Original handler class keeps `handleRequest(HttpExchange)` as a thin path-dispatcher.
- Collaborator classes constructed once in handler ctor, held as `final` fields.
- Shared state (e.g., sessions map) extracts to a singleton store class — matches existing `ScopeHandler.currentMode` static pattern.
- Helper methods (regex extraction, string interpolation) become static utilities in dedicated classes.
- HTTP route paths and JSON response shapes frozen — verified by `grep "createContext" ApiServer.java | wc -l` before/after.

### Python module split pattern (applies to A3, A4, A5)

- Create package directory replacing the single-file module.
- `__init__.py` is a re-export shim — every symbol previously importable from the module remains importable via the same path.
- Submodules organized by responsibility (per-backend, per-question, per-API).
- `register(mcp)` consolidated in `register.py` submodule; imported by `__init__.py` so `from .tools import X; X.register(mcp)` keeps working in `server.py`.
- Explicit `__all__` declared in `__init__.py` to catch private-symbol breakage.
- One release cycle of shim, then shim deletion in follow-up.

### advisor/assess.py split pattern (A3)

- Orchestrator (`assess_finding_impl`) stays in `advisor/assess.py`.
- Each of the 7 validation questions becomes a single-purpose module under `advisor_kb/`:
  - `q1_scope.py`, `q2_repro.py`, `q3_impact.py`, `q4_dedup.py`, `q5_evidence.py` (exists), `q6_never_submit.py`, `q7_triager.py`
- Each exports `check(args) -> CheckResult` where `CheckResult` is a `TypedDict({passed: bool, reason: str, evidence: dict})`.
- Existing `advisor_kb/q5.py` is the structural template.

## Tasks

### A. Splits (7 files)

| # | File | Lines | Split target |
|---|---|---|---|
| A1 | `burp-extension/src/main/java/com/swissknife/handlers/SessionHandler.java` | 2021 | `store/SessionStore.java`, `session/SessionRequestExecutor.java`, `session/VariableExtractor.java`, `session/FlowRunner.java`, `session/AttackSurfaceDiscovery.java`, `session/AutoProbeOrchestrator.java`, `session/BatchProbeHandler.java`, `session/SessionExtractHandler.java`, thin `SessionHandler.java` |
| A2 | `mcp-server/src/burpsuite_mcp/tools/recon/scanning.py` | 1004 | `recon/scanning/` package per recon family (read body to determine exact split) |
| A3 | `mcp-server/src/burpsuite_mcp/tools/advisor/assess.py` | 884 | 6 new `advisor_kb/qN_*.py` modules + thin orchestrator |
| A4 | `mcp-server/src/burpsuite_mcp/tools/research.py` | 841 | `research/{exploitdb,osv,github_advisory,snyk,attackerkb,github_code,register}.py` |
| A5 | `mcp-server/src/burpsuite_mcp/tools/cve.py` | 816 | `cve/{match,shodan,nvd,register}.py` |
| A6 | `burp-extension/src/main/java/com/swissknife/handlers/AttackHandler.java` | 789 | `attack/{AuthMatrixHandler,RaceHandler,HppHandler}.java` + shared `attack/AttackContext.java` if needed |
| A7 | `burp-extension/src/main/java/com/swissknife/ui/ConfigTab.java` | 757 | `ui/{ScopePanel,InterceptPanel,MatchReplacePanel,...}.java` |

### B. Gap fixes (4 items)

**B1 — Audit log rotation.** Add `rotateIfNeeded()` to `audit/ScopeAuditLog.java`. Pre-append check: if `_audit.log` > 10MB, shift archives (`.1`→`.2`, `.2`→`.3`, …, drop `.5`) then rename current to `.1`. Test writes >10MB content, asserts archives created and sized correctly.

**B2 — Java test infrastructure.** Add to `burp-extension/pom.xml`:
- `<dependency>org.junit.jupiter:junit-jupiter:5.10.0</dependency>` (test scope)
- `<plugin>maven-surefire-plugin:3.2.0</plugin>`

First tests:
- `MatcherEngineTest` — covers `not_status` case (added in f67d84d, currently inspection-only)
- `ScopeHandlerColdStartTest` — covers volatile mode load from `.burp-intel/_scope_mode.json` on JVM start
- `ScopeAuditLogRotationTest` — supports B1

Test scope keeps prod classpath at zero external deps (rule preserved).

**B3 — Collaborator placeholder wiring.** Audit the 7 new auto-probe KB files (state_machine_race, oauth_dpop_confused_deputy, edge_worker_ssrf, webauthn_passkey_attacks, cache_deception_v2, dom_clobbering_2024, service_worker_attacks) for `COLLABORATOR_URL` / `{{collaborator}}` placeholders. Verify `scan/auto_probe.py` `_substitute_collaborator()` covers them. Add `test_collaborator_substitution.py` asserting all placeholders are replaced before send.

**B4 — recon overlap audit.** Read full bodies of `recon/scanning.py` and `recon_extended.py`. Document overlap in this spec under "Findings" section (appended post-audit). Code change only if duplication is clear and removable without behavior change.

### C. Docs (2 items)

**C1.** Update `CLAUDE.md` "Adding New Features" if module paths shift. Re-verify tool/KB/skill counts in line 45 against actuals.

**C2.** Append `MEMORY.md` `## Refactor (2026-05-21)` section listing the 7 splits + 4 gap fixes + structural changes operators should know.

## Execution Order

B2 → A3 → A4 → A5 → A1 → A6 → A7 → A2 → B1 → B3 → B4 → C1 → C2

Rationale:
- B2 first: test infra enables verification of later Java tasks.
- Python splits (A3-A5) before Java splits (A1, A6, A7): independent, lower risk, build confidence in pattern.
- A2 (recon/scanning) late: may interact with B4 overlap audit findings.
- B1 depends on B2 (uses JUnit).
- B3, B4 are audit-driven, low blast radius — defer to late.
- Docs last to capture final state.

## Success Criteria

**Per-task gate (commit-blocking):**
- `mvn -q clean package` exit 0
- `uv run python -m unittest discover tests -v` — all tests pass (≥324 baseline)
- `mvn test` green (after B2)
- No file in changed set > 500 lines (soft cap 400)
- Every previously-importable symbol still importable via old path
- MCP tool count unchanged (218): `grep -rE "@mcp\\.tool" mcp-server/src | wc -l`
- HTTP route count unchanged: `grep "createContext" burp-extension/src/main/java/com/swissknife/server/ApiServer.java | wc -l`

**End-state gate:**
- All 13 tasks green
- `wc -l` < 500 on every changed source file
- `MEMORY.md`, `skill.json`, `CLAUDE.md` counts re-verified
- Push to main: 13 commits + spec + plan

## Rollback

Each task = one atomic commit. `git revert <sha>` restores prior file. Shim files allow partial revert (revert split, keep callers). B2 is purely additive — safe to revert standalone. A1 (SessionHandler) carries highest risk — 9 new files; if integration breaks, revert as one commit.

No DB migrations, no state file format changes — pure code refactor.

## Risk Register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Hidden coupling in SessionHandler private state | High | Subagent reads full file before split; field-by-field migration documented in commit message |
| Re-export shim breaks `from X import Y` for private `_foo` symbols | Medium | Explicit `__all__` in `__init__.py`; smoke-import test asserts all prior public + private re-export |
| Maven junit-jupiter dependency leaks into prod classpath | Low | `<scope>test</scope>` enforced; verified by `mvn dependency:tree -Dscope=runtime` |
| Existing `advisor_kb/q5.py` doesn't match new pattern | Low | A3 subagent reads q5.py first; adapts q1-q4, q6-q7 to match |
| AttackHandler shared state across attack subclasses | Medium | Extract shared state to `AttackContext.java` if `grep` confirms cross-attack field access |
| ConfigTab Swing panels share UI state | Medium | Pass shared model object to panel ctors; no static state migration |
| recon/scanning.py inline `@mcp.tool` defs reference shared helpers | High | A2 subagent maps shared helpers before splitting; promotes to package-level `_shared.py` |

## Out of Scope (deferred to follow-ups)

- Files in 500-700 range (FuzzHandler, notes, JsSecretExtractor, dom_probe, recon_extended, DomAnalyzer, HttpSendHandler, browser). Split when touched.
- Audit log JSONL schema evolution (separate concern).
- CWD-coupled state path divergence between Java + Python (architectural, separate spec).
- KB probe orchestrator wiring beyond placeholder substitution (B3 only verifies substitution, not full execution).
