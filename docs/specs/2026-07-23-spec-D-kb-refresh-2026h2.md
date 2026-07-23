# Spec D — KB / Payload / Technique Refresh (2026 H2)

**Date:** 2026-07-23
**Status:** Design, pending implementation plan.
**Forecast in:** `2026-07-21-agent-council-design.md` ("Spec D — KB/Payload/Technique Refresh").
**Scope:** Net-new attack techniques and high-confidence CVEs published since the W37 KB drop. Only items NOT already covered (verified against the CLAUDE.md changelog). This spec authors KB content + a small number of new probes; it does NOT build the NL→probe generator (that is Spec F).

## Problem

The KB is hand-authored on a weekly `W##` cadence. Between drops, high-value public techniques go untested. The 2026-H2 harvest (PortSwigger Top-10-of-2025 published Feb 2026, plus mid-2026 advisories) contains four **P0** techniques Praetor cannot currently detect and six **P1** items, none in the current 150-file KB.

## Goals

- Close the four P0 detection gaps with KB contexts + probes that run through `auto_probe`/existing probe tools.
- Land the P1 intake as KB contexts and one to two targeted probes.
- Preserve the KB-org rule: merge into existing parents; add a new sibling file ONLY when no parent fits.
- Every CVE-derived context traces to an **authoritative** advisory (vendor/NVD/KEV). Content-farm CVE IDs are excluded.

## Non-Goals

- No NL/auto probe generation (Spec F).
- No KB content for UNVERIFIED CVE IDs until an authoritative source confirms.
- No changes to `MatcherEngine.java` matcher types unless a technique genuinely needs a new one (none identified here — all map to existing `word`/`regex`/`status`/`length_delta`/`collaborator`/`differential_timing`).

## Design constraints (from the codebase)

- **KB schema:** `{contexts: {ctx: {description, ...matchers}}}` per file in `mcp-server/src/burpsuite_mcp/knowledge/`. Loaded by category at `auto_probe` time; `_REFERENCE_ONLY` set in `tools/scan/_constants.py` excludes reference packs.
- **New probe tool:** module in `tools/`, `@mcp.tool()`, `register(mcp)`, import in `server.py`. Return `VerdictResult` via `verdict_from_tally` where it's a pass/fail detector.
- **KB-org rule:** new sibling KB file requires justification that no existing parent fits.
- **OOB (Rule 9a):** blind exfil variants use a real Collaborator/`generate_collaborator_payload` subdomain, never a fabricated domain.

## P0 — the four gaps (do first)

### D1. MCP invisible-unicode tool-metadata concealment
- **Technique:** Unicode TAG-block (U+E0000–E007F) + zero-width + bidi characters hidden in MCP tool names/descriptions/schemas. Invisible in the human approval view, delivered verbatim to the model. Defeats both human-review and text-filter layers.
- **Source:** arXiv 2607.05744 (Jul 2026); CSA Labs note (2026). MCPTox ASR up to 72.8%.
- **Praetor status:** has schema-drift + stdio-shell-meta + tool-poisoning KB, but NO invisible-unicode detector. Distinct defect class.
- **Build:** new probe `detect_mcp_invisible_unicode(server)` — scans tool names/descriptions/JSON schemas for TAG-block, zero-width, and bidi-override codepoints; returns `VerdictResult` with per-field hits. Reuse detectors from `unicode_normalization.json`. Add a `invisible_unicode_in_tool_metadata` context to `mcp_tool_poisoning.json` (existing parent).
- **Matcher:** `regex` on the codepoint ranges. Deterministic; no network.

### D2. Error-based / boolean-error blind SSTI ("Successful Errors")
- **Technique:** force the template engine to throw an error whose message *contains execution output* → blind SSTI extraction. Universal polyglot detection; payloads for Python/PHP/Java/Ruby/NodeJS/**Elixir**. #1 of PortSwigger Top-10-of-2025.
- **Source:** portswigger.net/research/top-10-web-hacking-techniques-of-2025; github.com/vladko312/Research_Successful_Errors (Jan 2026, folded into SSTImap).
- **Praetor status:** SSTI KBs cover engines but not the error-oracle method, and no Elixir engine.
- **Build:** add `error_based_blind` + `boolean_error_blind` contexts across existing `ssti_*.json` parents; add a universal-polyglot detection payload set. New sibling **`ssti_elixir.json`** (justified — no Elixir parent exists). Matcher: `word`/`regex` on the engine error echoing a unique marker (e.g. arithmetic result inside the exception text).
- **Wiring:** reachable via existing `test_ssti`/`confirm_ssti`/`auto_probe`.

### D3. SSRF via redirect-loop full-response leak
- **Technique:** attacker redirect server increments 3xx status (301→310) then 200; once the client's redirect threshold trips, the app's internal error handler leaks the *entire* redirect chain + final body. Turns blind SSRF into readable/full-response.
- **Source:** slcyber.io Assetnote SRC; PortSwigger Top-10-of-2025 #3.
- **Praetor status:** SSRF KBs lack the redirect-threshold-exhaustion leak.
- **Build:** `redirect_loop_full_response_leak` context in `ssrf_bypass.json`. Helper to stand up an incrementing-3xx OAST redirect chain — extend the `generate_collaborator_payload` / `build_encrypted_oast_payload` flow (Rule 9a: real Collaborator subdomain). Matcher: `length_delta` + `word` on leaked internal-response markers vs blind baseline.

### D4. Next.js May-2026 middleware / RSC batch
- **Technique / CVEs (Vercel-official, high confidence):**
  - **CVE-2026-44575** — App Router `.rsc`/segment-prefetch URLs reach protected content, skipping middleware.
  - **CVE-2026-44574** — crafted query params alter dynamic route values, hiding the path from middleware.
  - **CVE-2026-23870** — RSC Server-Function deserialization CPU-DoS (React 19.x / all App Router).
- **Source:** Vercel changelog + react.dev + Cloudflare (May 8 2026).
- **Praetor status:** `nextjs_cache_poisoning.json` + `react_server_components.json` have W31-c CVEs (44578/27980) but not this trio.
- **Build:** variant pack for `probe_cve_with_variants` (`nextjs_middleware_bypass` class: rsc/segment-prefetch + query-param route-override variants) + a Server-Function-deserialization-DoS context in `react_server_components.json`. **Dedup check:** CVE-2026-44573 (i18n locale-less `_next/data`) may overlap the W31-c "i18n middleware strip" context — verify before adding.

## P1 — intake (second pass)

| ID | Technique / CVE | Praetor form | Source |
|---|---|---|---|
| D5 | **MCP tool shadowing** (cross-server same-name registration mutates a trusted tool's behavior) | `cross_server_name_collision` context in `mcp_server_attacks.json`; optional check in `enumerate_mcp_server` | agyn.io MCP Top-20 (2026) |
| D6 | **Agent Data Injection** (delimiter forgery in trusted metadata: email sender, DOM id, prior tool-result) | delimiter-forgery contexts in `ai_prompt_injection.json` (per field type) + variants for `probe_cua_injection_surface` | The Hacker News, Jul 2026 |
| D7 | **HTTP/1.1 chunk-parse smuggling** (two-byte chunk-terminator overread; trailer-newline ambiguity) | `chunk_terminator_overread` + `trailer_newline_ambiguity` contexts in `request_smuggling.json`; ref-only, raw wire via `send_raw_request` | arXiv 2510.09952; Kettle "HTTP/1.1 must die" |
| D8 | **GraphQL-over-WS CSWSH** (cross-site WebSocket hijack reaches GraphQL, bypassing preflight-gated CSRF) | `graphql_over_ws_cswsh` context in `websocket.json`; link to `probe_graphql_csrf` | BH GraphQL / arXiv (2025-26) |
| D9 | **WAFFLED parser-differential WAF bypass** (multipart/body/header parser disagreement WAF↔origin) | `multipart_boundary_disagreement` + body-parser-split contexts in `waf_bypass_40x.json` / `parser_differential.json` | arXiv 2503.10846 |
| D10 | **Ivanti Sentry CVE-2026-10520** (pre-auth OS command injection, CVSS 10.0, CISA KEV, public PoC) | `sentry_handlemessage_cmdinj` context in `ivanti.json` + variant for `probe_cve_with_variants` | Rapid7 + SecurityWeek + THN, Jun 2026 |

## P2 — verify-first backlog

Reference-only, each gated on an authoritative advisory before a KB context is written: Ivanti Sentry CVE-2026-10523 (auth bypass, pairs with D10), CometJacking agentic-browser URL exfil, RAGPoison latent-trigger contexts, GitHub Actions cache→OIDC exfil, ORM-leak framework extension (Prisma/TypeORM/GORM), OAuth device-code QR-lure audit. Full list + sources in the research archive.

## Hallucination guard (HARD)

The technique research surfaced fabricated 2026 CVE IDs from AI-content-farm domains (examples flagged and excluded: an nginx "pre-auth RCE", "OpenClaw", a WordPress "wp2shell", an HTTP.sys and a Netlogon ID). **No KB context is authored around any CVE ID without a matching vendor advisory, NVD entry, or CISA KEV listing.** Only Next.js (Vercel-official) and Ivanti Sentry (Rapid7/SecurityWeek/THN corroborated) CVE numbers cleared this bar. P2 CVEs (ServiceNow, Splunk, "new CitrixBleed") stay reference-only until confirmed.

## Watch items (post-conference re-harvest)

BH USA 2026 + DEF CON 34 (Aug 5–9 2026) are abstracts-only as of this date — tracked, not intake: Kettle "Meet the HTTP Terminator"; "Trusted Enough to Run: Breaking AI Agents in Official Workflows"; "Bye Bye AI: Hacking the AI Shopping Assistant." Re-run the technique-refresh track after the conferences.

## Build surface summary

- **New probes (2):** `detect_mcp_invisible_unicode` (D1), redirect-chain OAST helper for D3 (extends existing OAST flow, may not need a top-level tool).
- **New KB sibling files (1):** `ssti_elixir.json` (D2).
- **Variant packs for `probe_cve_with_variants` (2):** Next.js middleware-bypass (D4), Ivanti Sentry (D10).
- **KB contexts merged into existing parents (~12):** across `mcp_tool_poisoning`, `ssti_*`, `ssrf_bypass`, `react_server_components`, `mcp_server_attacks`, `ai_prompt_injection`, `request_smuggling`, `websocket`, `waf_bypass_40x`/`parser_differential`, `ivanti`.
- **Advisor wiring:** route the two new probes in `pick_tool`; update KB count in CLAUDE.md + `_INDEX.md`.

## Testing

- `detect_mcp_invisible_unicode` — unit test: a known-poisoned tool-metadata fixture (TAG-block + zero-width) → CONFIRMED; clean fixture → FAILED. Real logic that can break.
- D2 error-oracle matchers — one fixture per engine class asserting the marker is extracted from the error body.
- D4 variant pack — assert the rsc/segment-prefetch and query-param variants are emitted and dispatch.
- Skip trivial KB-JSON-load wiring per project testing rules; add the KB-count assertion to the existing test that guards the file total.
