---
description: Smart move when you've found a JS bundle/chunk and need to extract attack surface — single call synthesises priority-ordered attack plan. Use when proxy history or recon shows any .js asset.
globs:
---

# Smart Move — Found a JS Bundle

Trigger: any `.js` / chunk / webpack / Next.js `/_next/static/chunks/` asset
appeared in proxy history or recon. Don't manually call
`extract_js_secrets` + `extract_api_endpoints` + `extract_regex` + reason.

## The move — 1 call → fire-ready plan

```
plan = smart_js_analyze(index=<N>)              # captured entry
plan = smart_js_analyze(url='https://app/.../main.js')   # fresh fetch
plan = smart_js_analyze(urls=['url1','url2',...])         # batch ≤25
```

Dispatch the top N `suggested_call` lines in `plan["attack_plan"][:5]`
directly. Each line is a complete tool call already.

## Priority matrix (what synthesis returns)

| P | Trigger in bundle | Plan entry routes to |
|---|---|---|
| 0 | RSC Server Action IDs (`createServerReference("...")` / `$ACTION_ID_*`) | `probe_cve_with_variants(cve='CVE-2025-55182', action_id=...)` |
| 1 | GraphQL endpoint | `test_graphql(test_introspection=True)` |
| 1 | `new WebSocket(...)` | `test_websocket(url=...)` |
| 2 | DOM XSS sink (innerHTML / dangerouslySetInnerHTML / eval / 11 sinks) | `test_dom_sinks(focus_sink=...)` |
| 2 | `addEventListener("message", ...)` | `probe_postmessage_listeners(target_url=...)` |
| 3 | Endpoint (filtered against static asset prefixes) | `auto_probe(url=...)` |
| 4 | Secret in bundle (AWS/Google/Stripe/GitHub/JWT/PEM/OpenAI/Anthropic) | `save_finding(NEVER_SUBMIT, chain_with=[])` per Rule 17 |
| 4 | `sourceMappingURL` | `curl_request(<.map URL>)` — reconstruct dev paths |

## Stop conditions

- Plan empty → bundle is purely framework runtime, no attack surface harvested.
- P0 RSC action ID found → chain DIRECTLY into `probe_cve_with_variants`.
- P4 secret in bundle → never report alone (Rule 17); save with `chain_with=[]` placeholder for later.

## Batch mode

When recon dumps 20+ chunks:

```
plan = smart_js_analyze(urls=[...up to 25...])
```

Synthesis dedups across all bundles. Operator dispatches the top 5
suggested_call lines — covers the whole bundle set at once.

## Rule references

- Rule 17 (NEVER_SUBMIT chain) — secrets in JS bundles are not standalone reports.
- Rule 22 (one smart call > five chatty) — this IS the principle.
- Rule 23 (captured-first) — `index=N` mode reads existing proxy entry.
- Rule 27 (creative hunting) — synthesis P0/P1 chains uncover the high-impact path.

## Anti-pattern

Don't loop `extract_js_secrets` + `extract_api_endpoints` per file when
batch mode does it in one synthesis pass. Don't manually reason about
"which class to test next" — synthesis already priority-ordered it.
