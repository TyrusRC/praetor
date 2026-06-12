---
description: Smart move when you captured a request/response and something looks off — single call collapses the 5-step LLM triage loop. Use when reviewing proxy history and an entry stands out.
globs:
---

# Smart Move — Captured Something Weird

Trigger: a captured proxy/logger entry has unusual status / body / header / timing
and you're about to chain `get_request_detail` → `extract_*` → `smart_analyze` →
reason → pick next tool. Don't. Use the synthesiser.

## The move — 1 call → fire-ready plan

```
plan = smart_request_triage(index=<N>)
```

Read `plan["attack_plan"][0]` only. Dispatch its `suggested_call` line.
Skip every other intermediate analysis call.

## Routing matrix (what triage will return)

| Trigger in entry | Plan[0] routes to |
|---|---|
| Error marker (pg_query / SQLSTATE / ORA / jinja2 / freemarker / uid=N(...)) | `confirm_sqli` / `confirm_ssti` / `confirm_rce` |
| `text/x-component` response | `probe_cve_with_variants(cve='CVE-2025-55182', ...)` |
| `application/javascript` or `.js` URL | `smart_js_analyze(index=N)` |
| GraphQL response shape | `test_graphql(test_introspection=True, test_batching=True)` |
| XML body (POST/PUT/PATCH) | `test_xxe` |
| `text/html` + form tags | `test_csrf` + `test_dom_sinks` |
| Status 401/403 | `test_auth_matrix` (+ `probe_kerberos_spnego_auth` if Negotiate) |
| 3xx + redirect-named param (url/next/return/callback/...) | `test_open_redirect` |
| JSON API + Authorization header | `test_auth_matrix` + `auto_probe` |
| Debug/version headers, secrets, stack-trace alone | `annotate_request` (NEVER_SUBMIT alone — Rule 17 chain candidate) |

## Stop conditions

- Plan empty (`attack_plan == []`) → entry is genuinely uninteresting; `annotate_request(index, color='GRAY')` and move on.
- Plan[0] = `annotate_request` + NEVER_SUBMIT chain candidate → save_finding with `chain_with=[]` placeholder per Rule 17.
- Plan[0] confirms a finding (CONFIRMED verdict) → `assess_finding` → `save_finding` per Rule 10.

## Rule references

- Rule 10 (save-finding pipeline) — confirm verdict before save.
- Rule 18 (annotate + organize) — every interesting entry gets color + comment.
- Rule 22 (one smart call > five chatty) — this skill IS the principle.
- Rule 23 (captured-first evidence) — triage reads existing index, doesn't refetch.

## Anti-pattern

Don't call `get_request_detail(full_body=True)` + `smart_analyze` + manual reasoning.
That's the 5-step loop the triage tool collapsed. One call does the routing.
