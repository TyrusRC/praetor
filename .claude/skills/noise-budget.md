---
name: noise-budget
description: Cut wasted token spend without skipping real bugs. Distinguish IMPOSSIBLE work (tech-mismatch CVEs, encoded reflections, WAF rebuffs) from EXPENSIVE-BUT-REAL coverage (framework-wide patterns, race conditions, deep auth matrices) — skip the first, fully cover the second. Use this when an anomaly looks borderline OR when deciding whether to keep probing a category that hasn't paid off yet.
---

# Noise Budget — Skip Impossible Work, NEVER Skip Real Coverage

The goal is **coverage, not speed**. This tool exists so the hunter doesn't miss real bugs. Tokens are spent freely on anything that could be a real finding — even if expensive. What gets cut is work that is *impossible by construction* (wrong tech stack, encoding-defeated, out of scope) and work that is *demonstrably noise* (3/3 verification fails, knowledge-base cleared by adaptive matchers).

## The Two Lists

| SKIP — Impossible / Wrong Surface | COVER — Expensive but Real |
|---|---|
| PHP-specific CVE on a Laravel/Node/Java site | React `dangerouslySetInnerHTML` reaches across an entire SPA — test every page that renders user data |
| WordPress plugin RCE on a non-WordPress target | Prototype pollution on a Node/Express stack — every endpoint that merges user JSON |
| Windows-style LFI (`C:\boot.ini`) on a Linux container | JWT algorithm confusion / `alg:none` — every endpoint that consumes a token |
| `.NET ViewState` deserialization on a Python app | Java deserialization gadgets — every endpoint that accepts serialized objects |
| `phpinfo` enumeration on Go/Rust services | Mass assignment — every PUT/PATCH/POST that updates a user-owned record |
| ASP.NET-specific `__VIEWSTATE` on Spring Boot | IDOR matrix — every authenticated endpoint, both auth states |
| `wp-config.php` discovery on a Rails app | Race conditions on state-changing endpoints (coupon, balance, vote, ticket) |
| Probes whose payload syntax doesn't parse on the detected DB engine (Oracle-only on MySQL) | SSRF Collaborator probes — every endpoint accepting a URL/host/IP |
| Tech-mismatch nuclei templates flagged by `match_tech_stack` | CSRF on every state-changing endpoint, with method-override variants |
| Probes against an endpoint that 410-Gone or 404 with no body delta on baseline | Open redirect chained with token-theft — every redirect-style param |

**The split rule:** if the vuln class can possibly exist given the detected tech stack and parameter shape, it gets full coverage even when individual probes are expensive. If the vuln class *cannot* exist (wrong runtime, wrong DB, wrong framework), it is removed from the plan entirely.

## Pre-Probe: Eliminate the Impossible

Before you spend a token on any payload:

1. **Know the stack.** `detect_tech_stack(index)` or read `load_target_intel(domain, "profile")`. Without a stack, you cannot distinguish impossible from expensive.
2. **Drop incompatible CVE/probe categories.** `match_tech_stack` already does this — trust it. Don't re-test PHP CVEs on a Laravel site by hand.
3. **Translate, don't drop.** A vuln class that LOOKS framework-specific often translates: SQLi works on every SQL backend with the right syntax; SSRF works regardless of language; mass assignment exists in every framework that auto-binds JSON. Translate the payload to the detected stack, don't skip the class.

## Framework-Wide Patterns — Mandatory Full Coverage

When the detected tech stack implies a class of bug, every applicable surface MUST be tested. Examples:

- **React detected:** every component path that renders server-supplied content → DOM XSS via `dangerouslySetInnerHTML`, `innerHTML`, JSX expression injection. Use `analyze_dom` to enumerate sinks; loop over every page.
- **Node/Express detected:** every JSON merge, every spread, every `Object.assign` from request body → prototype pollution. Test every endpoint that accepts a body.
- **Spring Boot / Java detected:** every endpoint accepting serialized objects or XML → deserialization + XXE. Probe every binary/XML-accepting endpoint.
- **GraphQL detected:** introspection + every mutation argument → injection, batching abuse, alias overload.
- **JWT in Authorization header:** `alg:none`, weak HMAC secret, RS→HS confusion, kid path traversal → test every token-bearing endpoint.
- **Multi-role auth (admin/user/guest):** test_auth_matrix on every authenticated endpoint, both directions.

Spending tokens on a complete sweep here is correct. Stopping early because "we already found one" misses 80% of the real bugs.

## Probing Exhaustion — Reasoning, Not Counting

Drop the old "10 probes then quit" heuristic. Use these signals instead, in order:

| Signal | Action |
|---|---|
| `auto_probe` knowledge-base matchers cleared on the priority categories AND tech stack matches the matchers' runtime | Class is genuinely unlikely for the framework — move to next class. Spot-check 1 handcrafted variant only if the param name strongly suggests it (`?cmd=`, `?file=`, `?next=`). |
| Same payload reflected encoded across 3+ probes (same WAF, same encoder) | DON'T abandon the class — switch technique: `craft-payload.md` for encoding bypass, transformation chains, alternative injection points (header/cookie/path/Content-Type), or a different vuln class that the WAF doesn't filter. |
| 2+ consecutive 403/406/429 from a WAF | Slow down (`delay_ms`), rotate session/origin, OR change technique. Do NOT skip the class — the WAF presence often signals the dev considered this attack class worth blocking, which is a tell. |
| Same response hash for clean and probe inputs | Cache, debug fence, or read-only endpoint. Move to a different endpoint, not a different class. |
| 3/3 replays produce inconsistent timing (variance > 30% of median) | Timing claim is jitter, not the bug. Do NOT save. Continue to other categories. |
| Probe sequence on the SAME (endpoint, parameter, vuln class) exceeds ~30 probes with c<0.30 across the board | Document the negative result in `coverage.json` and pivot. The result IS coverage — log it so the next session doesn't redo it. |

## Effort-Justified Categories — Spend the Budget

These vuln classes cost a lot of tokens AND a lot of requests, but they are the highest-paying bugs in real bounty programs. Never skip these for budget reasons:

- **Race conditions** (10–50 concurrent requests via `test_race_condition`) — coupon/balance/vote/role-grant
- **IDOR auth matrix** (every endpoint × every auth state via `test_auth_matrix`)
- **Deserialization** (gadget chain probes per endpoint accepting serialized data)
- **Request smuggling** (CL.TE / TE.CL / TE.TE per upstream/CDN combination)
- **Cache poisoning** (header injection per cache-key permutation)
- **Mass assignment** (every writable field, every privilege param, every PUT/PATCH)
- **Business logic chains** (multi-step flows via `run_flow` — replay, manipulate intermediate state)

If your hunt session hasn't touched these, it isn't done. Token spend here is correct; pretending the budget is spent on these is the actual waste.

## Suspicion Verification — Cap Per Suspicion, Not Per Class

Different from class budgets — once a SPECIFIC suspicion is on the table:

- **Reproducibility:** 3 replays via `resend_with_modification`. Inconsistent (< 3/3) → noise. STOP that suspicion (not the class).
- **Timing/blind:** 3 replays — record `elapsed_ms` each. Variance > 30% of median → jitter. STOP that suspicion.
- **Boolean blind:** 2 payloads (TRUE/FALSE variant). No stable delta → STOP that suspicion.

A failed suspicion does NOT close the vuln class. Keep testing other params/endpoints in the same class.

## What Gets Logged Even on a Negative

Every category swept — even if 0 findings — should write to `coverage.json` via `save_target_intel(domain, "coverage", {...})`. This is what stops the next session from redoing 30 probes you already ran. A negative result IS coverage; only silently stopping is waste.

## What This Skill Does NOT Authorize

- Skipping JWT testing because "the site has React" — JWT is endpoint-side, framework-agnostic
- Skipping mass assignment because "we found XSS already" — different class, different payout
- Skipping deserialization because "it might take 100 probes" — that's exactly the time it takes for a real critical
- Skipping CVE matches because "the version isn't disclosed" — the CVE may apply by behavior, not by banner
- Stopping at the first finding in a class — full sweep first, save findings, then move on

## Cross-references

- **What to do when a strong suspicion fails:** `verify-finding.md` Step 0 / Step 1
- **What to do when payloads are filtered:** `craft-payload.md`
- **Where to pivot:** `get_next_action(target_url, completed_phases, findings_count, tech_stack)`
- **Tech-stack CVE filter:** `match_tech_stack` — drops incompatible CVEs automatically
- **Hard rules behind these limits:** `.claude/rules/hunting.md` Rules 14, 17, 25, 26, 27, 28
