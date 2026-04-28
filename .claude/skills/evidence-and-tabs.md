---
name: evidence-and-tabs
description: How a real pentester uses Burp's surfaces — Proxy history search, Repeater tabs, Intruder, Organizer, annotations. Use whenever you need to (a) find evidence already captured, (b) iterate on a captured request, (c) brute/spam/rate-test, (d) bookmark for the report. Replaces the "default to curl" anti-pattern.
---

# Evidence Hunting + Tab Management

The MCP gives you the same surfaces a real Burp operator uses. Pick by INTENT, not by familiarity.

**This skill is about EVIDENCE retrieval and Burp-tab discipline — it is NOT a restriction on creating fresh requests.** Generating new traffic is the correct move when the test itself requires it (fuzz / brute-force / rate-limit / spam / race / business-flow / WAF probing / first-touch endpoints / controlled variation). See "When fresh requests ARE the right call" below.

## Decision Map

| Intent | Tool | Why this and not curl |
|---|---|---|
| Find a request already captured (auth, login, target endpoint) | `search_history(query=...)` → `get_proxy_history(filter=...)` → `get_logger_entries(filter_url=...)` | Captured requests carry real cookies, CSRF tokens, browser headers. Curl recreations lose state. |
| Read a specific request/response by index | `get_request_detail(index)` (or `extract_regex/json_path/headers` for token efficiency) | Reading is cheap; re-sending wastes scope traffic. |
| Test ONE modification on a captured request | `resend_with_modification(index, modify_headers=..., modify_body=..., modify_path=..., modify_method=...)` | Single-call diff vs baseline. |
| Iterate on a captured request through Burp UI (manual tweaks, re-runs) | `send_to_repeater(index, tab_name="<f-id> <vuln>")` → `repeater_resend(tab_name, modifications)` | Tracked tabs survive across calls; user can also hand-tweak in Burp UI. |
| Brute force, rate-limit absence, spam, header/param sweep, value enumeration | `send_to_intruder_configured(index, mode='auto', payload_lists=[...], attack_type=..., tab_name=...)` | Burp's native attack engine — proper position handling, mark/grep, exposes results table. |
| Race condition (concurrent identical/near-identical requests) | `test_race_condition(session, request, concurrent=10)` | Server-side CountDownLatch; `Intruder` is sequential. |
| Same payload list across N parameters or N endpoints | `fuzz_parameter(index, parameters=[...], attack_type='cluster_bomb')` | MCP-side, no UI overhead, anomaly detection on responses. |
| Genuinely fresh first-touch request (endpoint never visited yet) | `get_target_headers(domain)` → `curl_request(url, method, headers=<that dict>, ...)` (or `session_request(...)`) | Curl is the LAST resort. When you must use it, ALWAYS layer the real-client header profile on top — default httpx headers trip WAFs (Rule 32). |

If the captured request exists AND the goal is to retrieve / replay it, **start at row 1 of this table**. If the goal is to author NEW traffic (fuzz, brute, race, business flow, WAF probe), see the next section.

## When fresh requests ARE the right call

Generating fresh requests via `curl_request` / `send_raw_request` / `session_request` / direct loops is the correct first pick — not a fallback — for any of these:

| Goal | Approach |
|---|---|
| Fuzz a known-bad pattern across many payloads with branching/decoding logic Intruder can't express | Loop with `curl_request` / `session_request`. Use `auto_probe` or `fuzz_parameter` first only if their model fits the test. |
| Brute-force tested creds with custom logic (rotate UA per attempt, vary referer, decode JWT response per try, branch on response shape) | Hand-rolled loop with `curl_request`. Intruder is fine for flat lists; switch to a loop when you need conditional logic. |
| Rate-limit probing — fire N concurrent or back-to-back requests, measure when 429/Retry-After kicks in | `asyncio.gather([curl_request(...) for _ in range(N)])` or repeated `session_request`. Record timestamps + status codes; that IS the test. |
| Race conditions on a state-changer | `test_race_condition(session, request, concurrent=10)` (uses server-side CountDownLatch — better than client-side concurrency). |
| Multi-step business-logic flow that branches on intermediate state (e.g. "if step 2 returns A, do path X; else path Y") | Either `run_flow(...)` for linear flows, or explicit `session_request` chains with Python-side branching. |
| Test how the server reacts to bare/non-browser/malformed clients (WAF detection, fingerprint probes, smuggling, CRLF, host-header) | Bare `curl_request` or `send_raw_request` with hand-crafted headers. Do NOT auto-merge `get_target_headers` here — the point is to NOT look like a browser. |
| First-touch on a discovered endpoint that nobody has visited yet | `curl_request` (or `session_request` if auth required). Apply `get_target_headers(domain)` to look real, unless point is otherwise. |
| Controlled variation that doesn't match anything captured (custom payload + custom Content-Type + custom body shape) | Build it directly with `curl_request` / `send_raw_request`. |

The decision is: **am I retrieving evidence (use captured-first) or am I authoring traffic (use whatever tool fits the test)?** Both modes are first-class.

## Header Profile (real client mimicry — Rule 32)

When fresh `curl_request` is genuinely needed, default httpx headers (`User-Agent: python-httpx/...`, no `Sec-Fetch-*`, no `Sec-CH-UA`, no `Accept-Language`, no `Referer`) get blocked by every modern WAF and skew test coverage. Build a header profile once per target, reuse forever:

```
1. browser_crawl(target, max_pages=20)         # populates proxy history with real browser traffic
2. build_target_header_profile(domain)         # picks the most browser-like captured request,
                                               # strips Cookie/Authorization/Host/Content-Length,
                                               # saves to .burp-intel/<domain>/profile.json

3. # before every fresh curl_request:
   headers = get_target_headers(domain)        # returns JSON {domain, source_index, headers}
   curl_request(url, method='GET', headers=headers["headers"], ...)
```

`build_target_header_profile` scores candidate requests by browser-fingerprint signal (real-browser UA, Sec-Fetch-*, Sec-CH-UA, Accept-Language, Referer) and rejects bot/scanner UAs (curl/, python-httpx, nuclei, ffuf, sqlmap, etc.). It also strips session-specific headers (Cookie, Authorization) so layering session auth on top remains explicit.

Rebuild only when the target rotates its expected client signature (rare). `force=True` forces a rebuild.

## Workflow A — "Find evidence for finding X"

```
1. search_history(query="<endpoint>", filter_method="POST")
   → returns indices N, M, K
2. get_request_detail(index=N) OR extract_regex(index=N, '<proof_pattern>', group=1)
3. annotate_request(index=N, color='RED', comment='f001 | sqli | error pg_query in body')
4. send_to_organizer(index=N)
   → bookmarks for the report
```

If after step 1 the query returns 0 hits AND the user expects a captured request → don't immediately curl. First retry with broader filters (drop method, drop path-suffix). Then check `get_logger_entries`. Only after both miss should you create new traffic.

## Workflow B — "Modify and re-test a captured request"

```
1. send_to_repeater(index=N, tab_name="f001-sqli-login")
   → tab created, visible in Burp UI for the user too
2. repeater_resend(tab_name="f001-sqli-login", modifications={
       "body": "username=admin&password=admin' OR 1=1--",
   })
3. Compare via get_response_diff(index_a=<original>, index_b=<repeater_result>)
4. If anomaly persists → annotate_request(<repeater_result_index>, color='RED', comment=...)
                       → send_to_organizer(<repeater_result_index>)
```

Iterate by calling `repeater_resend` again with the next variation. The tab stays open; the user sees your iterations live.

## Workflow C — "Brute / rate-limit / spam test"

```
1. send_to_intruder_configured(
     index=N,
     mode='auto',                     # auto-detect injection points
     # OR explicit positions=[[start,end], ...]
     payload_lists=[
       ["admin", "test", "guest", "user", "demo"]   # tested-creds list
     ],
     attack_type='sniper',            # one position at a time
     tab_name='f002-creds-test'
   )
2. Wait for results (Intruder runs in Burp; poll get_intruder_results if available)
3. Look for status-code or length anomalies that indicate auth bypass / leakage
4. annotate_request(<winning index>, color='RED', comment='f002 | auth_bypass | admin/admin works')
5. send_to_organizer(<winning index>)
```

For rate-limit testing, use `attack_type='battering_ram'` with 100 copies of the same payload, time-boxed. For header injection sweeps (Host header, X-Forwarded-For), `attack_type='sniper'` on the header position.

## Workflow D — "Recover evidence later (e.g., for the report)"

```
1. get_organizer_entries()                          # list bookmarked req/resp pairs
2. get_repeater_tabs()                              # list all named Repeater tabs
3. search_history(query="annotation:RED")            # if annotation filter supported
   OR iterate proxy history filtering by color via get_logger_entries
4. For each evidence index:
     get_request_detail(index, full_body=True)
     extract_headers(index, ['Set-Cookie', 'Location'])
5. Feed into format_finding_for_platform / generate_report
```

This is why **Workflow A's `annotate_request` + `send_to_organizer` step is mandatory** — without it, the only way to find evidence later is to re-search the entire proxy history, which is expensive.

## Naming Conventions (use these consistently)

- **Repeater tab name:** `<finding-id>-<vuln-class>` (e.g. `f003-ssrf-image-fetch`)
- **Intruder tab name:** `<finding-id>-<attack-type>` (e.g. `f002-creds-bruteforce`)
- **Annotation comment:** `<finding-id> | <vuln_class> | <one-line evidence summary>`
- **Color convention:**
  - `RED` confirmed critical/high
  - `ORANGE` strong suspicion (assess_finding said REPORT but evidence still being gathered)
  - `YELLOW` anomaly worth investigating
  - `GREEN` baseline or verified pass (used to anchor delta claims)
  - `CYAN` chain candidate (informative-alone but escalates)
  - `GRAY` noise — pre-filtered out

`save_finding` reads `confidence` and the proxy auto-highlight already mirrors these bands; consistency makes triage and reporting trivial.

## Anti-patterns

- Sending a fresh `curl_request` to recreate the login flow when proxy history already has it
- Calling `fuzz_parameter` for a 3-payload sweep that Repeater + 3 `repeater_resend` calls would handle more clearly (and visibly to the user)
- Brute-forcing tested creds with hand-rolled `curl_request` loops instead of `send_to_intruder_configured`
- Calling `save_finding` without first `annotate_request` + `send_to_organizer` on the evidence indices — the report will then have to re-search history at report time
- Leaving Repeater tabs unnamed (default tab names like "Tab 1") — when the user opens Burp later they can't tell what's what

## Cross-references

- **Search-before-send rule:** `.claude/rules/hunting.md` Rule 29
- **Right-Burp-surface rule:** `.claude/rules/hunting.md` Rule 30
- **Annotate-and-organize rule:** `.claude/rules/hunting.md` Rule 31
- **Header / parameter / pollution / smuggling probes:** still use `test_*` or `auto_probe` — those wrap the right Burp surface internally
- **Tool selection cheatsheet:** `pick_tool('<task>')`
