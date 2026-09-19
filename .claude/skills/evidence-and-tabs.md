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
| Find a request already captured (auth, login, target endpoint) | `search_history(query=...)` → `get_proxy_history(filter=...)` | Captured requests carry real cookies, CSRF tokens, browser headers. Curl recreations lose state. |
| Read a specific request/response by index | `get_request_detail(index)` (or `extract_regex/json_path/headers` for token efficiency) | Reading is cheap; re-sending wastes scope traffic. |
| Test ONE modification on a captured request | `resend_with_modification(index, modify_headers=..., modify_body=..., modify_path=..., modify_method=...)` | Single-call diff vs baseline. |
| Iterate on a captured request through Burp UI (fire + re-run from the MCP) | `send_to_repeater_tracked(index, tab_name="<f-id>-<vuln>")` → `repeater_resend(tab_name, modify_*)` | `_tracked` is required — plain `send_to_repeater` only DISPLAYS the tab (untracked), so `repeater_resend` can't fire it and it waits on a human. |
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

If after step 1 the query returns 0 hits AND the user expects a captured request → don't immediately curl. First retry with broader filters (drop method, drop path-suffix). Only after both miss should you create new traffic.

## Workflow B — "Modify and re-test a captured request"

```
1. send_to_repeater_tracked(index=N, tab_name="f001-sqli-login")   # _tracked = fireable
   → tab created + TRACKED (visible in Burp UI too). Plain send_to_repeater is UI-only.
2. repeater_resend(tab_name="f001-sqli-login",
       modify_body="username=admin&password=admin' OR 1=1--")       # this FIRES it
   → the call RETURNS the response — READ it (status + BODY vs baseline, Rule 13a).
3. Compare via get_response_diff(index_a=<original>, index_b=<repeater_result>)
4. If anomaly persists → annotate_request(<repeater_result_index>, color='RED', comment=...)
                       → send_to_organizer(<repeater_result_index>)
```

Iterate by calling `repeater_resend` again with the next variation; each call fires and
returns the response. The tab stays open; the user sees your iterations live. If a
`repeater_resend` result looks wrong (e.g. a 400 with an nginx/error-page body when the
same request works via `curl_request`), the send path — not the target — is the problem:
fall back to `curl_request` (it fires + parses + lands in Proxy history) and note it.

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
   OR iterate proxy history filtering by color via get_proxy_history
4. For each evidence index:
     get_request_detail(index, full_body=True)
     extract_headers(index, ['Set-Cookie', 'Location'])
5. Feed into format_finding_for_platform / generate_report
```

This is why **Workflow A's `annotate_request` + `send_to_organizer` step is mandatory** — without it, the only way to find evidence later is to re-search the entire proxy history, which is expensive.

## Workflow E — "Screenshot a PoC step by step (visual evidence)"

Capture like a real pentester building a report, **not** a full-window dump of whatever
tab happens to be open. One screenshot = one thing that advances the proof. Prepare the
view first so the shot SHOWS the evidence and nothing else.

**`burp_screenshot(tab=...)` switches the top-level Burp tab FOR you — you do NOT ask the
operator to click it.** Pass the tool name (`logger`, `organizer`, `repeater`, `proxy`,
`comparer`, `decoder`, `intruder`, ...) and the extension brings that tab to front before
capturing; the return's `selected_tab` confirms it. The discipline is still **isolate +
highlight the one request, then capture** — a shot of Proxy history with 400 unrelated rows
proves nothing — but the tab switch is automatic, not a hand-off.

Prepare the view (all tool-driven — no manual clicking):
```
1. Isolate the ONE request that proves the step:
     send_to_repeater_tracked(index=N, tab_name="f001-sqli-login")  # tracked = fireable +
                                                             # focuses a new Repeater sub-tab
   OR annotate + bookmark so it's the highlighted/selected row:
     annotate_request(index=N, color='RED', comment='f001 | sqli | pg_query error in body')
     send_to_organizer(index=N)                              # or curate_evidence(...) — one call
2. burp_screenshot(tab='repeater'|'organizer'|'logger', ...) brings that tool to front and
   captures — the isolated request (the just-focused Repeater sub-tab / the annotated row)
   is what's shown. NO operator step.
```
The only thing NOT tool-selectable is a SUB-tab *within* a tool (Proxy > HTTP-history vs
Intercept) — Montoya exposes no selector below the top strip. Everything at the top-tab
level is automatic; only ask the operator when you genuinely need a specific sub-tab shown.

**A SCREENSHOT IS NOT A TEST. Fire the request and READ the response body first (Rule 13a);
the verdict comes from the parsed response, not the image — the shot only corroborates.**
Never screenshot a staged-but-unsent request. Two send paths that actually fire AND return
the response to you:
- `curl_request(url, ...)` — fires, returns the full parsed response, and lands in Proxy
  history. The reliable one-call send+parse; use it as the default.
- `send_to_repeater_tracked(index, tab_name=)` → `repeater_resend(tab_name, modify_*)` —
  fires a TRACKED tab and returns the response for iteration. NOTE the plain
  `send_to_repeater` (untracked) only DISPLAYS the request in Burp's UI — `repeater_resend`
  cannot fire it, so it waits on a human to click Send; use `_tracked` when you need to fire.

Each PoC step = FIRE it, PARSE the response (grade on the BODY vs baseline — status line is
not a verdict), THEN capture with a caption of what the response proved:
```
# baseline — fire the clean request, read the response, then capture
r = curl_request('https://t/x?id=1', cookies=...)     # r.body: one row, 200
burp_screenshot(domain, tab='repeater', finding_id='f001', note='baseline id=1 -> one row')
# attack — fire the payload, read the response
r = curl_request('https://t/x?id=1%27+OR+%271%27%3D%271', cookies=...)  # URL-ENCODE payloads
burp_screenshot(domain, tab='repeater', finding_id='f001', note='inject id=1 OR 1=1')
# result — the response is the proof (error string / other-user data / executed marker)
#   r.body shows "mysqli_sql_exception ... SELECT first_na..." => payload reached the SQL sink
burp_screenshot(domain, tab='repeater', finding_id='f001', note='mysqli error confirms SQLi at sink')
```
URL-encode payloads in a path/query (a raw space or quote makes an invalid request line —
nginx 400s it before the app, which is INCONCLUSIVE, not a negative: Rule 13b).

Each shot lands under `.burp-intel/<domain>/screenshots/` with a self-describing name
(`burp-<tab>-<finding_id>-<note-slug>-<ts>.png`) and, with `finding_id=`, is attached to
`evidence.screenshots[]` — so it renders IN ORDER in `generate_report` (client sees the
filename + caption, no internal path) and is copied into `export_poc_bundle`. Standalone
capture with no finding: omit `finding_id`, then `attach_screenshot(domain, fid, path, note)`
later. Verify the gallery with `screenshot_gallery(domain)`.

Banner (OPT-IN — ask first):
- `note`/`step` always go in the filename and the report caption; they do NOT draw on the
  image. An on-image caption is opt-in via `banner=True`, and it renders as a FOOTER strip
  appended below the shot (nothing is covered — like a phone-screenshot caption), with the
  step/caption left and an optional `trademark=` on the right.
- **Ask the operator before turning the banner on**, and whether they want a trademark/brand
  on it. Do not stamp a banner (or a brand) unprompted. Default is a clean, unbannered shot.

Rules:
- **One step per shot.** Baseline → attack → result is three shots, not one busy window.
- **Highlight before you shoot** (annotate colour + comment, or a named Repeater tab) so the
  reader's eye lands on the proof.
- **Caption every shot** (`note=`) — it becomes the filename slug AND the report caption.
- **Don't shoot noise.** No full HTTP-history dumps, no unrelated tabs, no other apps in
  front (printAll captures Burp regardless of z-order, but a wrong TAB is still wrong).
- **No secrets in frame.** If a real credential/token/PII is visible in the panel and it
  isn't the point of the finding, scroll it out or capture the isolated Repeater tab, not
  the whole session.

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

## Keep the .burp project lean (capture-time, not deletion)

Burp history is read-only to the extension — it cannot be pruned programmatically.
Control bloat at capture and curate what matters:
- **Scope first.** `configure_scope` tightly before crawling; out-of-scope traffic
  you never capture is the only traffic you never store.
- **Volume off-proxy.** Fuzz/brute/rate/race via `fuzz_parameter` /
  `send_to_intruder_configured` / `concurrent_requests` / `test_race_condition`,
  not repeated proxied `curl_request` — keeps thousands of variants out of history.
- **Curate evidence in one call.** On a confirmed finding:
  `curate_evidence(finding_id, index, domain, color='RED')` — annotates + sends to
  Organizer + records the canonical evidence index (Rule 18) in one step.
- **Audit before reporting.** `audit_history_noise(domain)` reports static/dup/
  out-of-scope composition and what to tighten next time.
