---
name: static-dynamic-analysis
description: Deep static file analysis and dynamic behavioral analysis — JS source review, response behavior profiling, page change detection, and state-dependent vulnerability discovery
---

# Static & Dynamic Analysis

You have powerful analysis primitives. This skill teaches you to COMBINE them: static analysis reveals what the application CAN do, dynamic analysis reveals what it ACTUALLY does, and behavioral differentials reveal what it is HIDING.

## When to Use This Skill

- After recon, to deeply analyze JavaScript before testing
- When you suspect state-dependent behavior (different responses based on cookies, roles, timing)
- When pages change between visits (dynamic content, A/B testing, session-dependent rendering)
- When you want to find DOM XSS by tracing source-to-sink flows
- When you want to profile the application's behavioral patterns

---

## Part 1: Static JavaScript Analysis Pipeline

JavaScript files are the application's source code served to you for free.

### Step 1: Inventory all JS files

```python
get_static_resources(url_prefix="https://target.com", resource_type="js")
# If few results, auto-fetch everything from the page:
fetch_page_resources(index=ROOT_PAGE_INDEX)
```

### Step 2: Scan for secrets (high-value, low-effort)

For each JS file: `extract_js_secrets(index=JS_FILE_INDEX)`

**Priority by severity:**
- CRITICAL: Cloud credentials (AWS/GCP/Azure), DB connection strings
- HIGH: API keys (Stripe, Twilio, SendGrid), JWT signing secrets
- MEDIUM: Internal URLs, staging environments, hardcoded passwords
- LOW: Debug flags, feature toggles, developer comments

**Cross-file hunting:**
```python
search_history(query="apiKey", in_response_body=True)
search_history(query="secret", in_response_body=True)
search_history(query="config", in_response_body=True)
```

### Step 3: DOM sink/source analysis

```python
analyze_dom(index=PAGE_INDEX)
```

DOM XSS requires: **user-controllable SOURCE** flows into **dangerous SINK**.

**Sources** (user controls these):
| Source | Attack vector |
|---|---|
| `location.hash` | URL fragment: `https://target.com/#PAYLOAD` |
| `location.search` | Query: `https://target.com/?q=PAYLOAD` |
| `document.referrer` | Link from attacker page |
| `window.name` | Set by `window.open('target', 'PAYLOAD')` |
| `postMessage` | Cross-origin message from attacker iframe |
| `localStorage/sessionStorage` | If attacker can write via XSS |

**Sinks** (these execute/render unsafely):
| Sink | Risk | Result |
|---|---|---|
| `innerHTML` / `outerHTML` | HIGH | HTML tags execute |
| `setTimeout(string)` / `setInterval(string)` | HIGH | String runs as JS |
| `location =` / `location.href =` | MEDIUM | Navigate to javascript: URL |
| `element.src =` | MEDIUM | Load attacker resource |
| jQuery `.html()` / `.append()` | HIGH | HTML parsing |
| Framework unsafe bindings (v-html, [innerHTML]) | HIGH | Bypass framework escaping |

### Step 4: Trace source-to-sink manually

When analyze_dom reports both sources and sinks:
```python
get_request_detail(index=JS_FILE_INDEX, full_body=True)
```

**Tracing checklist:**
1. Find where SOURCE value is read
2. Trace transformations (sanitization? encoding? validation?)
3. Find where it reaches SINK
4. Check sanitization: DOMPurify = generally safe; custom regex = likely bypassable; none = DOM XSS

**Test confirmed flows:**
```python
# For hash source + innerHTML sink:
session_request(session, "GET", "/page#<img src=x onerror=alert(document.domain)>")
```

### Step 5: Discover hidden functionality

```python
extract_api_endpoints(index=JS_FILE_INDEX)
search_history(query="admin", in_response_body=True)
search_history(query="debug", in_response_body=True)
search_history(query="/api/v2", in_response_body=True)
```

**Patterns revealing hidden features:**
- `if (user.role === 'admin')` — admin-only UI paths
- `if (config.debug)` — debug mode
- `// TODO:` / `// FIXME:` — weak spots
- `fetch('/api/v2/...')` — undocumented API versions
- `feature_flags` — unreleased features
- `staging.target.com` — internal environments
- Commented-out code — removed features that may still work server-side

---

## Part 2: Dynamic Behavioral Analysis

### Behavioral Profiling

```python
# Profile response consistency: same request 3 times
r1 = session_request(session, "GET", "/api/users")
r2 = session_request(session, "GET", "/api/users")
r3 = session_request(session, "GET", "/api/users")
# Inconsistency = dynamic content (timestamps, CSRF, ads)
```

### Auth-State Differential (most powerful technique)

**Same endpoint, different auth context:**
```python
test_auth_matrix(
    endpoints=[
        {"method": "GET", "path": "/dashboard"},
        {"method": "GET", "path": "/api/profile"},
        {"method": "GET", "path": "/admin"},
    ],
    auth_states={
        "admin": {"session": "admin_session"},
        "user": {"session": "user_session"},
        "anon": {"remove_auth": True},
    }
)
```

| Observation | Meaning | Action |
|---|---|---|
| Same response admin vs user | IDOR / broken access control | Verify immediately |
| Different content, same status | Proper auth — check shared elements for leaks | Review JS, errors |
| Admin page 200 for anon | Critical auth bypass | Document now |
| 403 anon, 200 user | Auth works — test user-to-user IDOR | Different user IDs |

### Parameter-State Differential

```python
fuzz_parameter(index, parameter="id",
    payloads=["1", "2", "0", "-1", "999999", "null", "undefined"],
    grep_match=["email", "phone", "address", "admin", "password"])
```

- Different user data per ID = IDOR
- Error message changes = info disclosure
- Redirect changes = access control logic
- Hidden fields appear/disappear = role-based rendering

### Page Change Detection

```python
# Fingerprint at session start
save_target_intel(domain, "fingerprint", {"pages": [
    {"path": "/", "response_hash": "sha256:...", "response_length": 12345, "status": 200},
    {"path": "/login", "response_hash": "...", "response_length": 5678, "status": 200},
]})

# Later, check what changed
check_target_freshness(domain, session)
```

**Signal vs noise:**
| Change | Signal | Noise |
|---|---|---|
| New HTML elements | New attack surface | Ad rotation |
| New JS files | New code to analyze | CDN version bump |
| Length +/- 5% | Minor dynamic | Timestamps, CSRF |
| Length +/- 20% | Significant change | Usually meaningful |
| Status change | Major behavior change | Always meaningful |

### Action-Triggered Changes

```python
# What changes after login?
before = session_request(session, "GET", "/dashboard")  # unauthenticated
run_flow(session, steps=[login_steps...])
after = session_request(session, "GET", "/dashboard")   # authenticated
compare_responses(before_index, after_index)
# Look for: new endpoints, admin links, hidden forms, different JS loaded
```

---

## Part 3: Behavioral Anomaly Classification

| Type | Indicator | Likely Cause | Action |
|---|---|---|---|
| Status anomaly | 200->500 on injection | Injection point | Check error body for SQL/stack trace |
| Length increase | Response much longer | Data leak, UNION success | compare_responses to see diff |
| Length decrease | Response shorter | Content filtered, blind false | Check if data disappeared |
| Timing spike | >3x baseline time | Blind injection (SLEEP) | Test 3x with, 3x without payload |
| Content diff | Same length, different content | Boolean-blind, IDOR | Compare specific content elements |
| Header change | New/missing headers | CRLF injection, code path change | Check for injected headers |
| Redirect change | Different Location header | Open redirect, auth bypass | Check Location, test Collaborator |

**Decision flow:**
- Score >= 50: likely real, quick verify then confirm
- Score 30-49: suspicious, run full investigation (see investigate skill)
- Score < 30: probably noise, max 5 tool calls then move on
- Collaborator interaction: always real, document immediately

---

## Part 4: Cross-Analysis Workflows

### Workflow 1: JS Secrets -> Verified Access
Static: find API key -> Dynamic: test the key -> Assess permissions -> Rate severity

### Workflow 2: DOM Sinks -> Exploitable XSS
Static: find sink+source -> Read JS to confirm flow -> Dynamic: inject via source -> Verify execution

### Workflow 3: Hidden Endpoints -> Auth Bypass
Static: find /api/v2/admin in JS -> Dynamic: test unauthenticated -> Dynamic: test low-priv user

### Workflow 4: Page Change -> New Attack Surface
Dynamic: freshness check shows change -> Re-crawl -> Diff endpoints -> Analyze new ones -> Probe

### Workflow 5: Behavioral Profile -> Logic Bugs
Dynamic: profile with different values -> Static: check JS validation -> Dynamic: bypass validation directly

### Workflow 6: Multi-Page State Analysis
Dynamic: map checkout flow -> Test: skip steps, replay, modify values -> Test: race condition on coupons

---

## Part 5: Agent Dispatch for Analysis

**Dispatch js-analyst (background):**
> Analyze all JS files for {domain}. Session: {session}.
> For each: extract_js_secrets + analyze_dom.
> Search history for "apiKey", "secret", "config", "admin" in response bodies.
> Return: secrets, DOM XSS flows, hidden endpoints.

**Dispatch recon-agent (background):**
> Profile behavioral patterns for {domain}. Session: {session}.
> Test consistency (3 identical requests). Test auth differential.
> Return: behavioral profile, IDOR candidates.

**Orchestrator (foreground):**
> Merge results. Verify secrets immediately. Test top DOM XSS flows. Deep-dive IDOR candidates.

---

## Quick Reference: Tool Selection

| I want to... | Use |
|---|---|
| List all JS files | `get_static_resources(resource_type="js")` |
| Fetch a JS file | `fetch_resource(url)` |
| Fetch all page resources | `fetch_page_resources(index)` |
| Scan for secrets | `extract_js_secrets(index)` |
| Find DOM sinks/sources | `analyze_dom(index)` |
| Extract endpoints from JS | `extract_api_endpoints(index)` |
| Full single-page analysis | `smart_analyze(index)` |
| Compare two responses | `compare_responses(i1, i2)` |
| Quick diff | `get_response_diff(i1, i2)` |
| Auth differential | `compare_auth_states(index, ...)` |
| Multi-auth matrix | `test_auth_matrix(endpoints, states)` |
| Search patterns in history | `search_history(query, in_response_body=True)` |
| Fingerprint pages | `save_target_intel(domain, "fingerprint", ...)` |
| Check freshness | `check_target_freshness(domain, session)` |
| Read full response | `get_request_detail(index, full_body=True)` |
