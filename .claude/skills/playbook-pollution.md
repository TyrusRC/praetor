---
name: playbook-pollution
description: Pollution and parser-confusion flaws — HPP at validator/handler split, prototype pollution, cache poisoning/deception, request smuggling, JSON parser inconsistency, cookie tossing. Load when standard payloads find nothing on a mature target or WAF blocks normal injection.
prerequisite: At least one signal — WAF blocks standard payloads, target uses CDN/proxy chain, multi-tier architecture (LB → app → backend), JSON APIs with strict validation, Node.js/Express stack.
stop_condition: 10 tool calls with no parser inconsistency, no cache hit/miss anomalies, no header reflection from smuggled body, no prototype gadget evidence → return to playbook-router.
---

# Pollution & Parser-Confusion Playbook

Pollution flaws route around WAFs by exploiting disagreements between two parsers, layers, or views of the same data.

## Decision tree (top-down, stop at first match)

```
Multi-tier? (CDN + LB + app, e.g. CF→nginx→app)?
    YES → Try smuggling first (highest impact when present)
         → If no smuggling: try cache poisoning
    NO  → continue

Node.js / Express / Lodash / Mongoose detected?
    YES → Try prototype pollution (server-side first, then client-side)
    NO  → continue

JSON-only API with strict validation?
    YES → Try JSON parser inconsistency (ghost params, duplicate keys)
    NO  → continue

URL with path params hitting a cached layer?
    YES → Try cache deception (path normalization tricks)
    NO  → continue

Standard HPP last (cheap, low signal but worth one shot)
```

## Technique 1 — HTTP Request Smuggling (CL.TE / TE.CL / TE.TE / H2.CL / H2.TE / CL.0)

**Why this matters:** Front-end and back-end disagree on where a request ends. Attacker prepends one user's request onto another's.

### Preflight (1 call)
```
test_request_smuggling(target_url=ROOT, technique="auto")
```
Return value flags vulnerable variant. **If it says "no inconsistency detected" → SKIP and try cache poisoning.** Don't burn budget.

### Variants worth trying (in order)
| Variant | Trigger | When to try |
|---|---|---|
| CL.TE | Front-end uses `Content-Length`, back-end uses `Transfer-Encoding` | Always first — most common |
| TE.CL | Front-end uses `TE`, back-end uses `CL` | If CL.TE returns 400 |
| TE.TE | Both honor TE but disagree on obfuscated headers (`Transfer-Encoding : chunked`) | If both above fail and TE is allowed |
| H2.CL / H2.TE | HTTP/2 downgrade — front-end speaks H2, back-end H1 | If `:scheme` / `:authority` pseudo-headers visible in proxy history |
| CL.0 | Back-end ignores `Content-Length` on certain methods | GraphQL/WebSocket upgrade endpoints |

### Evidence (zero-noise gate)
- **Required:** Two requests in `get_logger_entries` where request B's body shows up in request A's response, OR a delayed-response oracle confirming queue poisoning.
- **`evidence.logger_index`** = the response that received the smuggled body
- **`reproductions[]` ≥ 2** (this vuln_type is in the timing/blind set — server enforces)
- **NEVER** use a destructive smuggled payload (no `DELETE`, no admin actions). Use a `GET /not-real-path` smuggle to prove queue poisoning safely.

### False positives
- Single 400 response = front-end rejected the malformed request, not smuggling
- Length anomaly without delayed-response correlation = noise
- Different keep-alive behavior between requests = connection pooling, not smuggling

### Save template
```python
save_finding(
    vuln_type="request_smuggling",
    severity="critical",
    title="HTTP Request Smuggling (CL.TE) on origin via Cloudflare",
    description="...",
    url="https://target/",
    evidence={"logger_index": 42},
    reproductions=[
        {"logger_index": 42, "elapsed_ms": 350, "status_code": 200},
        {"logger_index": 51, "elapsed_ms": 380, "status_code": 200},
    ],
)
```

## Technique 2 — Cache Poisoning & Cache Deception

**Cache poisoning:** Trick the cache into storing an attacker-controlled response that other users get.
**Cache deception:** Trick the cache into storing a sensitive page under a static-asset URL the attacker can read.

### Unkeyed-input discovery (preflight)
Call `test_cache_poisoning(target_url, headers_to_test=[...])`. Tests these unkeyed inputs:
- `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`
- `X-Original-URL`, `X-Rewrite-URL`
- `X-Forwarded-Scheme`, `X-Forwarded-Proto`
- `X-Forwarded-For` (some apps reflect this)
- Trailing-slash, fat-GET (body on GET), parameter cloaking

### Cache deception variants
| Trick | Example | Cache thinks |
|---|---|---|
| Path-suffix | `/account/profile.css` | Static CSS — cache it |
| Path-traversal-in-path | `/static/..%2faccount/profile` | Static — cache it |
| Path-normalization | `/account/profile;.css` | Static (semicolon stripped by app, kept by cache) |
| Encoded-slash | `/static%2f..%2faccount` | Static prefix |

### Evidence
- **Required:** Two requests with `extract_headers(index, ['Cache-Control', 'X-Cache', 'Age', 'CF-Cache-Status', 'X-Served-By'])`. The second hits the cache (`Age > 0`, `X-Cache: HIT`) while serving attacker-controlled content.
- **Cache deception:** First request authenticated, second unauthenticated **for the deception URL** must return the cached sensitive content.
- Save with `evidence.logger_index` of the cache HIT response.

### False positives
- `X-Cache: MISS` on the second request = not actually cached
- `Cache-Control: private` or `Vary: Cookie` present = response not shared across users
- CDN bypass on debug headers = your test bypassed cache, didn't poison it

## Technique 3 — Prototype Pollution

### Server-side (Node.js / Express / Mongoose / Lodash)

**Probe:** `test_mass_assignment` won't catch this. Send:
```json
{"__proto__": {"polluted": "yes"}}
```
or
```json
{"constructor": {"prototype": {"polluted": "yes"}}}
```
to any JSON-accepting endpoint.

**Detection oracle:** Send a follow-up request that exercises a code path which would now read `Object.prototype.polluted`:
- A search endpoint that defaults to `query.polluted` if no filter set
- A render endpoint that checks `req.body.x?.allowed`
- A config-merge endpoint

**Gadget chains worth knowing (do NOT exploit, just verify reachability):**
| Library | Gadget | Result |
|---|---|---|
| `lodash` < 4.17.12 | `_.merge`, `_.set`, `_.defaultsDeep` | Pollution sink |
| `express-fileupload` | `parseNested: true` | Pollution → RCE on upload |
| `mongoose` < 5.13.20 | `Schema.path('__proto__')` | Schema-level pollution |
| `express` view engine | `settings['view options'].polluted` | Pollution → SSTI → RCE |
| `node-config` | `config.util.extendDeep` | Pollution sink |

### Client-side (DOM XSS via prototype)
After server-side fails, check JS for `Object.prototype.X` reads:
```
analyze_dom(index)
search_history(query="__proto__", in_response_body=True)
search_history(query="constructor.prototype", in_response_body=True)
```

### Evidence
- **Required:** Two requests — pollution request, then probe request that reads the polluted property and reflects it. Both `logger_index` go in evidence/reproductions.
- **NEVER use destructive gadgets** (`require('child_process').exec`). Stop at "polluted property is readable from request scope."

## Technique 4 — JSON Parser Inconsistency (Ghost Parameters)

**The flaw:** Validator parses JSON one way, handler parses another. Common when WAF/validator and app use different parsers (e.g., `JSON.parse` vs Jackson vs `simplejson`).

### Probes (send each, observe handler response)
```json
// Duplicate key — RFC says undefined behavior, parsers disagree
{"role": "user", "role": "admin"}

// Comment in JSON — Jackson allows, JSON.parse rejects
{"role": "user" /* injected */, "admin": true}

// Trailing comma — relaxed parsers accept
{"role": "user",}

// BOM prefix
﻿{"role": "admin"}

// Numeric coercion — "1" vs 1 vs 1.0 vs true
{"is_admin": "true"}    // string "true" — does it coerce?
{"is_admin": 1}         // number 1
{"is_admin": [true]}    // array — some parsers take [0]
{"is_admin": {"$ne": null}}  // NoSQL operator confusion

// Unicode normalization
{"role": "admin"}  // role == role after unicode

// Type confusion
{"id": ["1", "2"]}      // array where scalar expected — first/last? joined?
```

### Evidence
- **Required:** Send the polluted body, then a second request that demonstrates the privileged outcome (admin endpoint returns 200, profile shows `role: admin`, etc.).
- Compare against baseline (without ghost param) using `compare_responses`.

## Technique 5 — Standard HPP (HTTP Parameter Pollution)

Lower priority — try only after the above. `test_parameter_pollution` covers most cases.

### When HPP actually matters
- WAF processes first occurrence, app uses last (or vice versa) → WAF bypass
- Auth check uses `query.user_id`, business logic uses `body.user_id` → privilege bypass
- Multi-value: `?role=user&role=admin` — backend picks based on framework

### Quick framework reference
| Framework | First / Last / Joined |
|---|---|
| PHP | Last wins |
| ASP.NET | Joined with `,` |
| Java Servlet | First |
| Node.js (Express default) | Joined as array |
| Python (Flask/Django) | Joined as list |
| Rails | Last wins |

**Bypass example:** WAF checks `?id=1` (first), app uses `?id=1&id=1' OR '1'='1` (last/array). Test by polluting a known-blocked payload.

## Technique 6 — Cookie Tossing & `__Host-` Bypass

**Cookie tossing:** Set a cookie with broader scope from a less-trusted subdomain to override the parent's session cookie.

**Probe:**
```
session_request(session, "GET", "https://evil-controlled-subdomain.target/set-cookie",
                headers={"Set-Cookie": "session=ATTACKER; Domain=.target.com; Path=/"})
```
Then check if main app accepts the tossed cookie. Only relevant if you control a subdomain (open redirect to subdomain, takeover, or XSS on subdomain).

**`__Host-` / `__Secure-` bypass:** If app uses `__Host-session`, browser-side it's locked to one host with no Domain. But **server-side**, some frameworks accept any cookie name. Strip the prefix server-side and see if it's still honored.

## Burp MCP tool mapping

| Technique | Primary tool | Evidence tool |
|---|---|---|
| Smuggling | `test_request_smuggling` | `get_logger_entries`, `extract_headers` |
| Cache poisoning | `test_cache_poisoning` | `extract_headers(['X-Cache','Age','CF-Cache-Status'])` |
| Prototype pollution | `send_http_request` (raw JSON) | `compare_responses`, `analyze_dom` |
| JSON parser confusion | `send_raw_request` | `compare_responses` |
| HPP | `test_parameter_pollution` | `fuzz_parameter` |
| Cookie tossing | `session_request` (cross-subdomain) | `extract_headers(['Set-Cookie'])` |

## Cross-references

- Pollution → SSTI? → load `playbook-cve-research.md` for engine-specific CVEs
- Smuggling found → `chain-findings.md` (chains with admin-only endpoints)
- Prototype pollution + Express view → potential RCE → `playbook-red-team-web.md` deserialization section

## Save-finding template (zero-noise compliant)

For pollution findings that aren't in NEVER-SUBMIT list:
```python
save_finding(
    vuln_type="prototype_pollution",  # or request_smuggling, cache_poisoning, hpp, json_parser_confusion
    severity="high",
    title="Server-side prototype pollution via /api/profile (lodash.merge sink)",
    description="POST /api/profile with __proto__ key pollutes Object.prototype. Subsequent /api/search reads polluted.role and grants admin view.",
    url="https://target/api/profile",
    evidence={"logger_index": 88},
    reproductions=[  # smuggling/race always need this; others optional but encouraged
        {"logger_index": 88, "elapsed_ms": 220, "status_code": 200},
        {"logger_index": 92, "elapsed_ms": 215, "status_code": 200},
    ],
)
```

For findings in NEVER-SUBMIT (e.g., host_header_no_cache_poison, hpp without auth/WAF impact):
```python
save_finding(
    vuln_type="host_header_no_cache_poison",
    severity="info",
    title="...",
    description="...",
    url="...",
    evidence={"logger_index": N},
    chain_with=["finding-id-of-cache-poison"],  # REQUIRED — server enforces
)
```

