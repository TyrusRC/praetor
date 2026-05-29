---
description: Web Cache Deception — static-suffix tricks, path-confusion variants, parser-differential bypass, Cloudflare/Akamai/Fastly/Varnish specifics. Load when target is behind a CDN.
globs:
---

# Web Cache Deception Deep-Dive

Load when: target is behind a CDN (Cloudflare / Akamai / Fastly / CloudFront / Varnish), AND has authenticated dynamic pages. Cache deception cannot exist on a single-server origin or a fully-static site.

## The vulnerability in one line

The CDN caches based on URL path (file extension / static suffix). The origin routes based on path resolution (ignoring the suffix). Attacker tricks the CDN into caching the authenticated dynamic response under an attacker-readable URL.

## Attack matrix

### 1. Static-suffix append (the classic)

```
Authenticated request:   GET /profile          → 200, Cache-Control: private, victim PII
Attacker request:        GET /profile/x.css    → 200, victim PII, CDN says CACHEABLE
Attacker fetch:          GET /profile/x.css    → 200, victim PII from cache
```

Origin treats `/profile/x.css` as `/profile` (path normalisation). CDN treats it as a CSS file (cacheable). PII served to anyone fetching that exact URL.

Cacheable suffixes: `.css`, `.js`, `.png`, `.jpg`, `.gif`, `.ico`, `.woff`, `.woff2`, `.txt`, `.json` (vendor-specific), `.svg`, `.map`.

### 2. Path traversal / normalisation bypass

```
Authenticated request:    GET /profile        → 200
Attacker probe variants:
  /profile/x.css                   # baseline trick
  /profile/../profile.css          # path traversal
  /static/../profile.css           # cross-segment
  /profile/anything/../profile.css # nested traversal
  /profile;.css                    # semicolon segment
  /profile%00.css                  # null byte
  /profile/x.css?nonexistent=1     # parameter pollution
  //profile/x.css                  # protocol-relative quirk
```

### 3. Parser-differential cache deception (W13 active KB)

W13 added `web_cache_deception.static_suffix_cache_poisoning` to active KB. Pairs:
- Status 200 + Cache-Control: public + user-data word → high severity
- Status 200 + X-Cache: HIT + user-data word → critical severity

The matcher fires automatically in `auto_probe` against state-changing endpoints when the operator drives the auth-then-suffix sequence.

### 4. Web Cache Deception 2.0 (Omer Gil + Kettle research, 2025)

Newer variants exploit **CDN-specific path normalisation differentials**:

- **Cloudflare-specific**: CF treats `.json` as cacheable by default in Workers cache; origin may strip and serve dynamic JSON
- **Akamai-specific**: `;` is segment separator at CDN; origin may strip
- **Fastly-specific**: Trailing `/` differences between front and origin
- **Varnish-specific**: TTL inheritance from parent directory

Each CDN has its own "static" definition. Probe each per-vendor.

### 5. Cache-key smuggling

Vary headers control the cache key:
- `Vary: User-Agent` — attacker poisons cache per UA but victim reads with same UA → poisoning succeeds
- `Vary: Cookie` — should isolate cache per user, but if cookie is missing on auth and present on cache-fetch, cross-user leak
- `Vary: Accept-Encoding` — compression-level differences leak content

### 6. Cache poisoning vs deception

| Class | Mechanism | Outcome |
|---|---|---|
| **Web Cache Deception** | Trick CDN into caching authenticated response under attacker-readable URL | Victim's PII served to attacker URL |
| **Web Cache Poisoning** | Trick CDN into caching attacker-controlled response under legitimate URL | Attacker's payload served to victim |

Different classes, same primitives (path / header manipulation). Both live in `cache_poisoning.json` / `web_cache_deception.json`.

## Tool chain

1. **CDN fingerprint** — fetch any URL and inspect `Server: cloudflare`, `Via: 1.1 google`, `CF-Ray`, `X-Akamai-*`, `X-Cache: cf-cache-status: HIT`, `X-Served-By: cache-* fastly`. Two distinct CDN identifiers = two-cache pipeline.
2. **Identify auth endpoint** — `discover_attack_surface` highlights `/profile`, `/account`, `/dashboard`, `/api/me` returning user-specific content with `Cache-Control: private`.
3. **Static-suffix probe** — `auto_probe(categories=['web_cache_deception'])` runs W13 active context.
4. **Vendor-specific** — `auto_probe(categories=['cache_deception_v2'])` for newer parser-differentials.
5. **Verify cacheable** — `concurrent_requests` with the suffix variant; check second request returns cached version (`X-Cache: HIT` / `Age: > 0`).

## Evidence ladder

| Verdict | Evidence shape | Save? |
|---|---|---|
| **CONFIRMED CRITICAL** | Authenticated PII / payment / tokens served via cacheable URL to unauth fetch + `X-Cache: HIT` | yes |
| **CONFIRMED HIGH** | Authenticated session data served via cacheable URL but no PII | yes (operator argues impact) |
| **CONFIRMED MEDIUM** | Path-normalisation bypass detected but no cached private data observed yet | yes (chain to escalate) |
| **SUSPECTED** | Suffix accepted but Cache-Control: private — origin honours private but CDN may not | NO save — investigate CDN config |
| **FAILED** | All variants get Cache-Control: private OR 404 | NO |

## save_finding shape

```python
save_finding(
    vuln_type="web_cache_deception",
    endpoint="https://target.com/profile/x.css",
    severity="critical",
    evidence={
        "logger_index": <cached-pii index>,
        "summary": "Web Cache Deception via static-suffix bypass — /profile/x.css served victim's profile PII; X-Cache: HIT on second fetch from different IP confirms public cache.",
        "cdn": "Cloudflare",
        "suffix_variant": ".css",
        "x_cache_header": "HIT",
        "cache_control": "max-age=3600",
        "leaked_field_classes": "PII (email, address); session token in cookie reflected",
    },
)
```

## Severity discipline

- Authenticated PII / payment served from public cache = CRITICAL.
- Public-but-sensitive metadata (private project names, draft posts) = HIGH.
- Cache normalisation bypass without observed private data leak = MEDIUM (informational).
- "I can poison the cache to serve a 500" = NEVER_SUBMIT (DoS, Rule 5 / Rule 17).

## NEVER_SUBMIT traps

- "Suffix accepted, returns 200" — without proving private content leaks to next fetcher, no impact.
- "Cache-Control: max-age=3600" on public marketing page — by design.
- "Path traversal accepted" — without cache deception consequence, just an LFI/info-disclosure candidate (different class).
- Standalone DoS via cache poisoning — Rule 5 + Rule 17 NEVER_SUBMIT.

## Chain patterns

- **Cache deception + token-in-response** = session token theft.
- **Cache poisoning + XSS payload** = XSS to mass victims.
- **Cache deception + GraphQL persisted query** = admin query result cached for victims.
- **Cache deception + IDOR** = enumerated PII for many users in one cached URL.
- **Path normalisation + smuggling** = cache + back-end disagree, two-stage attack.

## Related

- `knowledge/web_cache_deception.json` — W13 active (`static_suffix_cache_poisoning` + `path_confusion` normalised)
- `knowledge/cache_poisoning.json` — adjacent class (W18 added `nextjs_15_cache_key_confusion`)
- `knowledge/cache_deception_v2.json` — vendor-specific newer variants
- `test_cache_poisoning` (W11 VerdictResult)
- `playbook-request-smuggling.md` — cache poisoning via smuggle chain
- Omer Gil "Web Cache Deception Attack" original (2017) + Kettle 2025 updates
- Rule 17 NEVER_SUBMIT — DoS / pure cache poisoning without exploit chain
