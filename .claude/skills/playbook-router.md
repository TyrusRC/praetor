---
name: playbook-router
description: Pick which advanced playbook to load based on target traits. Use when standard hunt skill yielded nothing or user asks for advanced/red-team/deep testing. Loads at most 2 playbooks instead of spamming all.
---

# Playbook Router

You have **6 advanced playbooks** that go beyond OWASP WSTG. **Loading all of them wastes context.** This router runs a quick target classifier and returns the 1-2 playbooks that actually fit. If none match, stay on `hunt.md`.

## When to invoke this router

Trigger conditions (any one is enough):
- `hunt.md` Phase 3 finished with **zero confirmed findings** after 2+ categories tested
- User says: "go deeper", "advanced", "red team this", "find chains", "what am I missing"
- `auto_probe` returned only score < 30 noise across the board
- Target has been tested before (memory shows prior coverage with no new findings)
- Recon revealed unusual surface: GraphQL, gRPC, WebSocket, mobile API, cloud metadata reachable, framework versions in headers

## When NOT to invoke

- First-pass recon hasn't completed yet → run `hunt.md` first
- Target is brand new and no fingerprinting done yet → recon first
- User asked for a specific bug class only → use `craft-payload.md` or `investigate.md` directly

## Classifier (run in order, stop at first STRONG match)

### Q1 — Is this a mobile-app backend?

**Signals (need 2+):**
- `/api/v*/mobile/`, `/api/app/`, `/m/api/` paths in proxy history
- `User-Agent: okhttp/`, `CFNetwork/`, `Dalvik/`, `Alamofire/` seen
- Push notification tokens (FCM, APNs) in request bodies
- `X-Device-Id`, `X-App-Version`, `X-Platform: ios|android` headers
- User mentions APK/IPA, "mobile app", "iOS app", "Android app"
- Receipt-validation endpoints (`/iap/verify`, `/subscription/validate`)

**Match → load `playbook-mobile-backend.md`** (PRIMARY).
Often co-load `playbook-api-advanced.md` since mobile backends are API-first.

### Q2 — Is this an API-first product (no HTML UI)?

**Signals (need 2+):**
- Root path returns JSON / 404 / OpenAPI spec, not HTML
- `/graphql`, `/api/`, `/v1/`, `/v2/` are the dominant traffic
- `Content-Type: application/json` on >70% of responses
- gRPC-Web (`Content-Type: application/grpc-web`), JSON-RPC (`{"jsonrpc":"2.0"`)
- WebSocket upgrade frames seen in `get_websocket_history`
- SSE streams (`Content-Type: text/event-stream`)

**Match → load `playbook-api-advanced.md`** (PRIMARY).

### Q3 — Did fingerprinting reveal specific framework + version?

**Signals (need 1):**
- `Server: Apache/2.4.49`, `X-Powered-By: PHP/7.4.3`, `X-AspNet-Version`
- HTML meta `generator` tag, `<!-- Drupal 9.5.0 -->`, WP version in feeds
- Stack trace leaked exact version
- JS files reference `react@17.0.2`, `vue@2.6.14`, `next@12.1.0`
- `detect_tech_stack` returned a confidence ≥80% on a versioned stack

**Match → ALWAYS co-load `playbook-cve-research.md`** alongside whatever PRIMARY you picked. Cheap, parallelizes well.

### Q4 — Did standard testing find nothing on a target that "should" have bugs?

**Signals (need 2+):**
- Coverage > 30% across 3+ vuln categories, all clean
- WAF detected and blocking standard payloads consistently
- Target is mature (large company, public bug bounty, many resolved reports)
- App accepts complex inputs (multi-step forms, JSON bodies, file uploads) but standard tests show no anomalies
- Memory shows previous sessions also found nothing

**Match → load `playbook-pollution.md`** (PRIMARY) — pollution flaws hide where standard payloads can't reach. Often co-load `playbook-red-team-web.md` for chain hunting.

### Q5 — User said "red team", "chain", "exploit", or signals suggest SSO/serialization/LLM?

**Signals (any one):**
- User explicit ask: "red team", "find a chain", "post-exploitation"
- Target uses OAuth, OIDC, SAML (login flow goes through identity provider)
- Java/.NET/Python/Ruby with serialized data in cookies/params
- npm/PyPI/Maven dependency files exposed (`.npmrc`, `requirements.txt`, `package-lock.json` reachable)
- LLM features in product (chat, summarization, "AI assistant")

**Match → load `playbook-red-team-web.md`** (PRIMARY).

### Q6 — Cloud-native stack (AWS / GCP / Azure) reachable from web tier?

**Signals (need 1+):**
- Cloud metadata endpoints reachable (`169.254.169.254`, `metadata.google.internal`)
- JS bundles or responses contain cloud domains: `s3.amazonaws.com`, `*.lambda-url.*.on.aws`, `cognito-idp.*.amazonaws.com`, `storage.googleapis.com`, `*.firebaseio.com`, `*.azurewebsites.net`, `*.blob.core.windows.net`
- AWS access keys (`AKIA…`, `ASIA…`), Azure SAS query strings (`?sv=…&sig=…`), Firebase API keys (`AIza…`), GCP tokens (`ya29.…`) in JS or responses
- Cognito JWT issuer in `iss` claim
- Cloud SDK error fingerprints in 5xx pages (`AccessDenied`, `SignatureDoesNotMatch`, `Microsoft.WindowsAzure.Storage`, etc.)

**Match → load `playbook-cloud-native.md`** (PRIMARY). Often co-load `playbook-red-team-web.md` if SSO/Cognito present, or `playbook-api-advanced.md` if API Gateway / Lambda Function URLs are the surface.

## Decision matrix (combined)

| Target trait | Load | Co-load |
|---|---|---|
| Mobile API | `mobile-backend` | `api-advanced` |
| GraphQL/gRPC/WS heavy | `api-advanced` | `pollution` if WAF |
| Versioned stack leaked | (whatever Q1-Q6 said) | `cve-research` |
| Mature target, nothing found | `pollution` | `red-team-web` |
| OAuth/SSO/serialization/LLM | `red-team-web` | `cve-research` |
| Cloud-native (AWS/GCP/Azure) | `cloud-native` | `red-team-web` if SSO |
| Plain webapp, standard CMS | none — stay on `hunt.md` | — |

**Hard cap: never load more than 2 playbooks at once.** If 3 match, pick the two with strongest signals.

## Adaptive escape hatch

Every playbook has a `stop_condition`. After 10 tool calls inside a playbook with **zero signals (no anomalies, no Collaborator hits, no length/timing/status deltas)**, return here and re-classify:
1. Did the target's behavior teach me something? (Different tech now visible? New endpoints? WAF stronger than expected?)
2. Re-run the classifier with new signals.
3. If still no match → stop, report to user, suggest manual review.

## Anti-patterns

- **Don't load all 6** — that's 4000+ lines of context spam. The router exists to prevent this.
- **Don't load `cloud-native` for an on-prem app** — its IMDS/SAS/Cognito techniques don't apply.
- **Don't load `cve-research` without a versioned stack** — it has nothing to match against.
- **Don't load `mobile-backend` for a regular webapp** — its techniques (deep-link, IAP) don't apply.
- **Don't skip the router** — even experienced operators waste tokens on wrong techniques.

## Hand-off

Once you pick playbook(s):
1. Announce: `"Loading playbook-X based on signal Y."` (so user knows why)
2. Read the playbook with `Read` (or invoke as a skill if registered)
3. Follow its decision tree at the top
4. When done (finding saved OR stop_condition hit) → return here for next decision
