---
name: playbook-router
description: Pick which advanced playbook to load based on target traits. Use when standard hunt skill yielded nothing or user asks for advanced/red-team/deep testing. Loads at most 2 playbooks instead of spamming all.
---

# Playbook Router

You have **9 advanced playbooks** that go beyond OWASP WSTG. **Loading all of them wastes context.** This router runs a quick target classifier and returns the 1-2 playbooks that actually fit. If none match, stay on `hunt.md`.

**Always-on baseline:** `playbook-business-logic.md` is co-loaded with whatever Q1–Q6 returns when `business_context.app_type` is set and money / sensitive_data / kill_switches are populated. Logic flaws are the highest-paying class on any business-relevant target; never skip them.

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

**Dynamic instrumentation gate:** if operator has the APK/IPA installed on a device AND has Frida (iOS+Android) / adb (Android), co-load `playbook-mobile-dynamic.md` FIRST. It bypasses SSL pinning + root/JB detection to make Burp see traffic, hooks crypto/HMAC/storage at runtime, and abuses exported Android components — then hands off to `playbook-mobile-backend.md` for backend testing. Dynamic-only; no static decompile path.

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

### Q5 — User said "red team", "chain", "exploit", or signals suggest serialization/dependency/LLM?

**Signals (any one):**
- User explicit ask: "red team", "find a chain", "post-exploitation"
- Java/.NET/Python/Ruby with serialized data in cookies/params
- npm/PyPI/Maven dependency files exposed (`.npmrc`, `requirements.txt`, `package-lock.json` reachable)
- LLM features in product (chat, summarization, "AI assistant")

**Match → load `playbook-red-team-web.md`** (PRIMARY).

> Note: OAuth / OIDC / SAML / FIDO / payment signals previously routed here now route to **Q7** (`playbook-payment-and-auth.md`), which is deeper on those specific surfaces.

### Q6 — Cloud-native stack (AWS / GCP / Azure) reachable from web tier?

**Signals (need 1+):**
- Cloud metadata endpoints reachable (`169.254.169.254`, `metadata.google.internal`)
- JS bundles or responses contain cloud domains: `s3.amazonaws.com`, `*.lambda-url.*.on.aws`, `cognito-idp.*.amazonaws.com`, `storage.googleapis.com`, `*.firebaseio.com`, `*.azurewebsites.net`, `*.blob.core.windows.net`
- AWS access keys (`AKIA…`, `ASIA…`), Azure SAS query strings (`?sv=…&sig=…`), Firebase API keys (`AIza…`), GCP tokens (`ya29.…`) in JS or responses
- Cognito JWT issuer in `iss` claim
- Cloud SDK error fingerprints in 5xx pages (`AccessDenied`, `SignatureDoesNotMatch`, `Microsoft.WindowsAzure.Storage`, etc.)

**Match → load `playbook-cloud-native.md`** (PRIMARY). Often co-load `playbook-red-team-web.md` if SSO/Cognito present, or `playbook-api-advanced.md` if API Gateway / Lambda Function URLs are the surface.

### Q7 — Money-flow / auth-heavy surface (OAuth, FIDO, payment, IAP, 3DS, SCA)?

**Signals (any 1, two for STRONG match):**
- `/authorize`, `/oauth/`, `/oidc/`, `/.well-known/openid-configuration` reachable
- "Sign in with Google / Microsoft / Apple / Okta / Auth0" buttons
- `id_token` / `access_token` / `refresh_token` / `nonce` / `at_hash` in responses
- WebAuthn endpoints (`/webauthn/register/begin`, `attestationObject` in bodies, `navigator.credentials.create` in JS)
- Google Pay / Apple Pay / Samsung Pay buttons OR `paymentMethodData.tokenizationData.token` / `PKPaymentToken` / `X-Samsung-Knox-Token` in traffic
- Stripe / Square / PayPal / Adyen / Braintree integration (`pi_`, `seti_`, `ch_`, `tok_`, PayPal `PAY-/EC-` prefixes in requests)
- 3DS challenge: `cavv`, `eci`, `dsTransId`, `acsTransId` fields, `cardinalcommerce.com` iframes
- IAP / subscription endpoints (`/iap/verify`, `purchase_token`, `transactionReceipt`, `signedData`)
- Recovery flows handling money / admin actions (forgot password / forgot passkey / backup codes)

**Match → load `playbook-payment-and-auth.md`** (PRIMARY). This is the highest-paying surface on any program that has it ($5k–$50k typical). Often co-load:
- `playbook-mobile-backend.md` if signals come from mobile app (IAP, Google/Apple Pay native flow)
- `playbook-red-team-web.md` if SSO chain into broader ATO is the goal

## Decision matrix (combined)

| Target trait | Load | Co-load |
|---|---|---|
| Mobile API + binary/device available | `mobile-dynamic` | `mobile-backend` |
| Mobile API (passive only) | `mobile-backend` | `api-advanced` |
| GraphQL/gRPC/WS heavy | `api-advanced` | `pollution` if WAF |
| Versioned stack leaked | (whatever Q1-Q7 said) | `cve-research` |
| Mature target, nothing found | `pollution` | `red-team-web` |
| Serialization / dep confusion / LLM | `red-team-web` | `cve-research` |
| Cloud-native (AWS/GCP/Azure) | `cloud-native` | `red-team-web` if SSO |
| OAuth / FIDO / Apple-Google-Samsung Pay / IAP / 3DS | `payment-and-auth` | `mobile-backend` if from mobile, `red-team-web` if ATO chain |
| Plain webapp, standard CMS | none — stay on `hunt.md` | — |
| Money flow / kill switches set | (whatever else matches) | `business-logic` (always co-load) |

**Hard cap: never load more than 2 playbooks at once.** If 3 match, pick the two with strongest signals.

## Adaptive escape hatch

Every playbook has a `stop_condition`. After 10 tool calls inside a playbook with **zero signals (no anomalies, no Collaborator hits, no length/timing/status deltas)**, return here and re-classify:
1. Did the target's behavior teach me something? (Different tech now visible? New endpoints? WAF stronger than expected?)
2. Re-run the classifier with new signals.
3. If still no match → stop, report to user, suggest manual review.

## Deep-dive auto-trigger (no manual prompt needed)

Deep-dive (`hunt.md` Phase 3.6) **auto-fires** when ANY signal below is present after recon completes OR when intel for the domain already records the signal. Operator does NOT need to say "go deeper".

Evaluate at TWO checkpoints:
1. **End of Phase 2 (recon)** — run signal scan against fresh recon output + `load_target_intel(domain, "all")`
2. **End of Phase 3 (vuln testing)** — re-evaluate (new findings change which rounds fire)

### Auto-trigger matrix

| Signal — ANY one fires the trigger | Source (recon OR intel) | Rounds to run |
|---|---|---|
| `business_context.kill_switches` populated | `get_business_context(domain)` | R2 (logic) — MANDATORY |
| `business_context.money_flow != "none"` | `get_business_context` | R2 + R5 recovery |
| `business_context.user_roles` has ≥2 roles | `get_business_context` | R2 pattern E (BFLA/BOLA) → R3 |
| ≥1 confirmed finding saved | `get_findings(domain)` / intel `findings.json` | R3 (chains) — MANDATORY per finding |
| Webhook endpoints captured | `search_history(query="webhook")` >0 OR intel endpoints contain `/webhook` | R4 webhook + R5 second-order |
| Admin / internal URLs grep-hit | sourcemaps, swagger.json, robots.txt, sitemap.xml, intel endpoints | R4 admin/internal row |
| API versioning present | proxy history has `/v1/` AND `/v2/` (or any 2 versions) | R4 api-versioning |
| Subdomain count ≥ 5 | `query_crtsh(domain)` or intel `profile.json.subdomains` | R4 subdomain-takeover + beta/staging |
| Sourcemaps available | `*.js.map` HTTP 200 | R4 sourcemaps |
| CI/CD artifacts exposed | `discover_common_files` hit on `.github/`, `Jenkinsfile`, `.gitlab-ci.yml`, `.npmrc` | R4 ci-cd |
| Cloud asset references | JS / responses contain `s3.amazonaws.com`, `*.firebaseio.com`, `*.azurewebsites.net`, `metadata.google.internal` | R4 cloud + load `playbook-cloud-native.md` |
| Mobile traffic signals | `okhttp/`, `CFNetwork/`, `Dalvik/` UA OR `/api/mobile/` paths OR intel `profile.json.mobile_indicators` | R4 mobile-only + load `playbook-mobile-backend.md` (and `mobile-dynamic` if binary+device) |
| Serialization-prone stack | `detect_tech_stack` matches Java / .NET / Rails / Python / Node | R5 deserialization |
| OAuth / SSO / OIDC / SAML present | `/authorize`, `/oauth/`, `id_token` in responses, `.well-known/openid-configuration` | R5 OAuth mix-up + load `playbook-payment-and-auth.md` §1 |
| FIDO / WebAuthn / passkey | `/webauthn/`, `navigator.credentials` in JS, `attestationObject` in bodies | load `playbook-payment-and-auth.md` §2 |
| Payment processor visible | Stripe / Square / PayPal / Adyen / Braintree / GPay / Apple Pay / Samsung Pay markers | load `playbook-payment-and-auth.md` §3–9 |
| Recovery / 2FA flow | "forgot password" / `/recovery` / `/reset` / TOTP setup | R5 recovery + load `playbook-payment-and-auth.md` §10 |
| Multi-tenant indicators | `tenant_id`, `org_id`, `workspace_id` in URLs/bodies | R2 pattern H (tenant boundary) |
| Subscription / entitlement | `/subscription`, `/billing`, `tier`, `entitlement` in responses | R2 pattern I (entitlement state) |
| Idempotency keys | `Idempotency-Key` header observed | R2 pattern G (idempotency-key scope) |
| WebSocket traffic | `get_websocket_history` >0 OR intel logs WS endpoints | R5 WS smuggling + R4 WS |
| LLM / AI features | chat UI, "assistant", prompt endpoints, `/v1/chat/completions`, `/embeddings` | R5 cross-class + load `playbook-red-team-web.md` |
| CDN in front | `Cache-Control`, `CF-Cache-Status`, `X-Cache`, `Via`, `CF-Ray`, `Akamai-X-` headers | R5 cache-poisoning |
| Versioned tech with known CVEs | `Server: Apache/2.4.49`, framework versions in headers / HTML | load `playbook-cve-research.md` |

### Fallback trigger

NONE of the above fire BUT target has **>20 endpoints** in `load_target_intel(domain, "endpoints")`: run **R4 + R5 anyway** — large surface usually hides forgotten paths.

### Cross-target signals (intel from other engagements)

Also check `lookup_cross_target_patterns(tech_stack=<detected>, vuln_class="*")`:
- If patterns.json from past engagements shows a tech-stack-bound chain worked → run that chain class first regardless of this target's signals.
- If knowledge_version has advanced since last coverage entry → re-run R5 cross-class meta-passes (new probes available).

### When NOT to auto-trigger

- Target has <5 endpoints AND no money/auth signals → deep-dive yields nothing; stop after Phase 3.
- `business_context` empty AND no high-value recon signal → run `capture_business_context` first, then re-evaluate.
- Operator explicitly stopped session ("done", "summarize", "report", "stop") — never auto-trigger after stop.

### Operator override

- **Skip deep-dive even when signals fire:** `save_target_notes(domain, "skip_deep_dive=true")` for that engagement, OR per-call `--no-deep-dive`.
- **Force deep-dive without signals:** open `hunt.md` Phase 3.6 directly.

The router exists for *primary-class* selection (mobile / api / cloud / payment-auth / pollution / red-team / cve / business-logic). Deep-dive auto-fires AFTER (or alongside) primary class based on signals.

## Per-vuln-class deep-dives (W16-W17)

The primary-class playbooks above are for **target classification** (mobile / API / cloud / payment / etc.). The per-vuln-class deep-dives below are for **finding-class investigation** — load IN ADDITION to a primary playbook when a specific vuln class is in play.

These are exempt from the "never load more than 2 playbooks" cap because they're targeted single-class references operators consult once and put down, not multi-call workflow drivers.

| Trigger | Deep-dive | Wave |
|---|---|---|
| Param accepts URL/hostname; cloud-metadata reachable; image-proxy / link-preview / webhook-tester features | `playbook-ssrf-deep-dive.md` | W16 |
| Param contains an ID (numeric / UUID / slug / hash) AND ≥2 auth states available | `playbook-idor-bola.md` | W16 |
| `Authorization: Bearer <jwt>` observed; `harvest_identifiers` flagged a JWT; OAuth/OIDC auth model | `playbook-jwt-deep-dive.md` | W16 |
| `/oauth/authorize`, `/oauth/token`, `/.well-known/openid-configuration` reachable; federated identity in scope | `playbook-oauth-flow-attacks.md` | W17 |
| Target behind CDN/WAF + origin (≥2 HTTP parsers); Kettle 2025 endgame variants applicable | `playbook-request-smuggling.md` | W17 |
| Node.js (Express/Fastify/Hapi/Koa) + JSON body merge; client-side options-merge libraries (jQuery extend, lodash merge); CSPP gadgets in framework | `playbook-prototype-pollution.md` | W17 |
| Subdomain takeover hunt — wildcard scope or subdomain list harvested | `recon-takeover.md` | W9 |

**Loading rule:** Deep-dives are reference material. Load when investigating a specific finding-class. Unload immediately when the investigation is done.

## Severity routing

All confirmed findings rate against `hunt.md` Phase 4 rubric (`severity = base_class × business_context_multiplier ± floor/ceiling`). Floors override CVSS instinct: `alg:none`, sandbox-payment-on-prod, password-reset-to-attacker-email, mass PII without auth = CRITICAL minimum regardless of category. Ceilings cap inflation: reflected XSS without admin context = MEDIUM max.

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
