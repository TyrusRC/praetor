---
name: report-templates
description: Generate platform-specific bug-bounty reports (HackerOne, Bugcrowd, Intigriti, Immunefi). Use after a finding is `confirmed` and `assess_finding` returned `REPORT`. Output follows PTES + OWASP WSTG layout with CVSS 4.0.
---

# Report Templates

## Pre-flight Gate (Rule 28)

Before `generate_report` or `format_finding_for_platform`:

1. Finding has `status='confirmed'` (else excluded)
2. `assess_finding` returned `REPORT` (else gated upstream)
3. Step-0 replay passed (`verify-finding.md`)
4. False positives → set `status='likely_false_positive'`. The next `generate_report` HARD-DELETES them. No tracking, no tombstones.

If `generate_report` says "No reportable findings", you haven't confirmed anything — go verify, don't argue with the gate.

## Canonical Finding Layout (PTES §7 + OWASP WSTG)

Every finding — regardless of platform — must include these sections in this order. The MCP `_build_finding_section` already emits this structure when the `finding` dict has the right keys.

| Section | Source key | Purpose |
|---|---|---|
| Classification | `vuln_type` `cwe` `owasp` `cvss_vector` `severity` `confidence` | Triager filters by class |
| Context | `context` | What this endpoint does, who reaches it, why it matters |
| Vulnerability | `description` | Plain-language description of the bug |
| Attack Walkthrough | `attack_walkthrough` (list[str]) | End-to-end exploitation: discover → trigger → control → impact |
| Impact | `impact` | Concrete outcome (data, access, money, account control) |
| Escalation Path | `escalation` `chain_with` | How to chain into higher-impact bug (ATO, RCE, lateral) |
| Proof of Concept | `poc_request` (dict) | Exact HTTP request — copy-paste reproducible |
| Steps to Reproduce | `reproduction_steps` (list[str]) | Cold-start steps a triager can follow in <5 min |
| Evidence | `evidence` `evidence_text` `reproductions` | Logger indices, Collaborator IDs, response excerpts, replay table |
| Remediation | `remediation` (list[str]) | Concrete fix guidance for defenders |
| References | `references` (list[str]) | CWE, OWASP, CVE, vendor advisory, ATT&CK |

## Universal Rules

1. **Title:** `[Bug Class] in [Component] allows [actor] to [impact]`
2. **Impact-first** in the summary — what an attacker DOES, not how the bug works
3. **<600 words** main body (triagers read hundreds of reports)
4. **Reproduction must work cold-start in <5 min**
5. **One finding per report** — bundle only when it's a chain
6. **Severity honest** — Rule 21. NEVER inflate.

## CVSS 4.0 — Use the Calculator

Calculator: https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator

CVSS v4 metrics (Scope is REMOVED; replaced by Vulnerable / Subsequent System axes):

| Metric | Values | Notes |
|---|---|---|
| AV — Attack Vector | N=Network, A=Adjacent, L=Local, P=Physical | Most web vulns = N |
| AC — Attack Complexity | L=Low, H=High | H if needs race / specific config |
| AT — Attack Requirements | N=None, P=Present | P if conditions outside attacker control needed |
| PR — Privileges Required | N=None, L=Low, H=High | N=unauth, L=any user, H=admin |
| UI — User Interaction | N=None, P=Passive, A=Active | XSS/CSRF=A; IDOR/SQLi=N |
| VC, VI, VA — Vulnerable System Confidentiality / Integrity / Availability | H/L/N | Direct impact on the vulnerable component |
| SC, SI, SA — Subsequent System impact | H/L/N | Impact propagated to other components |

Severity bands (CVSS-BR base): None 0.0 / Low 0.1–3.9 / Medium 4.0–6.9 / High 7.0–8.9 / Critical 9.0–10.0.

**Common starting vectors** (replace AT/PR/UI/SC/SI/SA per target):
- RCE unauth: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` (~9.3)
- SQLi data extraction: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` (~8.7)
- Stored XSS hitting admin: `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:H/SI:H/SA:N` (~7.x)
- IDOR read other-user PII: `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` (~7.0)
- Reflected XSS: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` (~5.x)
- Open redirect (no chain): `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` (~3.x)

## HackerOne

```markdown
## Summary
[Bug class] in [component] on [domain] allows [actor] to [impact].

## Context
[Endpoint purpose, auth state, who reaches it.]

## Vulnerability Details
[2-3 sentences: root cause, affected component.]

## Steps to Reproduce (cold start)
1. [Auth step or "skip if unauth"]
2. [Exact request to URL with values]
3. [Observe: indicator]

## Proof of Concept Request
```http
METHOD /path HTTP/1.1
Host: target
[headers]

[body]
```

## Attack Walkthrough
1. Discovery: [how the issue is found]
2. Trigger: [exact payload / step]
3. Control: [what the attacker now controls]
4. Impact: [end outcome]

## Escalation Path
[Chain to ATO / RCE / lateral movement.]

## Impact
[What an attacker actually does — data, money, accounts.]

## Remediation
- [Concrete fix #1]
- [Concrete fix #2]

## Supporting Material / Evidence
[Logger indices, Collaborator ID, response excerpt.]

## References
- CWE-XXX
- OWASP A0X:2021-XXX
- CVSS 4.0: <vector>
- Severity: HIGH
```

H1 tips: use their severity taxonomy; reference program policy for scope; CWE required; remediation optional.

## Bugcrowd

```markdown
## Title
[Bug Class] in [Endpoint] — [Impact Summary]

## Context
[Endpoint purpose, auth state.]

## Description
[Root cause + affected component.]

## Proof of Concept
### Environment
- URL, Auth state, Browser/Tool

### PoC Request
```http
[HTTP request]
```

### Steps to Reproduce (cold start)
1. ...

### Expected vs Actual
- Expected: [secure handling]
- Actual: [observed exploit]

## Attack Walkthrough
[Discovery → trigger → control → impact.]

## Escalation Path
[Chain.]

## Impact Statement
[Business impact, scope of affected users.]

## Remediation
- ...

## CVSS 4.0
Vector: <vector>   |   Severity: HIGH
CWE: CWE-XXX
OWASP: A0X:2021-XXX

## Attachments / Evidence
[Raw req/resp pairs, screenshots, video.]

## References
- ...
```

Bugcrowd tips: VRT mapping is required; P1–P5 (P1=Critical); they prefer raw HTTP traffic.

## Intigriti

```markdown
## Vulnerability Type
[Their category]

## Domain/URL
https://target/path

## Context
[What this endpoint does.]

## Summary
[Brief.]

## Proof of Concept Request
```http
[HTTP request]
```

## Steps to Reproduce (cold start)
1. ...

## Attack Walkthrough
1. ...

## Escalation Path
[Chain.]

## Impact
[Outcome.]   Severity: HIGH

## Remediation
- ...

## CVSS 4.0
Vector: <vector>
CWE: CWE-XXX
OWASP: A0X:2021-XXX

## Proof / Evidence
[Req + resp.]

## References
- ...
```

Intigriti tips: heavy CVSS reliance; check disclosed reports for dupes; include both request and response.

## Immunefi (Web3 / DeFi)

```markdown
## Bug Description
[Technical description.]

## Context
[Protocol component, on-chain or off-chain.]

## Impact
[Funds at risk, governance, asset loss — quantify if possible.]

## Risk Breakdown
Difficulty: Easy/Medium/Hard
Severity: HIGH
CVSS 4.0: <vector>

## Proof of Concept
[Foundry/Hardhat test for smart contracts; HTTP req + steps for web frontend.]

## Steps to Reproduce
1. ...

## Attack Walkthrough
[End-to-end including any setup.]

## Escalation
[How this compounds across the protocol.]

## Recommendation / Remediation
- ...

## References
- ...
```

Immunefi tips: remediation REQUIRED; severity by funds at risk (Critical $10M+, High $1M+, Medium $100K+).

## Pipeline (use the MCP tools)

```
1. load_target_intel(domain, "findings")              # finding dict
2. load_target_intel(domain, "profile")               # tech context
3. get_request_detail(index=<poc_logger_index>)       # PoC req/resp
4. format_finding_for_platform(domain, finding_id, platform)
   # OR
   generate_report(domain, format="pentest", platform="")
```

## Quality Checklist

- [ ] Title: bug class + component + impact
- [ ] Cold-start reproduction <5 min
- [ ] No assumed knowledge
- [ ] Impact is specific, not "attacker can do bad things"
- [ ] CVSS 4.0 honest, not inflated
- [ ] Raw req + resp included
- [ ] No sensitive data leaked in screenshots
- [ ] Tested against current production
- [ ] Scope + excluded vuln-types double-checked against program policy
- [ ] One finding per report (or chain clearly labelled)

## Severity Inflation — DON'T

- Reflected XSS as "Critical" without an ATO chain
- "RCE from SQLi" claimed but only error-based proof
- Open redirect "High" without token-theft chain
- CORS misconfig "Critical" without proven data exfil
- "Could lead to" without proof it does
- Worst-case CVSS when PoC shows limited impact

## Cross-references

- **Finding lifecycle:** `verify-finding.md`
- **NEVER SUBMIT list + 7-Question Gate:** `.claude/rules/hunting.md`
- **Chain low-severity into high-severity:** `chain-findings.md`
- **CVSS 4.0 calculator:** https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator

## Per-vuln-class report skeletons (W16-W17 deep-dive companions)

The skeletons below pre-fill the canonical layout for each major class, matching the evidence ladders in the corresponding deep-dive playbook. Copy, fill the `<placeholders>`, submit.

### SSRF (per `playbook-ssrf-deep-dive.md`)

```
Title: SSRF in <component> allows attacker to <reach cloud metadata / internal service / bypass front-end ACL>

Classification:
  vuln_type: ssrf
  cwe: CWE-918
  owasp: A10:2021-Server-Side Request Forgery
  cvss4_vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N/E:A   # cloud-metadata class
  severity: Critical                                              # downgrade to High if internal-service only

Context:
  <Endpoint URL> accepts a user-controlled URL via parameter <name>.
  The server fetches that URL and reflects the response (or processes it server-side).

Vulnerability:
  No validation of scheme / host / IP literal allows a fetch to internal-only resources.
  Specifically, requests to <169.254.169.254 / 127.0.0.1 / RFC1918 / metadata.google.internal> succeed.

Attack Walkthrough:
  1. Identify the URL parameter <name>.
  2. Submit `<URL or bypass primitive>` (e.g. nip.io / IPv4-mapped IPv6 / octal).
  3. Server fetches and reflects `<AccessKeyId / instance-id / SSH banner / Redis -ERR>`.
  4. Use the leaked credentials / banner to <pivot / read PII / continue chain>.

Impact:
  <Specific outcome. For cloud metadata: AWS IAM creds → cross-service pivot.
   For internal: Redis flush / SSH probe / admin-panel reach.>

PoC request: <raw HTTP>
Reproduction steps: <cold-start 5-min recipe>
Evidence: logger_index #N, response excerpt with class marker, replay table for blind class
Remediation:
  - Allow-list scheme + host + resolved IP.
  - Block RFC1918 / link-local / loopback at the egress proxy.
  - IMDSv2 token requirement on AWS.
References: CWE-918, OWASP A10:2021, <vendor advisory if applicable>
```

### IDOR / BOLA (per `playbook-idor-bola.md`)

```
Title: BOLA in <endpoint> allows <role> to <read/modify> other users' <resource>

Classification:
  vuln_type: idor                                                   # or bola
  cwe: CWE-639 (IDOR) / CWE-285 (BOLA)
  owasp: OWASP API Security Top 10 (2023) API1:2023 — Broken Object Level Authorization
  cvss4_vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N/E:A
  severity: <Critical if PII/payment/health; High default; Medium for public-ish metadata>

Context:
  <GET /api/v1/orders/{id}> returns the order owned by the authenticated user.
  No server-side check confirms `request.user_id == order.owner_id`.

Vulnerability:
  Swapping <id> to a foreign value returns 200 with the foreign user's data.
  ID shape: <sequential / UUIDv1 / ULID / Snowflake / hash> — enumeration <feasible / requires harvest>.

Attack Walkthrough:
  1. Authenticate as user A; capture A's request.
  2. Note id parameter shape; harvest foreign IDs (or enumerate if sequential).
  3. Replay with B's id.
  4. Cross-principal verification: same response shape as A reading A's record.

Impact:
  <N foreign records observed in 5-minute window>. PII fields observed: <list redacted classes>.

PoC request: <raw HTTP with foreign id>
Reproduction steps: <cold-start with 2 accounts>
Evidence:
  - cross_principal_verified: True
  - id_shape: <sequential / uuidv1 / ulid / snowflake>
  - foreign_records_observed: <N>
  - logger_index: <foreign-record-read index>

Remediation:
  - Server-side ownership check on every object access.
  - Stop trusting the client-supplied id; derive from session principal.
  - Adopt opaque random IDs (UUIDv4) to disable enumeration as defence-in-depth.
References: CWE-639, CWE-285, OWASP API1:2023
```

### JWT (per `playbook-jwt-deep-dive.md`)

```
Title: JWT <alg confusion / kid traversal / weak HS secret / alg:none> allows ATO

Classification:
  vuln_type: jwt
  cwe: CWE-327 (broken crypto) / CWE-345 (insufficient verification)
  owasp: A2:2021-Cryptographic Failures
  cvss4_vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/E:A
  severity: Critical

Context:
  Target uses JWT for session auth (Bearer header on every authenticated request).
  Original token: alg=<RS256 | HS256 | ES256>, claims include <sub, role, exp, iss, aud, ...>.

Vulnerability:
  <Server accepts alg:none and skips signature.
   OR Server uses RS256 issuer pubkey as HMAC secret when alg=HS256 (alg confusion).
   OR Server loads HMAC key from kid path without traversal protection.
   OR HS256 secret is short / dictionary-crackable.>

Attack Walkthrough:
  1. Capture victim's JWT (or your own to clone the structure).
  2. Forge with `forge_jwt(attack='<alg_none|rs_to_hs|kid_traversal|claim_swap>', ...)`.
  3. Replay to `/me` / protected endpoint.
  4. Server returns victim's data (or grants admin role per swapped claim).

Impact: Full account takeover. Cross-tenant data exposure if multi-tenant.

PoC request: <raw HTTP with forged token>
Reproduction steps: <cold-start: capture token → forge → replay → assert 200 with victim data>
Evidence:
  - original_alg: <...>
  - forged_alg: <...>
  - attack: <alg_none | rs_to_hs | kid_traversal | claim_swap>
  - logger_index: <forge-accepted index>

Remediation:
  - Pin alg server-side; reject tokens whose alg != server's expected value.
  - Use library that separates JWS / JWE / JWT validation (e.g. jose, jjwt).
  - For RS256: never use pubkey as HMAC secret (validate signature algorithm before key lookup).
  - For kid: allow-list key IDs from a key registry; never use kid as filesystem path or SQL input.
References: CWE-327, CWE-345, CVE-2018-1000531 (RS-HS confusion class)
```

### OAuth / OIDC flow attacks (per `playbook-oauth-flow-attacks.md`)

```
Title: OAuth <redirect_uri bypass / missing state / PKCE downgrade / mix-up / JWKS swap> allows ATO

Classification:
  vuln_type: oauth
  cwe: CWE-601 (redirect) / CWE-352 (state CSRF) / CWE-345 (auth-server confusion)
  owasp: A1:2021-Broken Access Control
  cvss4_vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:A
  severity: Critical

Context:
  Authorization Server: <issuer>. Client: <client_id>. Flow: <Authorization Code / Code+PKCE / Device>.
  Reachable from: <web / mobile / SPA>.

Vulnerability:
  <Authorization server accepts redirect_uri `https://app.target.com.evil.com/callback` (suffix bypass).
   OR State parameter not validated on callback.
   OR PKCE code_verifier not enforced — server issues token without verifier match.
   OR Server fetches JWKS from issuer-controlled URL; attacker controls issuer.>

Attack Walkthrough:
  1. Lure victim to start OAuth flow with attacker-crafted authorize URL.
  2. <redirect_uri parser quirk leaks code to attacker / mix-up swaps issuer / PKCE drop / etc.>
  3. Attacker exchanges code at /token (or forges token via JWKS swap).
  4. Attacker authenticated as victim.

Impact: Full ATO across federated identity. Cross-tenant if multi-tenant SSO.

PoC: <full flow with curl + attacker-controlled redirect>
Reproduction steps: <cold-start: spin up Collaborator → craft authorize URL → victim clicks → code arrives>
Evidence:
  - flow_type: <authorization_code | pkce | device>
  - attack: <redirect_uri_suffix_bypass | missing_state | pkce_downgrade | mix_up | jwks_swap>
  - logger_index: <code-arrival index>
  - collaborator_interaction_id: <id>

Remediation:
  - Strict redirect_uri allow-list with exact match (no wildcards, no parser quirks).
  - State must be cryptographically random AND validated on every callback.
  - Enforce PKCE for public clients; reject token requests missing verifier.
  - Use the discovery document's `jwks_uri`, never derive from request-controlled `iss`.
References: CWE-601, RFC 6749 §10.6, OAuth 2.1 draft, OIDC Core §3.1.2.1
```

### HTTP Request Smuggling (per `playbook-request-smuggling.md`)

```
Title: HTTP Request Smuggling (<CL.TE | TE.CL | 0.CL | CL.0 | V-H | Expect | RQP | double-desync>) allows <bypass of front-end ACL / cache poisoning>

Classification:
  vuln_type: request_smuggling
  cwe: CWE-444 (HTTP Request/Response Smuggling)
  owasp: A1:2021-Broken Access Control (when used to bypass front-end ACL)
  cvss4_vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:N/E:A
  severity: Critical

Context:
  Front-end parser: <Akamai / Cloudflare / Fastly / nginx / haproxy / Envoy>.
  Origin parser: <nginx / Apache / IIS / Node.js / Spring>.
  Two-parser pipeline confirmed via <Via / X-Cache / CF-RAY / Server header divergence>.

Vulnerability:
  Frontend and origin disagree on request boundary due to <CL.TE | TE.CL | 0.CL | CL.0 | V-H | Expect | RQP>.
  Attacker can prefix bytes to the NEXT request seen by the origin.

Attack Walkthrough:
  1. Send smuggle payload (raw HTTP — see PoC).
  2. Frontend forwards N bytes to origin per its parser.
  3. Origin parses N + M bytes (M from attacker's smuggle prefix).
  4. Next request through the same connection is interpreted by origin starting at attacker's prefix.
  5. Demonstrated effect: <Collaborator callback / cache-poisoned URL with attacker payload / internal admin route reached>.

Impact:
  <Single victim: cache-poisoned URL serves attacker XSS to next visitor.
   Mass victims: shared front-end cache poisoned for all users of the same key.
   Internal reach: /admin reachable via smuggled request, bypassing front-end auth.>

PoC request: <raw HTTP with CRLF-exact byte stream>
Reproduction steps: <cold-start: open raw connection → send payload → observe behavior on second request>
Evidence:
  - variant: <CL.TE | TE.CL | 0.CL | CL.0 | V-H | Expect | RQP | double-desync>
  - front_parser: <vendor>
  - back_parser: <vendor>
  - collaborator_interaction_id: <id>
  - reproductions: 3 minimum (Rule 10a)
  - logger_index: <smuggle-confirming index>

Remediation:
  - Front-end and origin MUST agree on Content-Length / Transfer-Encoding parsing.
  - Reject ambiguous requests (both CL and TE present) at the front-end.
  - HTTP/2 termination at the front-end is the strategic mitigation (HTTP/1.1 desync endgame).
References: CWE-444, James Kettle 2025 "HTTP/1.1 Must Die" research, CVE-2025-32094 (Akamai class)
```

### Prototype Pollution (per `playbook-prototype-pollution.md`)

```
Title: <CSPP via URL fragment / SSPP via JSON merge> allows <DOM XSS / RCE / ATO>

Classification:
  vuln_type: <cspp | sspp>
  cwe: CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)
  owasp: A3:2021-Injection
  cvss4_vector_cspp: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N/E:A   # DOM XSS via CSPP gadget
  cvss4_vector_sspp: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A   # SSPP → RCE
  severity: <High for CSPP→XSS, Critical for SSPP→RCE/ATO>

Context:
  <Client-side: page merges URL fragment into options object via `_.merge` / `$.extend(true, ...)`.
   OR Server-side: /api/settings merges POST body into user record via `lodash.merge`.>

Vulnerability:
  No reserved-key filter (`__proto__`, `constructor.prototype`, `prototype`). Attacker pollutes the runtime prototype.
  Chained gadget: <DOMPurify ALLOWED_TAGS / Angular CSTI / Express isAdmin default / child_process.spawnSync default args / Handlebars compile options>.

Attack Walkthrough:
  1. Inject pollution payload via <fragment / query / JSON body>.
  2. Verify pollution propagated (canary check on follow-up request / DOM check via devtools).
  3. Trigger gadget: <load page that consumes default config / next request that reads default isAdmin / next exec call>.
  4. Observe exploitation: <script execution / admin response / shell command output / pwned>.

Impact:
  CSPP: DOM XSS in same-origin context. Account-cookie theft potential.
  SSPP: RCE in Node.js process, persists until process restart. Cross-user privilege escalation if web tier.

PoC request: <pollution payload + follow-up gadget trigger>
Reproduction steps: <cold-start: pollute → observe gadget>
Evidence:
  - polluted_key: <__proto__.ALLOWED_TAGS | __proto__.isAdmin | constructor.prototype.exec_argv>
  - gadget: <dompurify_allowed_tags | express_isadmin_default | childprocess_argv | handlebars_compileoptions>
  - sink: <innerHTML after DOMPurify.sanitize | role-check middleware | spawn call site>
  - impact_window: <single-page / single-tab / until process restart>
  - logger_index: <pollute-then-trigger index>

Remediation:
  - Reject reserved keys (`__proto__`, `constructor`, `prototype`) at the input boundary.
  - Freeze `Object.prototype` at startup (Node: `--frozen-intrinsics`).
  - Use `Object.create(null)` for user-derived objects.
  - For CSPP gadgets: configure DOMPurify with explicit config (not default-merged).
References: CWE-1321, CVE-2024-21509 (Express-Handlebars SSPP), Doyensec CSPP research
```

## Per-vuln-class report skeletons (W19-W20 deep-dive companions)

### Insecure Deserialization (per `playbook-deserialization.md`)

```
Title: <Java/.NET/Python/Ruby/PHP> insecure deserialization at <endpoint> allows RCE via <gadget chain>

Classification:
  vuln_type: deserialization
  cwe: CWE-502 (Deserialization of Untrusted Data)
  owasp: A8:2021-Software and Data Integrity Failures
  cvss4_vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A
  severity: Critical (unauth RCE) | High (post-auth RCE) | Medium (limited gadget)

Context:
  <Endpoint accepts a serialized object (cookie / form field / Base64 body / WebSocket frame).
   Stack: <Java + commons-collections | .NET + Json.NET TypeNameHandling=Auto | Python + pickle.loads |
   Ruby + Marshal.load | PHP + unserialize() | Node + node-serialize>.>

Vulnerability:
  Server deserializes attacker-controlled bytes into language-native objects without a
  type-allowlist. Combined with a gadget present in the dependency tree, this yields
  arbitrary code execution at the server tier.

Attack Walkthrough:
  1. Identify serialized format (magic bytes: Java `\xac\xed`, .NET `AAEAAAD/`, pickle `\x80`,
     PHP `O:N:` / `a:N:`, Ruby `\x04\x08`, Node-serialize `_$$ND_FUNC$$_`).
  2. Generate gadget — ysoserial / ysoserial.net / php-ggc / marshalsec / nodejsshell.py / pickle payload.
  3. Replace original blob with gadget; preserve encoding/wrapper (Base64 + URL-encode if applicable).
  4. Send to endpoint; observe OOB callback (Collaborator DNS / HTTP).
  5. Demonstrate RCE — `id` output via OS-command gadget or runtime-exec gadget.

Impact:
  Unauthenticated/authenticated RCE on the server (depending on endpoint reachability).
  Full pivot into internal network, cloud-metadata access, secret material exfil.

PoC request: <serialized gadget delivered in original parameter>
Reproduction steps: <cold-start: capture original request → swap blob → resend → observe callback>
Evidence:
  - serialization_format: <java-binary | dotnet-binaryformatter | python-pickle | php-serialize | ruby-marshal | node-serialize>
  - gadget_chain: <CommonsCollections6 | ObjectDataProvider | __reduce__ pickle | system gadget | _$$ND_FUNC$$_>
  - injection_point: <cookie name / form field / header / WebSocket frame index>
  - exec_marker: <Collaborator DNS hit / uid stdout from `id` / file-write at path>
  - logger_index: <RCE-confirming request>

Remediation:
  - Never deserialize untrusted input with native language deserializers; use JSON / Protobuf with strict schema.
  - If native deserialization is required: type-allowlist (`ObjectInputFilter` in Java, `JsonSerializerSettings.TypeNameHandling=None` in .NET, signed-only via HMAC, etc.).
  - Remove vulnerable gadget libraries when possible (commons-collections-safe builds, etc.).
References: CWE-502, ysoserial (frohoff), marshalsec (mbechler), `playbook-deserialization.md`
```

### SAML XSW (per `playbook-saml-xsw.md`)

```
Title: SAML XSW (XML Signature Wrapping) at <SP /acs endpoint> permits assertion swap → ATO as <user>

Classification:
  vuln_type: saml_xsw
  cwe: CWE-347 (Improper Verification of Cryptographic Signature)
  owasp: A2:2021-Cryptographic Failures
  cvss4_vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:N/E:A
  severity: Critical (auth-as-arbitrary-user) | High (auth-as-self-with-privileged-attrs)

Context:
  <SP /acs (Assertion Consumer Service) accepts SAML responses signed by the IdP.
   Library: <python-saml | OneLogin Ruby | passport-saml | OpenSAML | spring-security-saml | etc.>.
   Operator capture: a valid SAML Response from a normal login.>

Vulnerability:
  Signature verification anchored on a different XML node than the one the application reads
  attributes from. Attacker wraps the signed assertion and adds a sibling/child with new attributes;
  signature verifies on original, but app consumes the unsigned wrapper.

XSW Variants (per Hackmanit research):
  - XSW-1: clone signed assertion; modify clone's NameID; keep original to satisfy signature.
  - XSW-2/3: insert sibling assertion under Response root with attacker NameID.
  - XSW-7/8: wrap assertion inside Extensions or Object element to confuse XPath.

Attack Walkthrough:
  1. Capture a valid signed SAML Response from a real login (Burp → /acs POST body).
  2. Decode Base64; pretty-print XML; identify <ds:Signature> Reference URI.
  3. Apply XSW-N transform — duplicate or wrap the assertion; place attacker NameID in the
     unsigned copy; preserve signature on original copy.
  4. Re-encode; replay POST to /acs.
  5. SP returns session as the attacker-NameID user.

Impact:
  ATO as any SP-known user (including admins) — full identity assumption,
  bypass MFA enrolled at the IdP since SP trusts the (wrongly-located) assertion.

PoC request: <POST /acs with the wrapped SAMLResponse>
Reproduction steps: <cold-start: capture legit → transform via XSW tool → replay → observe session as victim>
Evidence:
  - xsw_variant: <XSW-1 | XSW-2 | ... | XSW-8>
  - signed_node_path: <XPath of node Reference URI points at>
  - consumed_node_path: <XPath of node application reads NameID from>
  - victim_nameid: <NameID swapped in>
  - resulting_session_user: <observed via /me or similar>
  - logger_index: <wrapped request that produced victim session>

Remediation:
  - Use a SAML library that pins signature verification to the SAME node attributes are read from.
  - Reject SAML Responses containing more than one assertion.
  - Anchor signature verification via `getElementById` lookups on the SIGNED ID, not XPath.
  - Validate `<saml:Conditions>` AudienceRestriction + NotBefore/NotOnOrAfter strictly.
References: CWE-347, Hackmanit "On Breaking SAML" 2012 / 2025 update, `playbook-saml-xsw.md`
```

### GraphQL (per `playbook-graphql-deep-dive.md`)

```
Title: GraphQL <introspection-disclosure | batched-bypass | _entities-cross-subgraph | subscription-auth-skip | depth-DoS> at <endpoint>

Classification:
  vuln_type: graphql
  cwe: <CWE-200 introspection | CWE-285 batched-bypass / federation | CWE-770 depth-DoS>
  owasp: A1:2021-Broken Access Control | A5:2021-Security Misconfiguration | A4:2021-Insecure Design
  cvss4_vector_authz: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:N/E:A   # cross-subgraph IDOR
  cvss4_vector_dos:   CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:A   # depth/alias DoS
  severity: <Critical for cross-tenant IDOR via _entities; High for unauth introspection; Medium for batched-rate-bypass>

Context:
  <GraphQL endpoint at /graphql or /api/graphql. Server: <Apollo Federation v1/v2 | Hasura | graphql-php | graphene | strawberry | etc.>.
   Operator capture: real auth'd query from the app's browser session.>

Vulnerability:
  <One or more of:>
  - Introspection enabled in prod — schema fully revealed to anonymous clients.
  - Batched queries / aliases bypass per-request rate-limits and per-field authz.
  - Apollo Federation `_entities(representations:[...])` exposes types from other subgraphs
    without per-resolver authz — cross-tenant IDOR.
  - GraphQL subscription protocol drift: graphql-ws auth-checked vs subscriptions-transport-ws not.
  - Unbounded query depth → DoS via deeply-nested `friends { friends { friends ... } }`.

Attack Walkthrough:
  1. Probe introspection: `query { __schema { types { name } } }` against /graphql.
  2. If federated: send `query { _entities(representations:[{__typename:"User",id:"<victim>"}]) { ... on User { email } } }`.
  3. Batch BOLA: 100 aliased queries each fetching `user(id: $i)` with sequential IDs.
  4. Subscription auth: open ws://... with graphql-transport-ws (legacy) subprotocol; no auth handshake.
  5. Depth DoS: send query nested 50+ levels deep; observe timeout / 5xx.

Impact:
  - Cross-tenant data leak via _entities (highest impact).
  - Mass enumeration via batched alias (medium-high).
  - Schema leak enables targeted attacks downstream (medium).
  - DoS for unbounded depth (medium, often NEVER_SUBMIT alone).

PoC request: <single query reproducing the issue>
Reproduction steps: <cold-start: send query → observe cross-tenant data / DoS / leaked schema>
Evidence:
  - subclass: <introspection_enabled | batched_authz_bypass | apollo_entities_cross_subgraph | ws_subprotocol_authskip | depth_dos>
  - victim_tenant_id: <if cross-tenant>
  - cross_data_field_leaked: <email / address / token / internal_id>
  - subprotocol_observed: <graphql-ws | graphql-transport-ws | subscriptions-transport-ws>
  - logger_index: <query/response showing the cross-tenant data>

Remediation:
  - Disable introspection in production (Apollo: `introspection: false`; graphene: `IntrospectionSchema`).
  - Enforce per-resolver authz (don't rely on route-level checks).
  - Apollo Federation: per-subgraph authz directives + `__resolveReference` checks.
  - Subscription: enforce identical auth handshake on BOTH ws subprotocols, or disable the legacy one.
  - Depth / cost-limit via `graphql-depth-limit` / `graphql-cost-analysis`.
References: CWE-200/285/770, Apollo Federation Security Best Practices, `playbook-graphql-deep-dive.md`
```

### WebSocket attacks (per `playbook-websocket-attacks.md`)

```
Title: WebSocket <CSWSH | per-message BOLA | subprotocol-bypass | JWT-via-WS-frame> at <ws://target/...>

Classification:
  vuln_type: <cswsh | websocket_bola | websocket_subprotocol | websocket_jwt_replay>
  cwe: <CWE-352 CSWSH | CWE-285 BOLA | CWE-345 frame-trust>
  owasp: A1:2021-Broken Access Control | A2:2021-Cryptographic Failures
  cvss4_vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:R/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N/E:A
  severity: <Critical for CSWSH that triggers state-change | High for per-message BOLA | Medium for subprotocol downgrade>

Context:
  <WS endpoint at ws(s)://target/<path>. Subprotocols offered: <list>.
   Authentication model: <Cookie + Origin check | JWT in connect query | JWT per-frame | none>.>

Vulnerability:
  <One or more of:>
  - CSWSH: server does not validate Origin on the upgrade handshake; cookie-auth means
    attacker page can open WS to target, perform state-changing ops as victim.
  - Per-message BOLA: connection established with user A's session, but each frame carries
    `target_user_id` which is not re-checked against the session.
  - Subprotocol fallback to a legacy protocol that skips auth (W18 graphql-ws vs subscriptions-transport-ws).
  - JWT carried per-frame; server caches first valid JWT and trusts all subsequent frames.

Attack Walkthrough:
  1. Establish baseline: legitimate WS handshake via Burp `websocket_connect`.
  2. CSWSH: replay handshake from attacker-Origin; observe 101 Switching Protocols.
  3. Per-frame BOLA: send legitimate frame with `target_user_id` swapped to victim ID.
  4. Subprotocol downgrade: connect with `Sec-WebSocket-Protocol: subscriptions-transport-ws`
     (legacy) and replay frames; observe missing auth check.

Impact:
  CSWSH → CSRF-equivalent via WebSocket for any state-changing op.
  Per-message BOLA → cross-user data read/write at the message layer (often unlogged).
  Subprotocol bypass → identical to BOLA + may bypass WAF that only inspects HTTP.

PoC request: <upgrade handshake + first malicious frame>
Reproduction steps: <cold-start: open WS → send malicious frame → observe cross-user effect>
Evidence:
  - ws_class: <cswsh | bola | subprotocol | jwt_replay>
  - origin_sent: <attacker.tld>
  - subprotocol_negotiated: <observed Sec-WebSocket-Protocol response>
  - victim_id_in_frame: <body of frame showing swapped ID>
  - frame_response: <cross-user data / state-change ack>
  - logger_index: <handshake + frame indices>

Remediation:
  - Enforce strict Origin allowlist on the upgrade handshake (return 403 otherwise).
  - Re-authorise EVERY frame against the session identity, not first-frame.
  - Disable legacy subprotocols (`subscriptions-transport-ws` etc.) once clients are migrated.
  - Bind WS session to a CSRF-style nonce that the page must inject into the first frame.
References: CWE-352/285/345, OWASP WebSocket Security Cheat Sheet, `playbook-websocket-attacks.md`
```

### Web Cache Deception (per `playbook-cache-deception.md`)

```
Title: Web Cache Deception via <static-suffix .css | path-normalisation .json | vendor-specific Cloudflare .json> caches victim PII at attacker-readable URL

Classification:
  vuln_type: web_cache_deception
  cwe: CWE-525 (Information Exposure Through Browser Caching) / CWE-200
  owasp: A1:2021-Broken Access Control
  cvss4_vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N/E:A
  severity: Critical (PII/PCI/tokens leaked) | High (session metadata) | Medium (path-normalisation w/o observed leak)

Context:
  <Target behind CDN: <Cloudflare | Akamai | Fastly | Varnish | CloudFront>.
   Authenticated endpoint: <e.g. /profile, /api/me, /dashboard> returns user-specific
   content with Cache-Control: private.>

Vulnerability:
  CDN treats `<dynamic-path>/<static-suffix>` as cacheable (file extension rule); origin
  normalises the path back to the dynamic endpoint and returns the authenticated content.
  Cached response is served to anyone who fetches the same suffix-URL.

Attack Walkthrough:
  1. Auth as victim (operator's own test account).
  2. Fetch `<auth-endpoint>/x.css` (or `.json`, `.png`, `.svg`, vendor-specific suffix).
  3. Origin returns 200 + victim's data; CDN caches.
  4. From an unauthenticated context (different IP / browser / curl with no cookies):
     fetch the same URL.
  5. Receive victim's data + `X-Cache: HIT` / `Age: > 0`.

Impact:
  Authenticated PII (email, address), payment metadata, session tokens, internal IDs
  exposed to any attacker who can guess (or have the victim visit) the suffix-URL.

PoC request: <victim-cookied fetch of /<auth-endpoint>/x.css then unauth fetch of same URL>
Reproduction steps: <cold-start: auth → fetch suffix → wait → unauth re-fetch → observe leak + X-Cache: HIT>
Evidence:
  - cdn: <Cloudflare | Akamai | Fastly | Varnish | CloudFront>
  - suffix_variant: <.css | .js | .json | .png | .svg | .woff | path-traversal>
  - cache_control_observed: <max-age=N | public | no-cache>
  - x_cache_header: <HIT | cf-cache-status: HIT | X-Served-By cache hit>
  - leaked_field_classes: <PII (email, name) / payment / session token / internal ID>
  - victim_indicators: <victim user_id observed in cached response>
  - logger_index: <unauth-fetch index that returned victim data>

Remediation:
  - Add `Cache-Control: no-store, private` to ALL authenticated dynamic responses.
  - Configure CDN to honour origin Cache-Control (no rule-override on extension).
  - Strip / 404 unrecognised path segments before cache key computation.
  - Use `Vary: Cookie` strictly + ensure cache key includes session cookie.
References: CWE-525, Omer Gil "Web Cache Deception" (2017), Kettle 2025 updates, `playbook-cache-deception.md`
```

### Server Action / RSC (per `playbook-server-action-rsc.md`)

```
Title: Next.js Server Action ID exposure → <admin action invocation | RSC payload PII leak> (CVE-2025-55182 / CVE-2025-66478 class)

Classification:
  vuln_type: <server_action_authz_bypass | rsc_payload_leak | server_action_arg_tampering>
  cwe: <CWE-285 missing-per-action-authz | CWE-200 prop-disclosure | CWE-639 arg-tampering>
  owasp: A1:2021-Broken Access Control
  cvss4_vector_authz: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A   # admin action via leaked ID
  cvss4_vector_leak:  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N/E:A   # RSC prop leak
  severity: Critical (admin action invocable) | High (RSC PII leak / arg tampering)

Context:
  <Next.js 13+ (App Router) / 14 / 15. Server Actions invoked via `Next-Action: <id>` POST.
   Vulnerable surface: Action ID embedded in bundled JS or `data-action-id`.>

Vulnerability:
  <One or more of:>
  - Server Action ID leaked in bundled chunks / HTML; ID is route-independent so POST to
    any page + `Next-Action: <admin_id>` invokes the admin action without route authz.
  - RSC payload (Content-Type: text/x-component) serialises every prop including PII
    that the rendered HTML wouldn't show.
  - Server Action arguments deserialised and trusted — IDOR via swapped `user_id` / `role`.
  - GET coercion: `?_rsc=1` triggers action invocation, bypassing POST-only CSRF.

Attack Walkthrough:
  1. Fingerprint Next.js version (`Server:`, `X-Powered-By`, `_next/static/`).
  2. Grep bundles for `data-action-id=` or `Next-Action:` references → harvest IDs.
  3. POST to any page with `Next-Action: <leaked_admin_action_id>` and serialised arg list.
  4. Server executes the admin action regardless of route — observe state change /
     admin-only data in response.
  5. (Or) Fetch `<page>?_rsc=1` with `Accept: text/x-component`; parse for leaked props.

Impact:
  Privilege escalation via admin action invocation from non-admin page.
  Cross-user PII leak via RSC payload.
  Arg-tampering allows role / amount / target-ID mutation in trusted server actions.

PoC request: <POST /<any-page> with `Next-Action: <admin_id>` + serialised args>
Reproduction steps: <cold-start: harvest action ID from bundles → invoke from non-admin route → observe admin effect>
Evidence:
  - next_version: <observed Next.js version>
  - action_id: <leaked Server Action ID>
  - action_purpose: <delete_user | promote_role | etc.>
  - invoked_from_route: <non-admin page used as POST target>
  - effect_observed: <state change / admin response / cross-user data>
  - cve: <CVE-2025-55182 | CVE-2025-66478 | per-app class>
  - logger_index: <bypass-confirming request>

Remediation:
  - Enforce per-action authz INSIDE every Server Action body, not via route protection.
  - Treat Server Action arguments as untrusted; re-validate `user_id` / `role` against session.
  - Upgrade to Next.js ≥ 15.0.3 (Action ID now bound to route pattern).
  - Audit RSC payloads — never pass secret props into server components.
References: CWE-285/200/639, CVE-2025-55182, CVE-2025-66478, `playbook-server-action-rsc.md`
```

## Quick-pick reference

When in doubt, the deep-dive playbook tells you which skeleton to use:

| Finding class | Skeleton above | Deep-dive |
|---|---|---|
| SSRF | "SSRF" | `playbook-ssrf-deep-dive.md` |
| IDOR / BOLA | "IDOR / BOLA" | `playbook-idor-bola.md` |
| JWT | "JWT" | `playbook-jwt-deep-dive.md` |
| OAuth / OIDC | "OAuth / OIDC flow attacks" | `playbook-oauth-flow-attacks.md` |
| Request smuggling | "HTTP Request Smuggling" | `playbook-request-smuggling.md` |
| Prototype pollution | "Prototype Pollution" | `playbook-prototype-pollution.md` |
| Deserialization | "Insecure Deserialization" | `playbook-deserialization.md` |
| SAML XSW | "SAML XSW" | `playbook-saml-xsw.md` |
| GraphQL | "GraphQL" | `playbook-graphql-deep-dive.md` |
| WebSocket | "WebSocket attacks" | `playbook-websocket-attacks.md` |
| Web Cache Deception | "Web Cache Deception" | `playbook-cache-deception.md` |
| Server Action / RSC | "Server Action / RSC" | `playbook-server-action-rsc.md` |
| Other | Canonical layout above | `hunt.md` / `verify-finding.md` |
