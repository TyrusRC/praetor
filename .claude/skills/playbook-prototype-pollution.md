---
description: Prototype pollution — CSPP (client) vs SSPP (server). Express / Fastify / Hapi sinks. CSPP→DOM XSS. SSPP→RCE / auth bypass. Load when JSON body merges + nested objects are accepted.
globs:
---

# Prototype Pollution Deep-Dive

Load when: target accepts JSON bodies that get merged into objects (settings update, config endpoint, mass-update), OR has client-side options-merge libraries (jQuery extend, lodash merge), OR runs Node.js (Express / Fastify / Hapi / Koa / NestJS).

## CSPP vs SSPP

The class splits cleanly. Different tools, different evidence, different impact.

| Variant | Where | Impact | Detection |
|---|---|---|---|
| **CSPP** (Client-Side Prototype Pollution) | Browser JS — `Object.prototype` polluted via URL fragment / query / JSON parse | DOM XSS via gadget reflection | `test_dom_sinks(url, fragment_shapes=[...], cspp_known_keys=[...])` (W9) |
| **SSPP** (Server-Side Prototype Pollution) | Node.js process — `Object.prototype` polluted via JSON body merge | RCE (childProcess) / auth bypass (isAdmin defaults) | `test_prototype_pollution(url, body)` (W11) |

## CSPP

### Detection

1. **Identify merge sites** — view-source for libraries that merge user input:
   - `$.extend(true, target, source)` (jQuery deep extend)
   - `_.merge(target, source)` (lodash)
   - `Object.assign(target, ...sources)` (vanilla, no recursion → low risk)
   - `mergeWith` / `defaultsDeep` (lodash variants)
2. **Identify input source** — URL fragment (`#`), query (`?`), JSON parse of body, `JSON.parse(window.name)`, postMessage handler.
3. **Inject canary** — `?__proto__[praetorCanary]=1` or fragment `#/route?__proto__[praetorCanary]=1`.
4. **Verify pollution** — open devtools console: `Object.prototype.praetorCanary` should be `1`.

### Gadgets (CSPP → DOM XSS)

Many libraries lookup-on-demand from prototype. Common gadgets:

- **AngularJS** (`{{ }}`): pollute `Object.prototype.constructor.constructor` → CSTI → XSS.
- **Vue 2**: pollute `Object.prototype.template` → component template injection.
- **DOMPurify with config object**: pollute `Object.prototype.ALLOWED_TAGS` to include `<script>`.
- **Trusted Types policies**: pollute `Object.prototype.createScript` → bypass policy.
- **React** (rare): pollute `Object.prototype.dangerouslySetInnerHTML`.

### Tool

`test_dom_sinks(url, source_kinds=['fragment','fragment_kv','query'], cspp_known_keys=['praetorCanary','isAdmin','ALLOWED_TAGS','toString'])` — DOM probe (W9 VerdictResult). Reports which sinks reflect the canary AND whether prototype pollution propagated to known gadgets.

## SSPP

### Detection

1. **Identify merge endpoints** — settings update, profile update, options endpoint that accepts JSON.
2. **Submit canary** — `POST /api/settings` with body `{"__proto__":{"praetorCanary":"polluted"}}`.
3. **Verify pollution** — second request to a different endpoint that reads a default value. If the read returns `"polluted"`, prototype is polluted across requests.

### Gadgets (SSPP → RCE / Auth Bypass / DoS)

| Sink | Pollute | Impact |
|---|---|---|
| `child_process.spawnSync(cmd)` default args | `Object.prototype.shell = '/bin/sh'; Object.prototype.argv0 = '...'` | RCE on any spawn call |
| `Object.prototype.NODE_OPTIONS = '--require /tmp/x.js'` | When Node forks a subprocess | RCE on next fork |
| `Object.prototype.exec_argv = ['--inspect-brk=0.0.0.0:1337']` | Same; remote debugger | RCE |
| Express auth middleware `req.user.isAdmin` default | `Object.prototype.isAdmin = true` | Auth bypass (every user becomes admin) |
| Handlebars compile options | `Object.prototype.compilerOptions = {...}` | Template injection → SSTI → RCE |
| Express body-parser limits | `Object.prototype.limit = 0` | DoS via memory blowup |
| JWT validation libraries | `Object.prototype.algorithms = ['none']` | JWT alg:none accepted (chain with jwt playbook) |

### Tool

`test_prototype_pollution(url, body=..., follow_up_path='/api/me')` (W11 VerdictResult):
- Sends pollution canary (`__proto__`, `constructor.prototype`, `__proto__.x`).
- Then fetches `follow_up_path` and looks for canary reflection.
- CONFIRMED when canary appears in follow-up response.

Active KB context `prototype_pollution.express_handlebars_sspp` (W8) covers Express + Handlebars compile-options chain (CVE-2024-21509 class).

## Evidence ladder

| Verdict | Evidence shape | Save? |
|---|---|---|
| **CONFIRMED CRITICAL** | SSPP demonstrated → gadget executed (RCE marker / auth bypass observed / privesc) | yes |
| **CONFIRMED HIGH** | SSPP pollution canary reflected in follow-up but no gadget chained yet | yes (with gadget hypothesis) |
| **CONFIRMED HIGH** | CSPP → DOM XSS via known gadget (Angular CSTI / DOMPurify ALLOWED_TAGS) | yes |
| **SUSPECTED** | Pollution accepted but no follow-up reflection; investigate gadget chain | NO save |
| **FAILED** | Pollution rejected | NO |

## Severity discipline

- SSPP + RCE gadget chained = CRITICAL.
- SSPP + auth bypass chained = CRITICAL.
- SSPP pollution accepted but no gadget yet = MEDIUM (operator chain it before submit).
- CSPP + DOM XSS via known gadget = HIGH.
- CSPP pollution-only without gadget execution = LOW (informational).

## NEVER_SUBMIT traps

- Pollution that only affects a per-request scoped object (e.g. polluting then immediately freezing).
- CSPP via `Object.create(null)` targets — these objects don't inherit, pollution irrelevant.
- "User can submit `__proto__` in body" — without a follow-up that uses default values, no impact.

## save_finding shape

### CSPP

```python
save_finding(
    vuln_type="cspp",
    endpoint="https://app.target.com/#/route",
    parameter="__proto__[ALLOWED_TAGS]",
    severity="high",
    evidence={
        "logger_index": <dom-fire index>,
        "summary": "CSPP via URL fragment → DOMPurify ALLOWED_TAGS pollution → <script> tag survives sanitization → DOM XSS",
        "gadget": "dompurify_allowed_tags",
        "sink": "innerHTML after DOMPurify.sanitize",
    },
)
```

### SSPP

```python
save_finding(
    vuln_type="sspp",
    endpoint="https://api.target.com/v1/settings",
    parameter="__proto__.isAdmin",
    severity="critical",
    evidence={
        "logger_index": <pollute index>,
        "summary": "SSPP via Express body-parser merge → Object.prototype.isAdmin = true → subsequent GET /me returns admin=true for unauthenticated users → privilege escalation across all sessions until process restart",
        "follow_up_logger_index": <verification index>,
        "gadget": "express_isadmin_default",
        "impact_window": "until process restart",
    },
)
```

## Chain patterns

- **CSPP → DOM XSS** = direct.
- **CSPP → DOM XSS → CSRF token theft → ATO** = chain to ATO.
- **SSPP → isAdmin pollution → ATO** = direct.
- **SSPP → exec_argv pollution → RCE** = direct.
- **SSPP → JWT algorithms pollution → alg:none accepted → ATO via forged JWT** = chain to JWT playbook.
- **Prototype pollution at registration → pollution survives across requests** = stateful — note "impact_window: until process restart".

## Related

- `knowledge/prototype_pollution.json` — Express / Fastify / Hapi SSPP black-box contexts + W8 Express-Handlebars SSPP CVE-2024-21509 class
- `knowledge/cspp.json` — client-side dedicated KB
- `knowledge/dom_clobbering.json` / `dom_clobbering_2024.json` — DOM-side adjacent class
- `test_prototype_pollution` (W11) + `test_dom_sinks` (W9) — VerdictResult-returning probes
- `playbook-jwt-deep-dive.md` — chain when JWT validator pollution succeeds
- `chain-findings.md` — `proto_pollution_to_dom_xss` and `cspp_to_sspp` progressions
