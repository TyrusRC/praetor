---
name: security-research
description: Deep-dive a suspicious finding by mining disclosed reports, writeups, and class-specific obscure vectors. Use when an anomaly might be exploitable but you don't yet see the chain.
prerequisite: At least one of — a confirmed anomaly (status/length/timing delta vs baseline), a versioned tech-stack fingerprint, OR an open-ended "what would an attacker want here?" question on a high-value endpoint.
stop_condition: 6 web-fetches + 2 testable MCP probes without producing a reproducer or a new hypothesis worth chasing → return to router. Research is a means to an attack, not a substitute for one.
---

# Security Research Skill

Operationalize Rule 27's 20%-creative-hunting mandate. Instead of "let me Google something", run `research_attack_vector` once to get a curated bundle, WebFetch the high-signal URLs, and convert what you learn into ONE testable MCP probe.

## When To Invoke

| Trigger | Use research? |
|---|---|
| `auto_probe` returned score 30-60 (ambiguous) | YES — load class-specific obscure vectors |
| Fingerprinted a specific framework + version | YES — check disclosed CVEs + recent writeups |
| High-value endpoint (auth / payment / admin / file upload) with no obvious bug yet | YES — pull "what would an attacker want here?" prompts |
| Confirmed bug, want to escalate severity | YES — load chain hypotheses |
| `auto_probe` confidence ≥ 80 + clear PoC | NO — go straight to `assess_finding` |
| Pre-recon (no fingerprint yet) | NO — run `full_recon` first |

## The One Call

```python
research_attack_vector(
    vuln_type="ssrf",                              # required
    tech_stack="express,redis",                    # narrows code-search + CVE queries
    finding_summary="Image-proxy /api/preview?url= fetches arbitrary URLs",
    endpoint="/api/preview",
    target_domain="target.com",
)
```

You get back seven sections. Triage them in this order:

```
1. DEEP-DIVE QUESTIONS   →  pick the question your finding doesn't yet answer
2. OBSCURE VECTORS       →  pick ONE you haven't tested
3. CHAIN HYPOTHESES      →  bank these for after you confirm the primitive
4. METHODOLOGY DEEP-LINKS→  WebFetch — verified-static PortSwigger Academy + HackTricks + PAYLOADs + OWASP WSTG
5. SUGGESTED WEB SEARCHES→  WebSearch — disclosed reports / writeups / tech-specific bypass
6. ADVISORY DATABASES    →  WebFetch — Exploit-DB / OSV / GH Advisory / Snyk DB / AttackerKB
7. GITHUB CODE SEARCH    →  WebFetch — sink-pattern hunt in similar codebases
```

**Why two output modes?** Some sources return rich content to a plain curl (PortSwigger Academy, HackTricks, OWASP WSTG, Exploit-DB, OSV) — those go in the WebFetch sections. Others are JS-rendered SPAs (HackerOne hacktivity), Cloudflare-blocked (NCC, CISA KEV), or 403 to bots (OpenBugBounty) — those go in the WebSearch section because search engines crawl them and return excerpts that Claude can see.

## The Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│ Anomaly observed → research_attack_vector(vuln_type, ...)       │
│                                                                 │
│ FREE (no fetch): read DEEP-DIVE + OBSCURE + CHAIN inline        │
│   → pick ONE hypothesis you haven't tested                      │
│                                                                 │
│ WebFetch METHODOLOGY DEEP-LINKS (PortSwigger Academy + HackTricks)│
│   → class methodology + canonical payload patterns              │
│                                                                 │
│ WebSearch SUGGESTED queries (top 2-3)                           │
│   → disclosed reports, writeups, tech-specific CVEs             │
│   → look for: exact tech match / similar param / same chain     │
│                                                                 │
│ Optional: WebFetch 1-2 ADVISORY DBs if tech_stack is versioned  │
│   → Exploit-DB / OSV / Snyk DB for known CVEs + PoCs            │
│                                                                 │
│ If a writeup or PoC shows a working pattern:                    │
│   → ADAPT, don't copy — match to your target                    │
│   → craft_payload skill if needed                               │
│                                                                 │
│ Build ONE testable probe — auto_probe / test_* / curl_request   │
│   → measured against the recorded baseline (Rule 11)            │
│   → through Burp (Rule 26a — never raw requests/httpx)          │
│                                                                 │
│ Outcome:                                                        │
│   PASS  → assess_finding → save_finding (with chain_with[])     │
│   FAIL  → did you exhaust DEEP-DIVE questions?                  │
│           YES → return to router, this isn't the vuln           │
│           NO  → cycle one more time                             │
└─────────────────────────────────────────────────────────────────┘
```

## What the Bundle Output Means

**DEEP-DIVE QUESTIONS** — open-ended "you should know this" prompts. NOT a checklist to mechanically complete. Pick the one you HAVEN'T thought about.

**OBSCURE VECTORS** — actually-missed-in-practice attack surfaces. These are what experienced researchers see that auto_probe doesn't. Weighted toward bug-bounty disclosed-report patterns.

**CHAIN HYPOTHESES** — what the primitive ENABLES. Crucial for severity:
- Reflected XSS alone = MEDIUM
- XSS → CSRF email-change → ATO = CRITICAL

The same primitive, two different reports, two different bounties.

**METHODOLOGY DEEP-LINKS** — direct WebFetch URLs to verified-static-HTML reference pages:
- **PortSwigger Web Security Academy** — class methodology, labs, payload taxonomy.
- **HackTricks book** — technique-by-technique reference with engine-specific gadgets.
- **PayloadsAllTheThings** — curated payload archive per class.
- **OWASP WSTG** — official testing methodology with evidence requirements.

Always WebFetch these first — they're stable, content-rich, and dodge the bot-block trap.

**SUGGESTED WEB SEARCHES** — pre-baked queries for Claude's native `WebSearch` tool. We don't link directly to HackerOne hacktivity / Bugcrowd Crowdstream / OpenBugBounty because those are JS-SPA / Cloudflare-blocked. Search engines crawl them — we get content via `site:hackerone.com/reports` + `site:pentester.land` + `site:portswigger.net/research` filters, plus tech-specific CVE/bypass keyword searches.

Run 2-3 of the highest-relevance queries. WebSearch returns synthesized excerpts; if one looks promising, WebFetch the specific URL it cites.

**ADVISORY DATABASES** — direct WebFetch URLs to server-rendered vulnerability databases (all verified to return rich content, not JS shells):
- **Exploit-DB** — historical PoC archive.
- **OSV.dev** — Google's open-source vuln database.
- **GitHub Advisory Database** — high-quality, well-tagged.
- **Snyk Vulnerability DB** — commercial-grade tracking.
- **Rapid7 AttackerKB** — "exploited in the wild" intel for severity assessment.

Most useful when `tech_stack` is supplied — these databases index by package name.

**GITHUB CODE SEARCH** — for when you suspect a known vulnerable code pattern. The search URL pre-builds `findByPk req.params.id`, `Object.assign req.body`, `render_template_string request`, etc. WebFetch to see the sink shape in similar codebases.

## Adapting Disclosed PoCs

When a HackerOne disclosed report has a PoC payload that looks relevant:

1. **Confirm the primitive matches your context.** Same engine? Same auth state? Same content-type?
2. **Strip the destructive parts.** Disclosed PoCs sometimes include `; DROP TABLE` — replace with detection-only (`SLEEP(5)`, math expression, Collaborator callback) per Rule 5.
3. **Match the marker convention.** Use a unique per-call marker like the native `test_*` orchestrators do — easy to spot in baseline diff.
4. **Send through Burp.** Never via raw `requests`/`httpx` script (Rule 26a). Use `curl_request` / `auto_probe` / `test_*` / `session_request`.

## Source Patch-Diffing (when you hold source of both versions)

`adapt_poc_to_version` reasons about a fix from version *numbers* alone — the axes
that break a cross-version PoC, and whether the target is likely patched. When you
can actually **fetch the source of both the vulnerable and the fixed release**, stop
reasoning about the delta and read it. The security-relevant commit *is* the
advisory, in code.

Use this when: an advisory names a fixed version AND the project is open-source (or
you hold both release tarballs / a monorepo the SOW gave you). The patch is the
ground truth `adapt_poc_to_version` approximates.

### Locate the fix

```bash
# Tag-to-tag when the vendor tagged releases.
git clone --filter=blob:none https://github.com/vendor/product /tmp/prod && cd /tmp/prod
git log --oneline v1.4.2..v1.4.3                       # commits between vuln and fix
git diff v1.4.2 v1.4.3 -- src/                         # full delta, scoped to source

# No tags? diff two release tarballs.
diff -ruN product-1.4.2/ product-1.4.3/ | less

# CVE references a commit/PR? go straight to it.
git show <commit_sha>
```

Narrow the diff to the **security-relevant** change — noise (version bumps,
changelog, tests, formatting) is not it. The fix is almost always one of:

| Fix shape | What it tells you about the trigger |
|---|---|
| Added input **validation** (regex, allow-list, type check, length cap) | the input that *fails* the new check is the trigger |
| New **sanitizer / encoder** call wrapping a sink | the sink took raw input before — feed it the pre-sanitiser payload |
| Added **authz / auth** check (role, ownership, token) | the path was reachable without it — replay from the lower-priv state |
| **Bounds / integer** check before an index/alloc | the out-of-range value the check now rejects |
| Parameterised query replacing string concat | classic SQLi — the concatenated param is injectable pre-fix |
| Disabled a **parser feature** (DTD, `TypeNameHandling`, `resolve_entities`) | XXE / deserialization — the feature was on pre-fix |
| Removed a **debug / dev** branch or endpoint | that endpoint was the exposure |

### Reverse the diff into a trigger

The added check defines exactly what input it was added to *stop*. Construct that
input:

```
git shows:  if (!/^[a-z0-9_]+$/.test(sortKey)) throw new BadRequest();   # added in fix
reverse  →  sortKey that contains something OUTSIDE [a-z0-9_]  →  ' OR SLEEP(5)--
```

```
git shows:  entity.setOwner(currentUser); assertOwns(currentUser, id);   # added in fix
reverse  →  request the resource by id from a DIFFERENT user's session   →  IDOR
```

Then confirm against the **live** target through Burp — the deployed build may be a
different patch level than either release you diffed, so the source is the hypothesis
and the live confirm is the proof (per `verify-finding.md` / Rule 10). If the target
holds the *first-party* source too, hand off to `playbook-source-review.md` Step 5 to
trace the pre-patch sink and fire the matched `confirm_*`.

**Pair with `adapt_poc_to_version`:** run it first for the version verdict and the
adaptation axes (`LIKELY_PATCHED` → don't bother diffing this one), then diff to turn
the axes into a concrete byte-level trigger. Numbers say *whether*; the diff says
*what*.

## Anti-Patterns (do NOT do)

- **Don't fetch every URL in the bundle.** Budget: 2 WebFetches + 2-3 WebSearches per cycle. Over-research is the failure mode.
- **Don't paste disclosed-report payloads verbatim.** Programs reject "copy of public bug" reports. Adapt to your target's exact context.
- **Don't research a class you haven't even attempted to probe.** Always probe → observe → research → re-probe. Reversing this produces "could be X" reports without evidence.
- **Don't ignore CHAIN HYPOTHESES.** If your bug alone caps at MEDIUM, the chain section tells you whether the program pays the chain — sometimes the same bug becomes CRITICAL on a different chain target.
- **Don't skip the inline KB.** DEEP-DIVE + OBSCURE + CHAIN come for free in the tool's reply — read these BEFORE any fetch or search.
- **Don't WebFetch JS-SPA URLs directly.** If a section says "WebSearch" (not "WebFetch"), pipe through WebSearch — the underlying source needs search-engine rendering to be readable.

## Integration With Other Skills

- `craft-payload.md` — research_attack_vector says "try gopher://", craft-payload tells you the exact byte-for-byte gadget.
- `verify-finding.md` — once research produces a reproducer, run it through the 7-question gate.
- `chain-findings.md` — CHAIN HYPOTHESES output feeds directly into chain construction.
- `playbook-cve-research.md` — research_attack_vector with `tech_stack=` overlaps with the CVE playbook. If the bundle's `map_tech_to_cves` suggestion produces a hit, switch to that playbook.

## Token Discipline

- Inline KB (DEEP-DIVE + OBSCURE + CHAIN) is free — comes back in one tool call.
- Each WebFetch costs ~1-3K tokens for the fetched page. Budget 2-3 fetches per research cycle.
- If you're 6+ fetches deep without a hypothesis, you've over-researched. Return to the router and pick a different target.

## Quick Examples

**Example 1 — Ambiguous SSRF anomaly**
```
auto_probe → score=42 on ?url= param. Status delta but no error reflected.

research_attack_vector(vuln_type="ssrf", tech_stack="node,express",
                      finding_summary="image-proxy with allowlist that accepts http://target.com.evil.com")
→ OBSCURE: "Webhook URL acceptance — slack/discord-style integration endpoints often SSRF"
→ DEEP-DIVE: "DNS rebinding — does the app re-resolve between check and use?"
→ DISCLOSED: WebFetch top H1 result on Express SSRF allowlist bypass

Adapted hypothesis: try DNS-rebinding TTL=0 host.
→ test_ssrf(url=..., probes=['dns_rebind']) → confirm.
```

**Example 2 — Versioned Spring Boot found**
```
detect_tech_stack → Spring Boot 2.6.6 confirmed.

research_attack_vector(vuln_type="ssti", tech_stack="spring-boot",
                      finding_summary="Spring Boot 2.6.6 with Thymeleaf 3.0.15")
→ CHAIN: "SSTI → cloud metadata read → temp creds → wider compromise"
→ OBSCURE: "Spring Thymeleaf Spring EL preprocessing __${...}__::.x syntax"
→ DISCLOSED: H1 search for Thymeleaf SpEL preprocessing
→ map_tech_to_cves suggested → run that next

Adapted: test_ssti(endpoint=..., parameter=..., engine_hint='spring_el') → confirm.
```

**Example 3 — High-value endpoint, no bug yet**
```
Found /api/admin/migrate accepting POST with JSON body. Auth required but no
obvious vuln. What now?

research_attack_vector(vuln_type="auth_bypass", tech_stack="django",
                      endpoint="/api/admin/migrate")
→ DEEP-DIVE: "Header smuggling: X-Original-URL / X-Rewrite-URL"
→ OBSCURE: "Method confusion: GET protected but HEAD/OPTIONS/PROPFIND not"
→ CHAIN: "Header smuggling → admin panel → ATO of all users"

Adapted: try X-Original-URL: /api/admin/migrate from a low-priv session.
→ test_login_bypass(target=..., paths=['/api/admin/migrate']) → confirm.
```
