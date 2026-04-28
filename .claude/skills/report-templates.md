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
