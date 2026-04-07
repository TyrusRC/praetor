---
name: report-templates
description: Generate platform-specific vulnerability reports for HackerOne, Bugcrowd, Intigriti, and Immunefi
---

# Report Templates

Generate professional bug bounty reports optimized for each platform. Reports must be evidence-driven, impact-focused, and follow the platform's preferred format.

## Universal Report Rules

1. **Title formula:** `[Bug Class] in [Component/Endpoint] allows [actor] to [impact]`
   - Good: "Stored XSS in comment field allows authenticated user to steal admin session"
   - Bad: "XSS vulnerability found" / "Security issue in application"

2. **Impact-first:** Lead with what the attacker can DO, not how the bug works
3. **Under 600 words** for the main body — triagers read hundreds of reports
4. **Human tone:** Write like a skilled researcher, not an AI. Avoid "I discovered", "upon further analysis"
5. **Reproduction must work** in under 5 minutes from a cold start
6. **One finding per report** — don't bundle unless it's a chain
7. **CVSS 3.1 required** — calculate honestly, don't inflate

## CVSS 3.1 Quick Reference

| Vector | Values | Notes |
|---|---|---|
| Attack Vector (AV) | N=Network, A=Adjacent, L=Local, P=Physical | Most web vulns = Network |
| Attack Complexity (AC) | L=Low, H=High | High if needs race condition or specific config |
| Privileges Required (PR) | N=None, L=Low, H=High | None = unauthenticated, Low = any user, High = admin |
| User Interaction (UI) | N=None, R=Required | XSS/CSRF = Required, IDOR/SQLi = None |
| Scope (S) | U=Unchanged, C=Changed | Changed if affects other components (XSS, SSRF) |
| Confidentiality (C) | N/L/H | H = all data, L = some data, N = none |
| Integrity (I) | N/L/H | H = full modification, L = some, N = none |
| Availability (A) | N/L/H | H = full DoS, L = degraded, N = none |

**Common scores:**
- RCE: CVSS 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- SQLi (data extraction): CVSS 8.6-9.1
- Stored XSS (admin): CVSS 8.1-8.7
- IDOR (read other user data): CVSS 6.5-7.5
- Reflected XSS: CVSS 6.1
- Open redirect: CVSS 4.7 (unless chained)

## HackerOne Format

```markdown
## Summary
[1-2 sentences: what the vulnerability is and its impact]

## Steps to Reproduce
1. Navigate to [URL]
2. [Exact action with exact values]
3. [Exact action]
4. Observe: [what proves the vulnerability]

## Impact
[What can an attacker actually do? Be specific about data/access/actions affected]
[Who is affected? All users? Only admins? Specific roles?]

## Supporting Material/References
- [Screenshot/video if helpful]
- [Relevant CWE: CWE-XXX]
- [CVSS 3.1: X.X (vector string)]

## Severity Justification
[Why you chose this severity — map to their taxonomy]
```

**HackerOne tips:**
- Use their severity taxonomy: Critical/High/Medium/Low
- Reference their specific program policy for scope/severity guidance
- Include CWE ID — triagers use it for categorization
- Don't include remediation advice unless asked (some programs dislike it)
- Mention if you have additional impact not yet demonstrated

## Bugcrowd Format

```markdown
## Title
[Bug Class] in [Endpoint] — [Impact Summary]

## Description
[2-3 sentences describing the vulnerability, affected component, and root cause]

## Proof of Concept
### Environment
- URL: [target URL]
- Browser/Tool: [what you used]
- Auth state: [authenticated as role X / unauthenticated]

### Steps
1. [Step with exact URL, params, headers]
2. [Step]
3. [Step]

### Expected vs Actual
- Expected: [what should happen]
- Actual: [what happens — the vulnerability]

## Impact Statement
[Business impact: what can attacker achieve, who is affected, what data is at risk]

## CVSS
Score: X.X
Vector: CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X

## Attachments
[Screenshots, HTTP request/response pairs, video PoC]
```

**Bugcrowd tips:**
- Bugcrowd uses VRT (Vulnerability Rating Taxonomy) — map your finding to their taxonomy
- P1-P5 severity scale: P1=Critical, P2=High, P3=Medium, P4=Low, P5=Info
- Include raw HTTP requests (from `get_request_detail`) — they love seeing the actual traffic
- Bugcrowd prefers detailed reproduction steps over theoretical analysis

## Intigriti Format

```markdown
## Vulnerability Type
[Select from their categories: XSS, SQLi, IDOR, etc.]

## Domain/URL
[Exact affected URL]

## Summary
[Brief description of the vulnerability]

## Steps to Reproduce
1. Go to [URL]
2. [Action with specific values]
3. [Action]
4. Result: [observable vulnerability proof]

## Impact
[What is the real-world security impact?]
[Rate: Critical / High / Medium / Low / Informational]

## CVSS 3.1
Score: X.X
Vector String: CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X

## Proof
[HTTP request/response showing the vulnerability]
[Screenshot or video demonstrating impact]
```

**Intigriti tips:**
- They use CVSS heavily for severity determination
- Duplicate detection is strict — check disclosed reports first
- Clean, concise reports get faster triage
- Include both request AND response in proof section

## Immunefi (Web3/DeFi)

```markdown
## Bug Description
[Detailed technical description of the vulnerability]

## Impact
[Concrete impact on the protocol/smart contract/frontend]
[Quantify financial impact if possible: "could drain $X from pool"]

## Risk Breakdown
Difficulty to Exploit: [Easy/Medium/Hard]
CVSS: X.X (vector string)

## Proof of Concept
[For smart contracts: Foundry/Hardhat test demonstrating the exploit]
[For web vulns: step-by-step with exact requests]

## Recommendation
[How to fix the vulnerability]
```

**Immunefi tips:**
- Immunefi REQUIRES fix recommendations (unlike other platforms)
- Smart contract bugs need working PoC code (Foundry test preferred)
- Web frontend bugs follow standard format but always tie back to DeFi impact
- Severity based on funds at risk: Critical=$10M+, High=$1M+, Medium=$100K+

## Generating Reports with Tools

To build a report, gather evidence using these tools:

```
1. Get the finding details:
   load_target_intel(domain, "findings")

2. Get the PoC request/response:
   get_request_detail(index=POC_INDEX)

3. Get tech context:
   load_target_intel(domain, "profile")

4. Format using the platform template above

5. Save the report:
   export_report(format="markdown")
   # or generate directly in conversation
```

## Report Quality Checklist

Before submitting, verify:

- [ ] Title clearly states bug class + component + impact
- [ ] Steps reproduce from scratch in < 5 minutes
- [ ] No assumed knowledge — a triager unfamiliar with the app can follow
- [ ] Impact is specific (not "attacker can do bad things")
- [ ] CVSS score is honest (not inflated)
- [ ] Raw HTTP evidence included (request + response)
- [ ] No sensitive data in screenshots (your own credentials, other users' PII)
- [ ] Tested on the latest version / production environment
- [ ] Checked program policy for scope and excluded vuln types
- [ ] Single finding per report (chains clearly marked as chains)

## Severity Inflation Red Flags

Never do these — triagers will downgrade or close:

- Calling reflected XSS "critical" without ATO chain
- Claiming RCE from error-based SQLi without demonstrating it
- Rating open redirect as "high" without token theft chain
- Calling CORS misconfiguration "critical" without proving data theft
- Saying "could lead to" without proving it actually does
- Using worst-case CVSS when your PoC only demonstrates limited impact
