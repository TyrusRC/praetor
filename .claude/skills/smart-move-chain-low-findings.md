---
description: Smart move when you have multiple low/medium findings — chain them into a single high-impact report. Use when standalone severity caps at MEDIUM or NEVER_SUBMIT but combined impact is real.
globs:
---

# Smart Move — Chain Low Findings into Impact

Trigger: ≥2 confirmed findings on the target, each capped at MEDIUM or
NEVER_SUBMIT (open redirect, info disclosure, missing CSRF, self-XSS,
CORS-without-creds, debug headers, etc.). Per Rule 17, these are
reportable ONLY when chained for real impact. Per Rule 27, chain
reasoning is where the high-payout bugs live.

## The move (5 steps — uses W22+ chain auto-proposer)

```
1. findings = get_findings(domain='target.com', status='confirmed')
2. graph = build_findings_graph(domain='target.com')
3. chains = propose_chains(domain='target.com')
4. for chain in chains:
       impact = assess_finding(
           vuln_type=chain.anchor_class,
           evidence={...with logger_index from each link...},
           chain_with=[f.id for f in chain.links],
           domain='target.com',
       )
       if impact.verdict == 'CONFIRMED':
           save_finding(..., chain_with=[ids], severity=chain.combined_severity)
5. format_finding_for_platform(finding_id, platform='hackerone'|...)
```

## Chain escalation table (NEVER_SUBMIT → real impact)

| Standalone (NEVER_SUBMIT) | Chain partner | Combined impact |
|---|---|---|
| Open redirect | OAuth `redirect_uri` reflected in token flow | OAuth account-takeover (CRITICAL) |
| Open redirect | DOM XSS via redirected page | Stored XSS via redirect chain (HIGH) |
| Self-XSS | CSRF on settings/profile | One-click XSS → ATO (HIGH-CRIT) |
| CSRF on email-change | Email confirmation auto-clicked by victim | Account takeover (CRITICAL) |
| Info disclosure (internal URL) | SSRF on disclosed endpoint | Internal pivot (HIGH) |
| Info disclosure (JWT secret) | JWT in use | Token forgery → ATO (CRITICAL) |
| Verbose error (DB version) | KEV-published CVE matching version | Exploit chain (HIGH-CRIT, see `playbook-cve-research.md`) |
| Subdomain takeover (DNS-only) | Cookie scoped to parent domain | Session hijack (CRITICAL) |
| CORS no-creds | XSS or content injection on origin | Cross-origin steal (HIGH) |
| Missing CSP frame-ancestors | Sensitive state-change action | Clickjacking → ATO (HIGH) |

## Stop conditions

- `propose_chains` returns 0 candidates → all findings are isolated; this skill is not the right move. Run `playbook-cve-research.md` or `playbook-business-logic.md` instead.
- Chain candidate's assess_finding returns NEEDS_MORE_EVIDENCE → don't save yet; build the missing link (e.g. prove the OAuth flow actually consumes the redirect; prove the XSS payload reaches admin context).
- Chain anchor is `likely_false_positive` or `stale` → assess_finding REJECTS per Rule 10c. Re-verify anchor first.

## Reporting

Severity = the highest-impact step in the chain, NOT the sum. State the
chain explicitly in the report title: "Open Redirect → OAuth ATO" not
"Open Redirect + OAuth Misconfig". Triagers pay for the impact, not the
inventory.

## Rule references

- Rule 14 (no inflation) — combined chain impact must be REAL, not theoretical.
- Rule 17 (NEVER_SUBMIT list) — this skill is the chain-exception path.
- Rule 27 (creative hunting / chain reasoning) — ≥20% of session budget goes here.

## Anti-pattern

Don't report each finding standalone "to be safe". Triagers mass-close
informative reports. Don't chain weak anchors (suspected, stale,
likely_false_positive) — assess_finding rejects them per Rule 10c.
