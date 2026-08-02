# Gap Analysis — verified against the codebase, August 2026

Every claim below was checked against the tree, not inferred from a tool's
marketing. Where a suspected gap turned out to be covered, it is recorded as
such — a false gap costs as much as a missed one.

Method: cross-reference the current external picture (PortSwigger Top 10 Web
Hacking Techniques of 2025, HackerOne payout trends, commercial DAST feature
sets, OSS agentic tooling) against a mechanical audit of the knowledge base,
the probe orchestrator, the matcher engine, and the tool registry.

---

## Part 1 — Defects found and fixed

### D1. Cloud-metadata SSRF probes were sent but could never match — FIXED

`AutoProbeOrchestrator` read matchers from `probe.matchers` only.
`cloud_webapp.json` declares them once per context instead. Result: 10 probes
across `aws_metadata_imdsv1`, `gcp_metadata`, `azure_imds`, `s3_public_bucket`
and `firebase_open_db` fired their payload at the target and were scored
against nothing.

Worse than a miss: `auto_probe` then recorded the tuple as covered, so Rule
19/20 suppressed re-testing a class that had never been evaluated. SSRF is one
of only three weakness types whose average HackerOne bounty rose more than 10%
this year — this is squarely the "only finds info and low" complaint.

Fix: `resolveMatchers(probe, contextMatchers)` — probe matchers win, context
matchers inherit, no mutation of the thread-shared knowledge map.
Guard: `tests/test_kb_probe_scoreability.py` fails on any active probe with no
matchers at either level.

### D2. Reference-only probes were fired as live payloads — FIXED

`mcp_server_attacks/mcp_rug_pull` and `rag_injection/vector_metadata_injection`
carry `variables.reference_only: true` and a prose payload
(`<compare tool descriptions across MCP server versions>`). Nothing honoured the
flag, so that string was sent to the target as a payload — junk traffic, no
possible match, and still counted as coverage.

Fix: `isReferenceOnly(variables)` skips before the request is built.

### Confirmed healthy (suspected, then ruled out)

- **Matcher-type drift.** All 18 matcher types used across 820 active contexts
  and 1497 probes are implemented in `MatcherEngine`. No probe fails closed on
  an unknown type. (`shape_fingerprint`, `valid_vs_invalid_baseline` and
  `header_removed` are implemented but unused — dead capability, not a defect.)
- **Research currency.** All ten PortSwigger Top 10 2025 techniques have
  knowledge-base coverage. The tool is not behind on research intake.
- **Proof artifacts.** `export_proof_capsule` already emits the
  manifest + oracle + request/response + exit-0-on-reproduce replay script that
  commercial "proof-based scanning" sells. It is a wiring gap, not a
  capability gap — see G1.

---

## Part 2 — Verified capability gaps, ranked

### G1. The proof capsule is built but never reached — HIGH, cheap

`export_proof_capsule` is not called by `save_finding`, not referenced by the
report path, and not mentioned in any skill or rule. It exists and nothing
routes to it. This is the single cheapest upgrade in the list: the artifact
that makes a finding independently verifiable is already implemented and simply
never produced.

**Do:** emit it on `save_finding(status='confirmed')`, and cite it from the
report in place of the Burp indices that were just stripped.

### G2. GraphQL authorization is untested — HIGH

`test_graphql` tests aliases and batching **as DoS amplification** (100 aliases,
10-query batch, depth limits). It does not test them as **authorization
bypasses**, which is the class that pays and the one every 2026 GraphQL source
names: requesting the same protected object through an alias or inside a batch
to evade a per-request authz check.

Its only authz signal is a single-session string heuristic — no
`unauthorized|forbidden|denied|permission` in the response is treated as
bypass. That is a weak oracle with no privilege differential.

`test_auth_matrix` cannot fill this: it is Subject × Object × Action over URLs
and methods. GraphQL is one URL and one verb, so the matrix collapses to a
single cell. Authorization there is per field and per operation.
`probe_bopla` is the only tool that takes ranked role sessions, and it has no
GraphQL path.

**Do:** a GraphQL authz probe over ≥2 role sessions — same field via direct
query, via alias, and inside a batch, per role — flagging any shape that
returns data to the low-privilege role that the direct query denies.

### G3. Two of the PortSwigger Top 10 2025 have knowledge but no way to run

| # | Technique | KB | auto_probe | Dedicated tool |
|---|---|---|---|---|
| 1 | Parser Differentials | yes | yes (4 ctx) | — |
| 2 | **HTTP/2 CONNECT port scan** | yes | **reference-only** | **none** |
| 3 | XSS-Leak: cross-origin redirects | yes | yes (2 ctx) | — |
| 4 | Next.js cache chains | yes | yes (6 ctx) | `probe_cve_with_variants` |
| 5 | Cross-Site ETag Length Leak | yes | yes (2 ctx) | — |
| 6 | **SOAPwn (.NET WSDL RCE)** | yes | **reference-only** | **none** |
| 7 | Unicode Normalization | yes | yes (3 ctx) | `probe_unicode_normalize_split` |
| 8 | SSRF via redirect loops | yes | yes (5 ctx) | `test_ssrf`, `confirm_ssrf` |
| 9 | ORM Leak | yes | yes (3 ctx) | — |
| 10 | Successful Errors (error-based SSTI) | yes | yes (4 ctx) | `test_ssti`, `confirm_ssti` |

Both exclusions are honest — #2 needs a raw H2 CONNECT transport the standard
client cannot speak, #6 needs an attacker-hosted WSDL/XSD chain. But #6 is an
RCE primitive against .NET estates, which is the highest-value class in the
list. It deserves an operator-driven flow, not permanent shelving.

Six classes overall have knowledge, no auto-probe path, and no dedicated tool:
`http2_connect_portscan`, `soapwn`, `xs_leak` (generic parent — the two 2025
specifics are active), `dependency_confusion`, `captcha_bypass`,
`h2_continuation_flood`. Only the last is correctly out of scope (DoS, Rule 5).

### G4. No compliance-standard mapping — MEDIUM, pure data

`_framework_map` carries ATT&CK, WSTG, OWASP Top 10 and CWE. It has no ASVS,
MASVS, PCI DSS 4.0, ISO 27001, SOC 2 or NIST CSF. Every commercial DAST emits
these, and they are the reason a report is accepted into a client's GRC
process. Adding fields to the existing map costs no new tool.

### G5. No fix-side output — MEDIUM, cheap

ZAP shipped "Generate Fix Prompt" this year: one clipboard payload carrying
everything an LLM needs to fix the issue. Praetor emits remediation prose only.
`export_fix_prompt(finding_id)` — vulnerable request, sink, framework, version,
remediation constraint — is a small addition to a workflow half the tool
currently ignores.

### G6. No honeypot / decoy detection — MEDIUM

Nuclei ships one. For a scanner a decoy wastes requests; for an agent it also
writes fabricated findings into the persistent intel store, which then poison
every later session. Cheap heuristics (implausible service breadth, uniform
banners, always-200) in the recon phase.

### G7. No scheduled regression model — MEDIUM

`easm_monitor_loop` and `findings_diff` exist but nothing schedules them. The
consensus 2026 program shape is continuous DAST for regression plus periodic
agentic depth; Praetor only does the second half.

---

## Part 3 — Explicit non-goals

State these rather than carrying them as backlog:

- **IAST / runtime instrumentation** (Invicti's DAST+IAST). Requires an agent
  inside the target. Out of scope for a black/grey-box orchestrator.
- **Multi-user RBAC, dashboards, ticketing.** Procurement features.
  `export_sarif`, `export_junit` and `format_pr_comment` already cover the CI
  surface that matters to a single operator.
- **Asset discovery at portfolio scale.** Invicti's advantage over Burp DAST,
  but a multi-tenant concern. The part worth taking is cross-domain target
  ranking, for token cost, not for inventory.

---

## Positioning

The defensible line is the class of bugs automated DAST provably cannot reach —
authorization, business logic, race conditions, chained impact — backed by
evidence discipline strict enough to survive triage. G1 and G2 are the two that
convert existing capability into accepted reports, and both are small.

## Sources

- https://portswigger.net/research/top-10-web-hacking-techniques-of-2025
- https://www.hackerone.com/press-release/organizations-paid-hackers-235-million-these-10-vulnerabilities-one-year-4
- https://appsecsanta.com/research/ai-pentesting-agents-2026
- https://appsecsanta.com/dast-tools/invicti-vs-burp-suite
- https://securityboulevard.com/2026/07/best-graphql-security-tools-in-2026-an-in-depth-guide-including-business-logic-and-enterprise-coverage/
- https://www.zaproxy.org/blog/2026-06-02-zap-updates-may-2026/
- https://appsecsanta.com/nuclei
