---
name: user-override
description: How the operator routes Claude when default rules block legitimate findings or downgrade real impact. Use when the gate rejects/downgrades something the operator has manually verified, when the program/scenario differs from the default policy, when severity scoring is wrong for the engagement, or when an attack vector lives outside the catalogued classes.
---

# User Override — Scenario Routing

> **Rule reference:** all overrides here ride on top of `.claude/rules/hunting.md` Tier classification (HARD 1–10 = tool-enforced, DEFAULT 11–21 = audit override, ADVISORY 22–28 = on demand). HARD rules cannot be silenced. DEFAULT and ADVISORY can.

The default ruleset is calibrated for **bug-bounty triage averages**. Real engagements vary: pentest with explicit scope can take destructive risks; a high-paying program rewards classes others reject; a target's tech stack inverts severity; a scenario the catalog hasn't seen yet is still real. This skill documents how the **operator** instructs **Claude** when the default rules conflict with the engagement reality.

## Operator-controlled override surfaces

There are five surfaces. Use the lightest one that fits.

### 1. Per-call override (lightest)

Use when ONE specific finding is being wrongly rejected/downgraded by `assess_finding`.

```
assess_finding(
  vuln_type="open_redirect",
  evidence="redirected to attacker.com, then OAuth code captured at /callback",
  endpoint="https://target.com/oauth/authorize",
  domain="target.com",
  chain_with=["f014"],                    # OAuth code-theft chain
  human_verified=True,                     # operator confirmed in browser
  overrides=["q5_evidence:operator_confirmed_in_burp_ui",
             "q7_triager:chained_with_account_takeover"],
)
```

Recognized override gates:

| Gate | Effect | When to override |
|---|---|---|
| `q1_scope` | Skip scope check | Endpoint is in scope but `check_scope` returns false (program scope syntax differs) |
| `q2_repro` | Skip reproducibility check | Auth-state-dependent bug already covered by Q2 EXEMPT logic; only override if exemption misses your class |
| `q4_dedup` | Skip dedup check | Two findings look like dupes but differ in impact, sink, or affected user set |
| `q5_evidence` | Skip evidence keyword check | Operator verified in Burp UI / browser DevTools — equivalent to `human_verified=True` |
| `q6_never_submit` | Skip NEVER SUBMIT class block | Program explicitly accepts the class (e.g. some bounties pay tabnabbing-on-OAuth-flow) |
| `q7_triager` | Skip triager-mass-report heuristic | Target program has known acceptance for low-impact-but-clean findings |
| `recon_gate` | Skip Rule 20a recon-intel check | Recon was done out-of-band (logged in another tool) |

Each entry MUST be `<gate>:<reason>`. Reason is logged in the audit trail and saved with the finding.

### 2. Severity / chain hints (mid-weight)

Use when the gate would PASS but the inferred severity is wrong for the scenario.

```
assess_finding(...,
  business_context="banking",          # Boosts impact +10% (financial data)
  environment="production",            # +5% (live impact)
  session_name="hunt",                 # If session is authenticated, IDOR/BFLA boost +10% (Rule 28)
  reproductions=[                      # For timing/blind: 3 entries skip Q5 timing rule
    {"logger_index": 41, "elapsed_ms": 5230, "status_code": 200},
    {"logger_index": 42, "elapsed_ms": 5180, "status_code": 200},
    {"logger_index": 43, "elapsed_ms": 5310, "status_code": 200},
  ],
)
```

Then on `save_finding`:

```
save_finding(
  ...,
  severity="HIGH",          # Operator-locked; not auto-inferred
  confidence=0.85,           # Operator-set (use the suggested value from assess_finding)
  chain_with=["f014"],
)
```

Severity levels: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. The ZERO-NOISE GATE in Burp does not adjudicate severity beyond NEVER_SUBMIT class membership — operator owns the severity decision.

### 3. Per-program policy (engagement-wide)

Use when an entire CATEGORY needs different treatment for THIS engagement, every time.

```
set_program_policy(
  slug="acme-banking-program",
  never_submit_remove=["tabnabbing", "rate_limit_absent_non_sensitive"],   # Program pays these
  never_submit_add=["cors_no_creds"],                                       # Program rejects this
  confidence_floor=0.65,                                                    # Lower bar for this program
  notes="Acme accepts tabnabbing on OAuth flow (CVE chain bonus). Confidence floor 0.65 per program rules."
)
```

Persisted to `.burp-intel/programs/<slug>.json`. `assess_finding` loads the active policy automatically. Use `get_program_policy` to inspect, `clear_program_policy` to reset.

### 4. Scope override (per-domain)

Use when auto-filter strips a domain that's actually in scope (target's CDN, OAuth provider, asset host).

```
configure_scope(
  include=["https://target.com", "https://api.target.com", "https://cdn.target.com"],
  auto_filter=True,
  keep_in_scope=["cloudflare", "apis.google", "googleapis"],   # Keep these even though they look like trackers
)
```

Substring-matched against the auto-filter list. Use case: testing OAuth-via-Google flow needs `apis.google.com` in scope; testing subdomain-takeover on Cloudflare-fronted target needs `cloudflare.com` to remain testable.

### 5. Reference-only file override

Use when an entire knowledge file should NOT be skipped by `auto_probe` for this engagement.

```python
# Edit mcp-server/src/burpsuite_mcp/tools/scan.py:
# _REFERENCE_ONLY = { ... }   ← remove the file from this set
```

Or pass an explicit `categories=[]` list to `auto_probe` that includes the otherwise-excluded category — `auto_probe` will load the file directly. Use case: file-upload race conditions during a specific engagement.

## Routing decision tree

```
Gate rejected a finding I know is real
├── Was it Q1 (scope)?
│   ├── Domain genuinely in scope? → overrides=["q1_scope:per_program_brief"]
│   └── Genuinely out of scope? → STOP, don't report (Rule 1 is HARD)
│
├── Was it Q2 (reproducibility)?
│   ├── Class is auth-state-dependent (idor/bfla/business_logic)? → already exempt; double-check vuln_type spelling
│   └── Genuine flake? → re-test 5 times, supply reproductions=[...]; if still flaky, overrides=["q2_repro:race_window_5pct"]
│
├── Was it Q4 (dedup)?
│   ├── Same root finding, different impact path? → keep one finding, ADD the new vector to evidence_text
│   └── Truly distinct (different user set, different sink)? → overrides=["q4_dedup:distinct_sink_<name>"]
│
├── Was it Q5 (weak evidence)?
│   ├── Verified in Burp UI? → human_verified=True (no override needed)
│   ├── Have logger_index? → pass it; gate auto-derives markers
│   ├── Have reproductions[] (timing/blind)? → pass array; gate counts entries
│   └── None of the above? → strengthen evidence first; do NOT override Q5 lightly
│
├── Was it Q6 (NEVER SUBMIT)?
│   ├── Have a chain? → chain_with=[<id>]; gate passes conditionally
│   ├── Endpoint is sensitive (auth/reset/OTP/payment)? → for rate_limit_missing, gate passes automatically
│   ├── Program pays the class? → set_program_policy(never_submit_remove=[<class>])
│   └── No chain, no policy? → don't report standalone (this is exactly what Q6 is for)
│
├── Was it Q7 (triager mass report)?
│   ├── Have a chain? → already skipped automatically
│   ├── High-confidence + clean evidence? → strengthen evidence to push past confidence_floor
│   └── Program pays low-impact classes? → set_program_policy(confidence_floor=0.45)
│
└── Was it the program confidence floor?
    └── Floor is too high for this engagement? → set_program_policy(confidence_floor=<lower>)
```

## Severity routing — when default is wrong

The advisor infers severity. The operator may know better. Three signals override:

1. **Business context unique to engagement** — pentest of an internal HR system has different impact than a public-facing banking app even with the same vuln class. Set `business_context` to reflect ACTUAL impact, not technical class.
2. **Chain context** — open-redirect alone is LOW; open-redirect chained with OAuth code theft is CRITICAL. Pass `chain_with=[<oauth_finding_id>]` and lock `severity="CRITICAL"` on save_finding.
3. **Environment** — the same SQLi is HIGH on staging, CRITICAL on production. Pass `environment="production"`.

Operator severity always wins on `save_finding`. The advisor's inferred severity is a SUGGESTION, not a verdict.

## Attack vector — class missing or unknown

When the bug doesn't fit a catalogued class:

1. Pick the closest known class for `vuln_type` (e.g. "auth_bypass" for novel auth flaws). The advisor will skip Q5 (unknown vuln_type → DEFAULT REPORT, R2).
2. Put the actual technique in `evidence_text` and `description` — this is what the report uses, not the class label.
3. If the class is genuinely new and you'll see it again on this engagement, add a knowledge file under `mcp-server/src/burpsuite_mcp/knowledge/<class>.json` with at least one context + matchers. `auto_probe` will pick it up next run.

## What you CANNOT override

The HARD tier (Rules 1–10) is enforced at the tool layer (Java handler). No override flag releases these:

- **Out-of-scope requests** are blocked at `check_scope`. No `q1_scope` override prevents this — it only suppresses the advisor's Q1 gate; the request still gets blocked when sent.
- **Destructive payloads** (`DROP TABLE`, `rm -rf`, `shutdown`) — Rule 5 is HARD. Use benign markers.
- **Brute-force credentials** — Rule 6 is HARD. ID enumeration is permitted (Rule 6 carve-out); credential dictionaries are not.
- **Real-user-data exfiltration** — Rule 7 is HARD. PoC means 1-2 records for distinctness, not a full dump.
- **Modify/delete other users' data** — Rule 8 is HARD. Demonstrate IDOR with READ access only.
- **Fabricated OOB callbacks** — Rule 9a is HARD. Use Collaborator or operator-provided callback; never hardcode `evil.com` for OOB exfil.

If a HARD rule blocks something you genuinely need, the answer is the engagement contract / Statement of Work, not a Claude override. Stop and ask the operator.

## Quick reference — most common operator instructions

```
# "I verified this in Burp myself"
human_verified=True

# "This chains with finding f014"
chain_with=["f014"]

# "This program pays tabnabbing"
set_program_policy(slug="<slug>", never_submit_remove=["tabnabbing"])

# "Lower the confidence bar for this program"
set_program_policy(slug="<slug>", confidence_floor=0.50)

# "Treat this as production banking severity"
business_context="banking", environment="production"

# "Keep CDN in scope"
configure_scope(include=[...], keep_in_scope=["cloudflare"])

# "I'm in grey-box now (logged in as user)"
session_name="<authenticated_session>"

# "Force severity HIGH on save"
save_finding(..., severity="HIGH")
```
