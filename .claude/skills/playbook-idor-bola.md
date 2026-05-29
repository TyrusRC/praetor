---
description: IDOR vs BOLA hunting — ID-shape inventory, auth matrix discipline, mass-enum vs single-pivot, severity calibration. Load when a parameter contains an ID and you have ≥2 auth states.
globs:
---

# IDOR / BOLA Deep-Dive Playbook

Load when: a parameter contains a record identifier (numeric / UUID / slug / hash) AND you can create or capture ≥2 distinct accounts. This is the single highest-paying bug class in bug bounty per 2025 HackerOne / Bugcrowd data.

## IDOR vs BOLA (terminology)

- **IDOR** — Insecure Direct Object Reference. Legacy web term. Same root cause.
- **BOLA** — Broken Object Level Authorization. OWASP API Security Top 10 (2023) #1. Modern API context.

Same vulnerability class — pick the term your program uses in scope language.

## Decision gate

- Does the endpoint accept an ID and return per-user data? → candidate.
- Do you have at least two principals (your_account + victim_account)? If no, create a second account or capture session_post-downgrade.
- Are the IDs sequential / time-based / predictable? → mass-enumeration in play.
- Is the ID a hash / UUIDv4 / random slug? → single-pivot only (you need a leaked or harvested ID).

## ID-shape inventory

Run this FIRST. ID shape determines enumeration strategy.

| Shape | Detection regex | Strategy |
|---|---|---|
| Sequential numeric | `\b[1-9]\d{0,8}\b` | Walk ±N around known ID — fast |
| UUIDv1 (time-based) | `[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-...` | `probe_id_monotonic(seed_id, id_type='uuidv1')` — time-window enumeration via MAC + clock_seq |
| ULID | `[0-9A-HJKMNP-TV-Z]{26}` | `probe_id_monotonic(seed_id, id_type='ulid')` — first 10 chars are timestamp |
| Snowflake | `\b\d{17,19}\b` (Discord / X-style) | `probe_id_monotonic(seed_id, id_type='snowflake')` — epoch-relative timestamp |
| UUIDv4 random | `[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-...` | Single-pivot only |
| Hash / opaque | `[a-f0-9]{32,64}` | Single-pivot only; check token entropy via `analyze_reset_tokens` |
| Slug | `[a-z0-9-]+` | Single-pivot; harvest from public listings |

For everything except UUIDv4 / cryptographic hash: enumeration is in play.

## Tool chain

1. **Harvest IDs** — `harvest_identifiers(domain)` walks proxy history for IDs/emails/UUIDs/ULIDs/Snowflakes/JWTs. Pivot fuel.
2. **Auth matrix sweep** — `test_auth_matrix(endpoints, auth_states={pre, post})` confirms whether your_account can read victim_account's IDs. Subject × Object × Action coverage.
3. **Cross-transport probe** — `probe_cross_transport_idor(rest_path, victim_id, graphql_endpoints, ws_endpoints)` — same IDOR via GraphQL / WebSocket. Triager cannot dismiss as "only REST".
4. **Monotonic enumeration** — `probe_id_monotonic(path_template, seed_id, window=50)` for sequential / UUIDv1 / ULID / Snowflake.
5. **Compare-and-flag** — `compare_auth_states(index, original_cookies, alt_cookies)` for one-off CRUD operations.

## Auth state matrix discipline

The 2x2 minimum: (your auth × your ID) / (your auth × victim ID) / (victim auth × victim ID) / (no auth × any ID).

Pass:
- your × yours = 200
- your × victim = 403
- victim × victim = 200
- no auth × any = 401

IDOR confirmed when:
- your × victim = 200 with victim data

BFLA confirmed when:
- standard-role × admin-endpoint = 200 (vertical privilege)
- normal × victim's-admin = 200 (horizontal at admin level)

## Mass-enum vs single-pivot

| Pattern | Bounty cap | Evidence bar |
|---|---|---|
| **Mass enumeration** — walk 1..N and dump everyone's PII | CRITICAL | Show 3-5 distinct foreign records returned + redacted PII excerpt |
| **Single-pivot** — read one specific foreign record via leaked ID | HIGH | Show one cross-principal read with the foreign data structurally distinct |
| **Sparse hit** — hit only on specific role / specific resource | MEDIUM | Manual escalation: try to find a single high-impact resource (admin ID, payment ID) |

`probe_id_monotonic` returns `hits / probed`. ≥5 unique foreign records = mass-enum class.

## Severity calibration (don't inflate)

- IDOR returning **PII / payment / health data**: CRITICAL.
- IDOR returning **public-ish metadata** (project names, public usernames): MEDIUM. Even if cross-tenant.
- IDOR returning **technical IDs** (uuid_of_internal_object) with no further reach: LOW.
- IDOR on `GET /user/<id>/avatar` where avatar is already publicly serveable: NOT a finding.

## Chain patterns

Per `chain-findings.md`:

- **IDOR + auth_bypass** = mass enumeration on collection endpoint (e.g. `/users?org=other`).
- **IDOR + mass_assignment** = read-then-write foreign records by including the foreign ID in a PUT.
- **IDOR + IDOR-via-GraphQL** = cross-transport widens reporting impact.
- **IDOR + info disclosure** = leak ID range, then enumerate.

## NEVER_SUBMIT traps

- IDOR on a "public profile" endpoint where the data is meant to be public — even if there's no auth.
- IDOR on the user's own ID via a different parameter (you reading your own data).
- IDOR where the endpoint takes a token that IS the authorization (e.g. share-link tokens) — these are designed to be bearer-style.

## save_finding shape

```python
save_finding(
    vuln_type="idor",                                   # or "bola"
    endpoint="https://api.example.com/v1/orders/{id}",
    parameter="id",
    severity="high",                                    # critical only with PII / payment / health
    evidence={
        "logger_index": <foreign-record-read index>,
        "baseline_status": 403,                         # what should happen
        "summary": "Order 12347 (alice@victim.com) readable from bob's session — auth not enforced on resource owner",
        "cross_principal_verified": True,
        "id_shape": "sequential_numeric",               # or uuid_v1 / ulid / etc
        "foreign_records_observed": 5,                  # mass-enum signal
    },
)
```

For mass-enum chain reporting, also call `probe_cross_transport_idor` and reference both findings in `chain_with[]`.

## Related

- `harvest_identifiers` — pivot fuel
- `probe_id_monotonic` — enumeration
- `probe_cross_transport_idor` — REST + GraphQL + WS
- `test_auth_matrix` — Subject × Object × Action grid
- `compare_auth_states` — one-off CRUD diff
- `chain-findings.md` — escalation paths
- Rules 6/7/8 — never brute creds, never exfil real user data, never modify other users
