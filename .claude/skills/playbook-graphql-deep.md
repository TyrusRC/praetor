---
description: GraphQL deep-dive — introspection / field suggestion / batching / alias DoS / depth limits / persisted query bypass / subscription protocol drift. Apollo / graphql-js / Hasura / PostGraphile / Mercurius engine specifics. Load when target exposes /graphql.
globs:
---

# GraphQL Deep-Dive Playbook

Load when: target exposes `/graphql`, `/graphiql`, `/playground`, `/v2/graphql`, or `apollo-tracing` / `x-apollo-` headers appear in proxy history.

## Engine fingerprint (do FIRST)

Different engines have different bug profiles. Identify before attacking.

| Engine | Signal | Common bugs |
|---|---|---|
| **Apollo Server** | `x-apollo-` headers / Apollo Sandbox UI | introspection, batching, alias DoS, persisted query downgrades |
| **graphql-js (vanilla)** | Generic errors, no fingerprint | field suggestion always on (typo-leak) |
| **Hasura** | `/v1/graphql`, `x-hasura-*` headers | admin secret bypass, role-based auth gaps |
| **PostGraphile** | `/graphql` + PostgREST-style | row-level security (RLS) bypass via permission claims |
| **Mercurius** (Fastify) | Fastify error shape + GraphQL contract | similar to Apollo + Fastify ecosystem bugs |
| **AWS AppSync** | `*.appsync-api.*.amazonaws.com` | Cognito JWT trust, missing field resolvers |
| **Dgraph** | `/admin` endpoint variant | admin endpoint exposure |
| **Strawberry** (Python) | Python tech stack + GraphQL | SDL leak via debug routes |

KB `graphql.json` + `graphql_engines.json` cover engine-specific contexts.

## Attack matrix

### 1. Introspection (read schema)

```graphql
{ __schema { types { name fields { name type { name } } } } }
```

When blocked at the top level, try field-by-field (W8 added `partial_introspection`):

```graphql
{ __schema { queryType { name } } }    # one field — often slips past WAF
{ __type(name:"User") { fields { name type { name } } } }
```

For Apollo specifically: `__schema` may be blocked but `?query={...}` still allows. Also test `POST /graphql?queryid=...` — persisted-query API may bypass at separate code path.

### 2. Field suggestion / typo leak

graphql-js (and Apollo using it) emit `"Did you mean ..."` errors for typos:

```graphql
{ userrr(id:1) { id } }
# Response: "Did you mean 'user' or 'users'?"
```

Walk every typo to enumerate hidden fields without introspection. W8 added `typo_field_suggestion`. Disable: set `formatError` to strip "did you mean" hints (Apollo) or use `graphql-js` 16+ with disabled suggestions.

### 3. Batching / array request

```json
[
  {"query":"{ user(id:1){ id } }"},
  {"query":"{ user(id:2){ id } }"},
  ...
]
```

Many SPs apply rate-limit per-request, not per-batch. Submit 1000 items in one batch. Apollo Sandbox uses batching by default. Detection: `test_graphql(depth='deep')` runs batch probe.

### 4. Alias-based DoS

```graphql
{
  a1: user(id:1) { ...heavy }
  a2: user(id:2) { ...heavy }
  ...
  a1000: user(id:1000) { ...heavy }
}
```

Server resolves 1000 user queries in one request. Memory + CPU spike. NEVER actually DoS production — Rule 5 + safety net. Demonstrate with small N (10-50) and back-of-envelope projection.

### 5. Depth limits / circular query

When directives like `friend.friend.friend...` are resolvable, send 20-deep nested fragment:

```graphql
fragment U on User { id friend { ...U } }
{ user(id:1) { ...U } }
```

Resolver recurses until depth limit. Many APIs don't set a limit. Cap CHECK: `max_depth` config in Apollo / graphql-depth-limit plugin / cost analysis.

### 6. Persisted query bypass

Apollo / Relay use persisted queries — server stores `<hash, query>` map. Client sends only hash. When server falls back to accepting full query when hash unknown:

```json
{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"unknown_hash"}},"query":"{ secret_admin_field }"}
```

Server accepts the fallback query → arbitrary query bypassing the persisted allowlist. Apollo APQ research from PortSwigger 2024.

### 7. Subscription protocol drift (W18)

GraphQL subscription endpoints commonly support BOTH protocols:
- `graphql-transport-ws` (modern, RFC-aligned)
- `subscriptions-transport-ws` (legacy)

Auth gating frequently differs. W18 added `subscription_protocol_drift_2025` + `subscription_auth_skip_legacy_protocol`. Test legacy protocol acceptance, then privileged subscription:

```javascript
ws.send(JSON.stringify({type:"connection_init"}));
ws.send(JSON.stringify({id:"1", type:"start", payload:{query:"subscription { adminEvents { id } }"}}));
```

If admin subscription accepted unauth → high severity.

### 8. __typename info disclosure

`?query={__typename}` returns `"Query"` for the root type — confirms GraphQL endpoint. Trivial but useful for scope discovery via fuzzing.

### 9. Hasura admin secret bypass

`POST /v1/graphql` with header `x-hasura-admin-secret: wrong` — Hasura may accept role-based queries via x-hasura-role even when secret is wrong if anonymous role is misconfigured. Cross-ref `cloud_api_gateway.json`.

### 10. PostGraphile RLS bypass

PostGraphile maps GraphQL fields to Postgres functions. RLS (Row-Level Security) policies enforced at DB level. When the function runs as `SECURITY DEFINER`, RLS skipped → cross-tenant data. Inspect schema for `SECURITY DEFINER` markers.

### 11. Federation `_entities` abuse (Apollo Federation)

Apollo Federation gateway exposes `_entities` for cross-subgraph joins. When subgraph trusts the gateway implicitly:

```graphql
{ _entities(representations:[{__typename:"User",id:"victim_id"}]) { ... on User { ssn } } }
```

May leak fields the user shouldn't directly query.

## Tool chain

1. **Fingerprint engine** — first request to `/graphql` should reveal vendor (header / error shape / Sandbox UI).
2. **Introspect** — `test_graphql(session, path, depth='deep')` runs all 6 core tests (introspection, suggestions, batching, GET-CSRF, alias DoS, depth) — VerdictResult-returning (W10).
3. **Introspection-fuzz mode** — `test_graphql(depth='introspection_fuzz')` walks the introspected schema and probes every field with a stub value.
4. **Engine-specific** — `auto_probe(categories=['graphql_engines'])` for Hasura / PostGraphile / Dgraph / Strawberry per-engine probes.
5. **Subscription** — `test_websocket(ws_url='wss://target/graphql')` for upgrade-handshake attacks; cross-ref `playbook-jwt-deep-dive.md` for JWT-via-WS.

## Evidence ladder

| Verdict | Evidence shape | Save? |
|---|---|---|
| **CONFIRMED CRITICAL** | Cross-tenant data read via field / RLS bypass / federation join | yes |
| **CONFIRMED HIGH** | Introspection enabled in production + sensitive field name disclosed | yes (combined finding) |
| **CONFIRMED HIGH** | Batch / alias-DoS prove rate-limit bypass; demonstrate with safe N | yes |
| **CONFIRMED MEDIUM** | Field suggestion enabled — typo-leak enumeration confirmed | yes |
| **SUSPECTED** | Introspection-only finding without sensitive field name | NO save — info disclosure alone is NEVER_SUBMIT (Rule 17) |
| **FAILED** | All probes return per-spec errors | NO |

## save_finding shape

```python
save_finding(
    vuln_type="graphql",
    endpoint="https://api.target.com/graphql",
    severity="high",
    evidence={
        "logger_index": <success-confirming index>,
        "summary": "Persisted query bypass — server falls back to raw query when sha256Hash unknown. Submitted { secret_admin_field } via unknown hash; received full admin data.",
        "engine": "apollo",
        "attack": "persisted_query_bypass",
        "introspected_schema": "<truncated, hash for triager>",
    },
)
```

## NEVER_SUBMIT traps

- "Introspection enabled" alone — informational. Must show sensitive schema content or chain with another finding.
- "GraphQL endpoint exposed at `/graphql`" — by design for most APIs.
- "Field suggestion reveals field names" alone — info disclosure (Rule 17 NEVER_SUBMIT solo).
- "Alias query with 1000 items succeeded" — without proven server-side impact (CPU / memory), informational.

## Severity discipline

- Cross-tenant data via GraphQL = CRITICAL.
- Persisted query bypass + admin-only field = CRITICAL.
- RLS bypass via SECURITY DEFINER = CRITICAL.
- Subscription protocol drift + privileged sub = HIGH.
- Field suggestion + introspection bypass to enumerate hidden admin endpoints + chain to BOLA = HIGH.
- Standalone introspection / alias / depth = MEDIUM at best, often NEVER_SUBMIT.

## Chain patterns

- **Introspection → enumerate admin field → BOLA on admin endpoint** = ATO chain.
- **Field suggestion → typo-leak admin field names → BOLA** = same chain without introspection.
- **Persisted query bypass + GET cache** = cached admin response served to next visitor.
- **Subscription protocol drift + admin sub** = persistent admin event leak.
- **Federation _entities + field-level authz miss** = cross-subgraph data leak.

## Related

- `knowledge/graphql.json` — base + W8 additions (typo_field_suggestion, partial_introspection) + W18 (subscription drift, legacy auth skip)
- `knowledge/graphql_engines.json` — Apollo / Hasura / PostGraphile / Dgraph / Strawberry engine-specific
- `test_graphql` (VerdictResult W10) — 6-test detection battery
- `test_websocket` (VerdictResult W11) — WS upgrade for subscription drift
- `playbook-jwt-deep-dive.md` — JWT auth on WS subscriptions
- `chain-findings.md` — `graphql_introspection_to_field_idor` progression
