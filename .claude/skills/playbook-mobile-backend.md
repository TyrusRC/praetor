---
name: playbook-mobile-backend
description: Mobile-app backend flaws across all transport types (REST, GraphQL, gRPC-Web, WebSocket, SSE). MASTG/OWASP Mobile Top 10 aligned — BOLA, BFLA, excessive data, device-bound tokens, IAP bypass, deep-link injection, push-token spoofing, predictable IDs, WS hijack, GraphQL batch abuse, gRPC service enumeration.
prerequisite: Mobile-app indicators present — okhttp/CFNetwork/Dalvik UA, /api/mobile/, X-Device-Id headers, FCM/APNs tokens, IAP endpoints, GraphQL/gRPC-Web content-types, or user provided APK/IPA.
stop_condition: 12 calls, no auth difference between mobile/web sessions, no replay-cross-device success, no deep-link payload reaching backend, no GraphQL/gRPC abuse → return to router.
---

# Mobile Backend Playbook

Test the **backend the mobile app talks to** — often weaker than web because devs trust "the app." NOT testing binary security (pinning, root detection — not bug-bounty findings on most programs).

## Decision tree

```
APK/IPA available to inspect?
    YES → §1 (extract endpoints, compare to web surface)
    NO  → §2 (passive — inspect mobile traffic in proxy)

Mobile-only endpoints found?
    YES → §3 (test as web client — often missing auth)

Device-bound auth visible (X-Device-Id, device certs)?
    YES → §4 (replay across devices)

IAP/subscription endpoints?
    YES → §5

Deep-link / WebView features?
    YES → §6

Transport type?
    GraphQL  → §10 (introspection, batch abuse, nested DoS)
    gRPC-Web → §11 (service enum, admin services, proto injection)
    WebSocket→ §9  (CSWSH, missing auth, message injection)
    SSE      → §12 (cross-user streams, event leakage)
    REST     → §3 + §7 (BOLA, predictable IDs)
```

## 1. APK / IPA endpoint extraction

If user provided binary, key extraction targets:

### Android (APK)
| File | What to look for |
|---|---|
| `AndroidManifest.xml` | Exported activities, deep-link schemes (`<data android:scheme="myapp">`), exported providers |
| `strings.xml` (decompiled) | URLs, API keys |
| `network_security_config.xml` | Trusted domains, debug-mode pinning bypass |
| `classes.dex` (Jadx) | API endpoints in code, hardcoded secrets, `BuildConfig` |
| Assets / raw resources | Bundled cert pins, SDK configs |

### iOS (IPA)
| File | What to look for |
|---|---|
| `Info.plist` | URL schemes, ATS (App Transport Security) exceptions, bundle ID |
| Binary `strings` | URLs, API keys |
| `Frameworks/` | SDK versions (potential CVE chain) |
| `Resources/` plist files | Config endpoints |

**You don't need to do binary analysis here** — the user can provide extracted strings/endpoints. Your job: take the endpoint list and treat each as an attack surface.

### Endpoint comparison

```
Web has:        /api/v2/users        — requires CSRF token, rate-limited
Mobile has:     /api/mobile/users    — different auth path, different limits
Mobile has:     /api/v2/admin/...    — sometimes admin endpoints exposed only to mobile
```

**The gap is the bug.** Test mobile-only endpoints as a web client (curl/session_request) — they often skip checks that web has.

## 2. Passive mobile-traffic inspection

Without binary, derive from intercepted traffic in `get_proxy_history`:

```python
search_history(query="/api/mobile", in_url=True)
search_history(query="/v1/m/", in_url=True)
search_history(query="X-Platform", in_request_body=True)
search_history(query="okhttp", in_request_body=True)  # User-Agent
search_history(query="CFNetwork", in_request_body=True)
search_history(query="device_id", in_request_body=True)
search_history(query="device_token", in_request_body=True)
search_history(query="push_token", in_request_body=True)
search_history(query="receipt", in_request_body=True)  # IAP
extract_api_endpoints(index)  # JS files sometimes reference mobile endpoints
```

## 3. Mobile-only endpoint attacks

For each mobile endpoint found:

| Test | Reason |
|---|---|
| Send from non-mobile UA | Often no UA check — succeeds with same auth |
| Strip `X-Device-Id` | Many mobile APIs treat presence as "trusted client" |
| Replace `X-App-Version: 1.0.0` with `0.0.1` or `999.0.0` | Force-update logic sometimes returns admin debug responses |
| Send to `/api/mobile/admin/...` paths inferred from web `/api/v1/admin/...` | Admin gates often forgotten on mobile |
| Test verb tampering | `GET /api/mobile/users` works, `DELETE /api/mobile/users/123` may also work without web's CSRF |
| Test pagination explosion | Mobile APIs often return larger pages by default |
| Session token reuse | Mobile JWT/session sometimes longer-lived; reuse weeks-old token |

## 4. Device-bound token replay

Headers to look for: `X-Device-Id`, `X-Device-Token`, `Device-Fingerprint`, `X-Installation-Id`.

| Attack | Probe |
|---|---|
| Cross-device replay | Capture victim's device-bound token, replay from your device-id | Server doesn't actually bind = found bug |
| Predictable device-id | Sequential, timestamp-based, or based on phone IMEI hash | Enumeration possible |
| Token without device check | Drop `X-Device-Id` entirely, send only Bearer | Some endpoints skip the check |
| Multi-device session | Login from 2 sessions, do action from session A, replay from session B | Cross-session leak |
| Device-id case sensitivity | `X-Device-Id: ABC` vs `abc` | Inconsistent normalization |

## 5. IAP / Subscription / Receipt validation bypass

When app sends purchase receipts to backend:

| Attack | Reason |
|---|---|
| Replay another user's receipt | Receipts sometimes not bound to user_id, just to product_id |
| Server-side receipt validation off | Send fake receipt JSON; backend trusts client-side validation result |
| Sandbox vs prod receipt confusion | Send sandbox receipt to prod endpoint — some envs accept both |
| Missing transaction-id uniqueness | Same receipt grants entitlement multiple times |
| Subscription status manipulation | `PATCH /me/subscription {"tier":"premium","expires_at":"2099-..."}` |
| Refund-then-keep | Refund the IAP; does the backend revoke entitlement? Often no. |

**Probe ethically:** Use sandbox accounts. Don't actually purchase. Don't refund-attack production unless the program explicitly allows.

## 6. Deep-link / WebView intent injection

### Android intents (extracted from manifest)
```
myapp://path?param=...
```

| Attack | Probe |
|---|---|
| Open arbitrary URL in in-app WebView | `myapp://webview?url=https://evil.com` — phishing inside trusted app shell |
| WebView JS bridge (`@JavascriptInterface`) | If `addJavascriptInterface(obj, "Android")` and WebView loads attacker URL → call any Java method from JS |
| Local file read via deep link | `myapp://open?file=file:///data/data/com.app/...` |
| Path traversal in deep-link param hitting backend | Deep link forwards param to backend without sanitization |

### iOS Universal Links / URL schemes
| Attack | Probe |
|---|---|
| Universal Link to attacker-controlled path on trusted domain | If app routes `https://target.com/share/<id>` to in-app handler, attacker gets `id` |
| Custom scheme race | Multiple apps register same scheme → which opens? |
| WebView with `WKWebView` + `evaluateJavaScript` of user input | XSS-like in app context |

These are reportable IF backend can be reached or in-app data is leaked. Pure UI-redress without backend impact = often considered "won't fix."

## 7. Predictable IDs (timestamp-sortable)

Mobile apps love ULID, Snowflake, MongoDB ObjectId — all of which encode timestamps:

| Format | Predictable parts |
|---|---|
| ULID `01H8XGJWBK...` | First 10 chars = timestamp |
| Snowflake `1234567890123456789` | Top bits = timestamp, middle = worker, low = sequence |
| MongoDB ObjectId `507f1f77bcf86cd799439011` | First 4 bytes = timestamp |
| UUIDv1 `c232ab00-9414-...` | Time + MAC; MAC reveals server, time predictable |

**Attack:** Take your own ID, decode its timestamp, predict victim's ID by trying timestamps near a known event (their signup time, last login). Pair with BOLA.

## 8. Push-token spoofing

If app sends FCM/APNs token to backend:
- Capture victim's push token (via XSS, leaked logs)
- Register attacker's device with victim's user_id + own token
- Now attacker receives victim's push notifications (often containing OTP, transaction details)

This is a HIGH-impact bug when present and reproducible. Confirm by checking if backend lets the same `push_token` be registered to multiple users, or vice versa.

## 9. Mobile WebSocket flaws

Mobile apps often skip Origin checks on WS (no browser context), but their WS endpoints are sometimes reachable from browser via CSWSH.

| Attack | Probe |
|---|---|
| Missing Origin check | `websocket_connect` from browser context — if accepted, CSWSH is possible |
| Auth token in WS URL | `ws://api.target.com/ws?token=xxx` — token in URL leaks via logs, referrer |
| Message injection | Send SQLi/XSS payloads through WS messages — backend may not sanitize WS input like HTTP |
| Auth bypass on WS | Connect without auth, send authenticated-user messages — WS auth often checked only at handshake |
| Subscription abuse | Subscribe to other users' channels/rooms — missing authorization on subscribe events |

```
websocket_connect(url="wss://api.target.com/ws")
websocket_send_message(name="ws1", message='{"type":"subscribe","channel":"user_123_private"}')
```

## 10. Mobile GraphQL backends

Many mobile apps use GraphQL — often a single `/graphql` endpoint handles all operations.

| Attack | Probe |
|---|---|
| Introspection enabled | `test_graphql` — mobile backends often leave introspection on since "only the app calls it" |
| Batch query brute force | `test_graphql_deep` — batch 100 login mutations in one request to bypass rate limits |
| Nested query DoS | Deep nesting: `{ user { friends { friends { friends { ... } } } } }` — no depth limit |
| Field suggestion leakage | Typo a field name — GraphQL helpfully suggests valid field names including admin-only fields |
| Alias-based auth bypass | Query same field with different aliases to compare authorized vs unauthorized access |
| Mutation without auth | Introspect mutations, call admin mutations with user token |

```
test_graphql(session, url="/graphql")
test_graphql_deep(session, url="/graphql")
```

## 11. Mobile gRPC-Web / Protobuf backends

gRPC traffic proxied through Burp appears as HTTP/2 POST with `Content-Type: application/grpc-web+proto` or `application/grpc-web-text`.

| Attack | Probe |
|---|---|
| Service enumeration | gRPC reflection API: `grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo` — lists all services |
| Unprotected admin services | Mobile app calls `UserService`, but `AdminService` exists on same host — call it with user token |
| Protobuf field injection | Add extra fields to protobuf message — backend may accept hidden fields (mass assignment via proto) |
| Missing auth on streaming RPCs | Unary RPCs have auth interceptor, but server-streaming RPCs skip it |
| Error message leakage | gRPC status details often include stack traces, internal service names |

```
# gRPC-Web appears as regular HTTP POST in Burp
curl_request(
    url="https://api.target.com/service.AdminService/ListUsers",
    method="POST",
    headers={"Content-Type": "application/grpc-web+proto", "Authorization": "Bearer <user_token>"},
    body="<protobuf_bytes>"
)
```

**Note:** Protobuf binary encoding makes payloads harder to craft. Look for gRPC-Web-Text (base64-encoded) which is easier to manipulate. Use `decode_encode` to base64 decode/encode protobuf payloads.

## 12. Mobile SSE (Server-Sent Events) and real-time feeds

Mobile apps use SSE for live updates (notifications, chat, price feeds).

| Attack | Probe |
|---|---|
| Cross-user event subscription | Change user ID in SSE URL: `/events?user_id=victim` |
| Auth bypass on event stream | SSE endpoint may not validate token after initial connection |
| Event data leakage | SSE events may contain more data than the app displays (excessive data exposure) |
| Connection hijacking | If SSE uses predictable connection IDs, hijack another user's stream |

```
curl_request(url="https://api.target.com/events/stream?user_id=123", headers={"Accept": "text/event-stream"})
```

## Burp MCP tool mapping

| Need | Tool |
|---|---|
| Find mobile endpoints | `search_history`, `extract_api_endpoints`, `parse_api_schema` |
| Test mobile endpoint as web client | `session_request`, `curl_request` |
| Verb tampering | `resend_with_modification(modify_method=...)` |
| Device-id swap | `session_request(headers={"X-Device-Id": "..."})` |
| IDOR / auth matrix | `test_auth_matrix` across roles/devices |
| WebSocket testing | `websocket_connect`, `websocket_send_message` |
| GraphQL testing | `test_graphql`, `test_graphql_deep` |
| gRPC-Web probing | `curl_request` with `application/grpc-web+proto` content-type |
| SSE stream testing | `curl_request` with `Accept: text/event-stream` |
| Protobuf decode | `decode_encode(operation="base64_decode")` for gRPC-Web-Text |
| Business logic bypass | `test_business_logic`, `test_race_condition`, `run_flow` |

## Save-finding template

```python
save_finding(
    vuln_type="bola",  # or bfla, mass_assignment, idor, predictable_id, iap_bypass
    severity="high",
    title="Cross-device session replay on /api/mobile/transfer (no device-id check)",
    description="...",
    url="https://target/api/mobile/transfer",
    evidence={"logger_index": N},
)
```

## Anti-patterns

- **Don't** report cert-pinning absence as a finding — it's a client-side hardening item, not a backend bug
- **Don't** report root-detection bypass — same reason
- **Don't** report obfuscation weakness — same reason
- **Do** report when mobile binary leaks credentials, secret URLs, or admin endpoints — those are backend exposure

