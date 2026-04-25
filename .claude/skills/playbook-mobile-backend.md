---
name: playbook-mobile-backend
description: Mobile-app backend flaws, MASTG-aligned — APK/IPA endpoint extraction, device-bound token replay, IAP receipt bypass, deep-link → WebView intent injection, mobile WS auth, push-token spoofing, predictable ULID/Snowflake IDs.
prerequisite: Mobile-app indicators present — okhttp/CFNetwork/Dalvik UA, /api/mobile/, X-Device-Id headers, FCM/APNs tokens, IAP endpoints, or user provided APK/IPA.
stop_condition: 10 calls, no auth difference between mobile/web sessions, no replay-cross-device success, no deep-link payload reaching backend → return to router.
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
    NO  → continue

Device-bound auth visible (X-Device-Id, device certs)?
    YES → §4 (replay across devices)

IAP/subscription endpoints?
    YES → §5

Deep-link / WebView features?
    YES → §6
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

Mobile apps often skip Origin checks on WS (no browser context), but their WS endpoints are sometimes reachable from browser via CSWSH. See `playbook-api-advanced.md` §4 — same primitives apply.

## Burp MCP tool mapping

| Need | Tool |
|---|---|
| Find mobile endpoints | `search_history`, `extract_api_endpoints`, `parse_api_schema` |
| Test mobile endpoint as web client | `session_request`, `curl_request` |
| Verb tampering | `resend_with_modification(modify_method=...)` |
| Device-id swap | `session_request(headers={"X-Device-Id": "..."})` |
| WebSocket replay | `websocket_connect`, `websocket_send_message` |

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

