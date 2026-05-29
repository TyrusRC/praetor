---
description: Mobile app DAST workflow — OWASP MASTG / MASVS mapping. Frida + adb + Burp proxy. Load when target has an Android/iOS app in scope.
globs:
---

# Mobile MASTG Workflow

Use when: target has an Android/iOS app in scope (APK / IPA / store URL), or a web finding points at a mobile-specific surface (deep link, universal link, WebView bridge). Pair with `mobile-dynamic-agent`. NOT a substitute for static analysis — Praetor mobile is **supporter tier**, not focus.

## Decision gate

- **App in-scope per program policy?** Many programs list `*.com` but EXCLUDE the app — check first.
- **Device available?** Rooted Android emulator (Pixel-class image) or jailbroken iOS test device. Without one, fall back to `mobile-backend` skill (API-only).
- **Frida server running on device?** Android: `adb shell /data/local/tmp/frida-server &`. iOS: Frida via Cydia.

## MASTG → Praetor mapping

| MASVS control      | MASTG test family        | Praetor surface                                |
|--------------------|--------------------------|------------------------------------------------|
| MASVS-STORAGE      | MASTG-TEST-0001..0011    | `adb pull /data/data/<pkg>/`, sqlite3 dump     |
| MASVS-CRYPTO       | MASTG-TEST-0012..0020    | Frida hook crypto/keystore (snippet #6)        |
| MASVS-AUTH         | MASTG-TEST-0021..0030    | Frida biometric bypass (#8), session replay    |
| MASVS-NETWORK      | MASTG-TEST-0031..0040    | SSL-pin bypass (#1) + Burp proxy intercept     |
| MASVS-PLATFORM     | MASTG-TEST-0041..0050    | dumpsys package, deep link probe, WebView (#4) |
| MASVS-CODE         | MASTG-TEST-0051..0060    | apkanalyzer manifests, exported components     |
| MASVS-RESILIENCE   | MASTG-TEST-0061..0070    | Root-detect bypass (#3), debug bypass          |
| MASVS-PRIVACY      | MASTG-TEST-0071..0075    | logcat scrape (#9), clipboard hook (#10)       |

## Attacker workflow (per session)

1. **Inventory** — `adb shell pm list packages -3 | grep <target>`, pull APK with `adb shell pm path <pkg>` then `adb pull <apk>`. Record SHA256.
2. **Surface enumeration** — adb command pack (`mobile_adb_pack`). Capture exported activities, exported services, content providers, custom URL schemes, intent filters.
3. **Network unwrapping** — load SSL-pin bypass (`mobile_frida_snippet('ssl_pin_universal_android')`) + Burp CA. Confirm traffic in Burp proxy history. If still pinned, try the OkHttp3-specific variant (`ssl_pin_okhttp_specific`).
4. **Deep link / intent fuzzing** — `am start -a android.intent.action.VIEW -d "<scheme>://<path>"` against each registered scheme. WebView load-URL parameters are highest-yield. Probe with `mobile_deeplink` KB contexts.
5. **WebView bridge audit** — Frida `webview_debug_enable` snippet (#4) lists every exposed `@JavascriptInterface` method. Cross-reference with deep link entry points.
6. **Storage / crypto** — pull sandbox, run `sqlite3` over every `.db`, grep for tokens. Hook Keystore (#7) to capture key material at use-time.
7. **Backend handoff** — see section below. Every Burp-captured API call is fair game for the full web tool tree (`auto_probe`, `test_auth_matrix`, `test_mass_assignment`).

## Frida snippet bundle

Use `mobile_frida_snippet(name)` to get script source. Operator runs `frida -U -l <path> -f <pkg>`.

| Snippet name | Purpose |
|---|---|
| `ssl_pin_universal_android` | Hook `TrustManager` / `X509TrustManager` / `OkHostnameVerifier` / `CertificatePinner.check` |
| `ssl_pin_okhttp_specific` | OkHttp v3+v4 `CertificatePinner.check$okhttp` direct return |
| `ssl_pin_universal_ios` | Hook `SecTrustEvaluate` + `NSURLSession` + AFNetworking pinning |
| `root_jailbreak_bypass` | Hook `Build.TAGS`, `RootBeer.isRooted`, file existence checks; iOS `_dyld` / jailbreak path checks |
| `webview_debug_enable` | `WebView.setWebContentsDebuggingEnabled(true)`; enumerate `addJavascriptInterface` method signatures |
| `intent_url_enumerator` | Log every deep link / intent extra at runtime |
| `crypto_dump` | Print key bytes + IV + plaintext/ciphertext at `Cipher.doFinal` |
| `keystore_hook` | Dump aliases + key material from Android Keystore / iOS Keychain |
| `biometric_bypass` | Fabricate `AuthenticationResult` with null CryptoObject |
| `logcat_sensitive_tap` | Relay `Log.d/i/v/w/e` to Frida console regardless of device log level |
| `clipboard_hook` | Detect sensitive data passing through clipboard (privacy class) |

## adb command pack

Use `mobile_adb_pack(cmd_id, args)` for formatted commands. Praetor does NOT execute adb — operator runs on their authorized device.

Top patterns:

1. `pm list packages -3` — third-party packages
2. `pm path <pkg>` → `adb pull` — extract APK
3. `dumpsys package <pkg>` — exports, permissions, intent filters, signature
4. `dumpsys activity activities | grep <pkg>` — running activities + recent task stack
5. `dumpsys content <auth>` — content provider permissions and URIs
6. `pm dump <pkg> | grep -A2 'Activity Resolver'` — exported activities with intent filters
7. `am start -W -a android.intent.action.VIEW -d "<scheme>://..."` — deep link probe
8. `logcat -v time <pkg>:V *:S` — app-tagged log stream only
9. `run-as <pkg> sh -c 'find . -type f'` — sandbox file enumeration (debuggable APKs)
10. `service list` — exported services across all packages

## Backend handoff — the gap closed

`mobile-dynamic-agent` proxies device traffic through Burp (after SSL-pin bypass). That traffic lands in Burp proxy history as raw HTTP. Hand off to web tools via:

```
1. search_history(filter={host: <mobile_api_host>, response_status: [200,201,400,401,403]})
2. extract_api_endpoints(indices=[...])
3. save_target_intel(domain=<mobile_api_host>, category="endpoints", value=<list>)
4. auto_probe(targets=[...], session=<captured_mobile_session>)
```

Mobile apps frequently expose backend endpoints that the web UI hides (admin APIs, mobile-only endpoints, looser CORS). Once the mobile dynamic agent harvests endpoints + session, the entire web tool tree becomes useful against the mobile-only surface.

Helpers: `build_target_header_profile(domain, source='mobile')` pulls device User-Agent / X-App-Version instead of Chrome 131. `create_session(name, headers={'Authorization': 'Bearer <harvested>'})` carries the mobile token into web tests.

## Deliverables per session

- `.burp-intel/<pkg>/manifest.json` — parsed AndroidManifest exports
- `.burp-intel/<pkg>/deeplinks.json` — `{scheme, host, path, activity}[]`
- `.burp-intel/<pkg>/webview_bridges.json` — exposed JS interface methods
- `.burp-intel/<pkg>/endpoints.json` — backend API base URLs harvested from traffic
- Findings filed normally via `assess_finding` → `save_finding`. Mobile-specific evidence: attach `apk_sha256`, `package_name`, `device_model`, `os_version`, Frida hook output.

## Reference, not duplication

- `mobile-dynamic-agent.md` — agent-side hook execution mechanics
- `mobile-backend.md` — backend-only flow (skip device)
- KBs: `mobile_deeplink.json` (active in W8), `webview_injection.json` (ref-only — needs on-device JS context)
- Rules: hunting.md R5 / R7 / R8 apply to device data exactly as to server data.
