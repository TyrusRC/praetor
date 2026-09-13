---
name: phone-control
description: End-to-end device control flow — connect, verify traffic reaches Burp (DHCP-robust), unlock pinned traffic, drive the UI, capture and hand off. Load when driving a phone (Android or iOS) directly via mobile_* tools, or when device traffic isn't showing up in Burp.
---

# Phone Control

Five phases. Don't skip the proxy pre-flight — most "no traffic captured"
failures are DHCP drift or a loopback-bound Burp listener, not a pinning
problem.

## 1. Connect

`mobile_devices()` — device must show `authorized: true`.

- **Prefer wireless adb over WSL usbip once paired.** usbip resets the device
  mid-transfer on anything large (a 20-58MB frida-server or APK push) — it is a
  connect-time bridge, not a bulk-transfer-reliable one. Pair once over USB
  (`mobile_connect(action='tcpip')`), then use `mobile_connect(action='connect',
  ip=<device-ip>, port=5555)` for the rest of the session; Android 11+ wireless
  debugging pairs first with `mobile_connect(action='pair', ip=<device-ip>,
  code=<pairing-code>)`. Use the returned `serial` as `device=` on every other
  mobile_* tool. `mobile_connect(action='auto')` does this in one call — it
  derives the phone's current Wi-Fi IP over USB and connects, no manual `ip=`
  (DHCP-proof; no-ops if already on wireless adb).
- **WSL + USB Android (when wireless isn't an option):** Windows admin
  PowerShell `usbipd bind`/`usbipd attach --wsl`; WSL side `sudo modprobe
  vhci_hcd` (`doctor.sh` checks both). Devices drop on big transfers or screen
  lock — re-attach with `usbipd attach --wsl --busid <id>` + `adb
  wait-for-device`, and keep the screen awake during a long session
  (`adb shell svc power stayon usb`).
- **iOS:** go-ios (`mobile_devices`) — no Mac needed. Needs `usbmuxd` running
  (`sudo usbmuxd`; `doctor.sh` warns if it isn't) and the device paired once
  (`idevicepair pair`, then tap Trust on the device). See the iOS-on-Linux note
  in Phase 3/4 below for what works without a signed WebDriverAgent.

## 2. Proxy pre-flight (DHCP-robust) — gate, don't skip

1. USB Android → `mobile_set_proxy(mode="reverse")` (adb reverse, 127.0.0.1-based,
   immune to DHCP). Wireless Android / unstable LAN → `mobile_set_proxy(mode="tailscale")`.
   iOS → `mobile_set_proxy` is Android-only; set the device's Wi-Fi proxy manually
   to a stable host address (Tailscale IP or a DHCP reservation), or push a
   `.mobileconfig`.
2. `mobile_proxy_status(canary=True)` — fires one request from the device and
   confirms it lands in Burp proxy history.
3. **Don't proceed to Unlock/Drive until `routing_ok: true` AND `canary_landed:
   true`.** A `false` here means findings captured downstream are missing
   traffic silently, not that the target is clean.

**DHCP/IP-drift note:** the device's proxy config holds a raw IP; when the
host's LAN IP changes (lease renewal, wifi reconnect) the device silently
stops reaching Burp with no error on either side. `mobile_proxy_status` flags
the mismatch; re-run `mobile_set_proxy` with the same mode to fix. `reverse`
(USB) and `tailscale` modes are immune to this — prefer them over `lan` for
anything longer than a one-off check.

**Mirrored-WSL note:** when Burp runs on Windows and WSL is in mirrored
networking mode, `ss`/`netstat` inside WSL cannot see the Windows-side
listener — it looks unbound even when it's fine. `mobile_proxy_status`'s canary
is a real TCP connect + request probe, not a local socket check, so a landed
canary is ground truth regardless of what `ss` shows.

Scope the target and drop intercept before driving the device: `burp_settings`
(`scope_add`, `intercept_off`) — single dispatcher over Montoya-settable Burp
settings; see its docstring for the manual-only items (proxy listener,
upstream proxy, TLS).

## 3. Unlock (pinning / root-detection)

**Android — frida-server bring-up (device must be rooted, Magisk/KernelSU):**
push a frida-server build matching the host's `frida-tools` version and the
device's arch (arm64 on virtually all real hardware) to `/data/local/tmp/`
**over the wireless adb session, not usbip** — a 50-60MB push is exactly what
resets a WSL usbip device mid-transfer. Then `chmod 755`, start it as root and
daemonized (`su -c '/data/local/tmp/frida-server -D'`), and confirm with
`frida-ps -U` before touching the app. Only then
`mobile_frida_run(script="ssl_pin_universal_android", package=<pkg>)`.

**iOS:** `mobile_frida_run(script="ssl_pin_universal_ios", package=<bundle>)`.

Either platform, if the app still refuses to start: `root_jailbreak_bypass`.
Guarded Android settings reads/writes (e.g. checking `adb_enabled` or
`install_non_market_apps`) go through `mobile_setting` — destructive writes
(lock screen, package verifier, provisioning) are refused before the device
is touched.
Full cadence: `playbook-mobile-dynamic.md` / `mobile-dynamic-agent`.

**iOS-on-Linux (go-ios + libimobiledevice, Mac-free), what actually works today:**
device discovery, info and app listing (`mobile_devices`, `mobile_device_info`,
`mobile_app_list`) work over plain usbmuxd once paired — no WDA needed.
`mobile_screenshot` additionally needs the Developer Disk Image mounted (`ios
image auto`) or a running WDA; on some jailbroken devices the DDI mount is slow
or fails outright — it degrades cleanly (skip), it isn't a hard blocker for the
rest of the flow. UI tap/swipe (Phase 4) needs a **signed WebDriverAgent**
already installed and trusted on the device — Praetor doesn't sign or install
one. Without it, a jailbroken device still gives on-device access for
frida/inspection: USB SSH via `iproxy 2222 22 -u <udid>` then `ssh
mobile@127.0.0.1 -p 2222` (install/run frida on-device), or `frida-ps -D
<udid>` directly over usbmuxd.

## 4. Drive

`mobile_screenshot` + `mobile_ui_dump` → `mobile_tap`/`mobile_swipe`/
`mobile_input_text`/`mobile_key` — same tools on both platforms.

- **iOS-on-Linux:** UI driving goes through WebDriverAgent (go-ios), not idb.
  It starts lazily on first `mobile_tap`/`mobile_ui_dump`; call
  `mobile_wda_start(device=...)` explicitly first to warm it up and surface a
  startup failure up front instead of mid-flow. Requires a **signed
  WebDriverAgent build already installed/trusted on the device** — Praetor
  doesn't sign or install it; `mobile_wda_start` raises a clear error naming
  this when WDA never responds. `mobile_wda_stop` when done to free the
  device-side session and kill the go-ios forward.

## 5. Capture + hand off

Traffic is already flowing per step 2's canary. Pull it into the web lane:

`get_proxy_history`/`search_history` → `extract_api_endpoints` →
`build_target_header_profile(domain)` → `auto_probe`. Loot
(files, prefs, DBs) via `mobile_pull_file`.

Full backend handoff + MASTG mapping: `playbook-mobile-dynamic.md` Phase 3,
`playbook-mobile-backend.md` §3.
