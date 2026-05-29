---
description: Desktop application hunting — Electron / Tauri / WebView2. Static binary inspection + IPC fuzzing + proxied traffic capture. Load when target is a desktop binary.
globs:
---

# Desktop App Hunting — Electron / Tauri / WebView2

Load when: target is a desktop binary (`.app`, `.exe`, `.AppImage`, `.dmg`, `.msi`) or operator says "desktop app".
NOT for: pure web app testing (use hunt.md), mobile (use mobile-mastg.md).

## Honest scope

CloakBrowser does not apply — desktop testing is **out-of-process binary inspection + IPC fuzzing + proxied traffic capture**, not browser automation. The workflow is:

1. Unpack the binary → static audit
2. Run the app behind Burp proxy → dynamic traffic + `match_replace`
3. Force-open DevTools when possible → IPC fuzz from renderer

## Required tools on host

- `npx asar` (npm install -g asar)
- `electronegativity` (npm install -g @doyensec/electronegativity)
- `@electron/fuses` (npx)
- Praetor existing: `run_trufflehog`, `run_gitleaks`, `match_replace`, `concurrent_requests`, `kev_epss_enrich`

## Triage flow

1. **Identify framework**: `file <bin>`, presence of `resources/app.asar` (Electron), `Tauri.toml` / `tauri.conf.json` (Tauri), `WebView2Loader.dll` (WebView2).
2. **Electron path**: unpack ASAR (`npx asar extract resources/app.asar ./out`), run electronegativity (`electronegativity -i ./out -o report.csv`), read `process.versions` from DevTools, map Chrome version to CVEs via `kev_epss_enrich`.
3. **Static sweep** — KB `desktop_electron` lists all patterns:
   - `node_integration_enabled` — `grep -RE 'nodeIntegration\s*:\s*true' ./out`
   - `context_isolation_disabled` — also flag missing flag on Electron <12
   - `preload_dangerous_exposure` — `grep -R 'contextBridge.exposeInMainWorld' -A 20 ./out | grep -E 'child_process|spawn|fs\.|eval|new Function|ipcRenderer\b'`
   - `shell_openexternal_unfiltered` — every caller MUST have a scheme allowlist
   - `ipc_handler_no_origin_check` — every `ipcMain.handle` MUST check `event.sender.getURL()`
   - `custom_protocol_traversal` — every `protocol.register*` caller's URL parser
   - `autoupdate` — `grep -R 'autoUpdater\|electron-updater\|Squirrel\|feedURL' ./out`
4. **Secrets pass**: `run_trufflehog(./out)` + `run_gitleaks(./out)`. ASAR-embedded preload scripts frequently ship hardcoded API tokens.
5. **Electron Fuses**: `npx @electron/fuses read --app <path>`. Flag:
   - `RunAsNode = Enabled` → CVE-2024-23739 class. Critical.
   - `EnableNodeCliInspectArguments = Enabled` → chain with RunAsNode → RCE.
   - `OnlyLoadAppFromAsar = Disabled` or `EmbeddedAsarIntegrityValidation = Disabled` → ASAR swap.
6. **Tauri path**: read `tauri.conf.json` + `src-tauri/capabilities/*.json`. Flag `fs:allow-*` without scope, `shell:allow-execute` without args allowlist, `http:default` without origin allowlist.
7. **WebView2 path**: grep C#/C++ host for `AddHostObjectToScript`, `WebMessageReceived`, `AddWebResourceRequestedFilter`. Each is an attack surface if remote URL is navigable.
7a. **Tauri auto-update audit** (W9):
   - Read `tauri.conf.json` → `updater.endpoints` (list of update servers) and `updater.pubkey` (Ed25519 pubkey for manifest verification).
   - If `updater.pubkey` is empty / placeholder, the updater installs unsigned binaries (`tauri_autoupdate_unsigned`).
   - For each endpoint, MITM the manifest fetch via Burp `match_replace`. Swap the `signature` field — the updater MUST reject. If it accepts, signature verification is broken (`cosign_signature_missing` if Sigstore path).
   - Probe `<endpoint>/<binary>.sig` and `<endpoint>/<binary>.pem` — 404 means no Sigstore bundle is published.
   - For TUF-style update channels (Rust `tuf` crate): fetch `timestamp.json`, check `signed.expires` — older than 7 days = stale rotation (`tauri_autoupdate_tuf_metadata`) → freeze-attack surface.
8. **Dynamic phase** — launch app with `--proxy-server=http://127.0.0.1:8080` + Burp CA in OS trust store. SSL-pin bypass via Frida script if app pins. Common findings:
   - Update channel over HTTP → `match_replace` the manifest `url` field to attacker host → trojan update
   - `shell.openExternal` accepts attacker-controlled link from server response → swap link via `match_replace` to `javascript:` / `file:` / `smb://`
   - Custom protocol handler invoked from `open myapp://payload` → traversal in URL parser
   - IPC fuzz from DevTools when reachable — enumerate `Object.keys(window).filter(k => k.includes('electron'))`

## Evidence shape for save_finding

- `vuln_type`: pick from the desktop_electron context list (`electron_node_integration`, `electron_context_isolation_disabled`, `electron_preload_overexposure`, `electron_shell_openexternal_rce`, `electron_ipc_no_origin_check`, `electron_autoupdate_mitm`, `electron_fuse_runasnode`, `electron_custom_protocol_traversal`, `tauri_capability_bypass`, `webview2_host_bridge_abuse`, `v8_patch_gap`)
- `evidence` MUST include:
  - For static findings: `file_path` + `line_number` + grep match
  - For dynamic findings: `logger_index` from Burp + reproductions[] ≥3
- `chain_with[]` required when alone is NEVER_SUBMIT (Rule 17):
  - ASAR disclosure alone
  - `will-navigate` missing alone
  - Missing CSP on local content alone

## Reporting cap (severity discipline)

- Standalone `nodeIntegration: true` on **local-only** content with no remote nav: Medium.
- Same flag + remote content reachable + XSS sink: Critical.
- Auto-update over HTTP without signature: Critical (Rocket.Chat class).
- `shell.openExternal` accepting `javascript:` / `file:` / UNC: High → Critical.
- Electron Fuse `RunAsNode = Enabled` on production binary: Critical (CVE-2024-23739).

## Handoff to other surfaces

- Web requests from the app go in Burp like any web target. After capture, run `auto_probe` / `test_auth_matrix` against the captured API endpoints — desktop apps often expose admin APIs hidden from the web UI.
- ASAR-extracted JS sources are first-class input to `run_xvulnhuntr` / `run_vulnhuntr` for LLM-chain SAST on the renderer + preload bundles.
- Use `chain-findings.md` to chain ASAR disclosure (NEVER_SUBMIT alone) with a confirmed secret leak from `run_trufflehog`.
