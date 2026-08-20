"""Service -> enumeration routing for the network pipeline.

The efficiency win: only run the tool that fits an open service. A box with no
445 never gets SMB tools; an LDAP port triggers anon-bind checks; Kerberos
triggers user-enum / AS-REP. Each plan is unauthenticated by default (foothold
phase); cred-gated steps run only when creds are supplied.

A plan step: (tool, args_template, why, needs_creds). Templates interpolate
{ip} {domain} {user} {password} {creds} {userlist}. Missing tools are skipped
by the pipeline (it checks availability), so a partial toolset still runs.

Lead matchers turn raw output into candidate findings — the things worth an
operator's attention (anon access, roastable hashes, signing disabled).
"""

from __future__ import annotations

import re

# service-name substrings / ports -> list of plan steps.
# Keys are matched against BOTH the nmap service name and str(port).
SERVICE_PLANS: dict[str, list[dict]] = {
    "smb": [
        {"tool": "enum4linux-ng", "args": "-A {ip}", "why": "full SMB/RPC enum", "creds": False},
        {"tool": "nxc", "args": "smb {ip} -u '' -p '' --shares", "why": "null-session shares", "creds": False},
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
        {"tool": "certipy", "args": "find -u {user} -p {password} -dc-ip {ip}", "why": "AD-CS ESC scan", "creds": True},
    ],
    "kerberos": [
        {"tool": "nxc", "args": "smb {ip} -u '' -p '' --users", "why": "domain user list (for roasting)", "creds": False},
    ],
    "msrpc": [
        {"tool": "rpcclient", "args": "-U '' -N {ip} -c enumdomusers", "why": "null RPC user enum", "creds": False},
    ],
    "mssql": [
        {"tool": "nxc", "args": "mssql {ip} -u '' -p ''", "why": "MSSQL null / weak auth", "creds": False},
    ],
    "snmp": [
        {"tool": "onesixtyone", "args": "{ip} public", "why": "SNMP public community", "creds": False},
    ],
    "161": [
        {"tool": "onesixtyone", "args": "{ip} public", "why": "SNMP public community", "creds": False},
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
]

# Loot patterns worth auto-capturing to the loot store with chain-of-custody.
LOOT_MATCHERS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\$krb5asrep\$[^\s]+"), "asrep_hash"),
    (re.compile(r"\$krb5tgs\$[^\s]+"), "kerberoast_hash"),
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
