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
        "note": "LDAP collection is Burp-blind. Ingest graph + query shortest-path-to-DA.",
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
        "purpose": "AD Certificate Services abuse (ESC1-8 enumeration + exploitation).",
        "install": {"kali": "sudo apt install certipy-ad", "other": "pipx install certipy-ad"},
        "note": "LDAP/RPC/HTTP-enrollment mix — mostly Burp-blind.",
    },
    "kerbrute": {
        "tier": "C", "routes_burp": False,
        "purpose": "Kerberos pre-auth user enumeration + password spray.",
        "install": {"kali": "sudo apt install kerbrute", "other": "go install github.com/ropnop/kerbrute@latest"},
        "note": "Spray touches Rule 6; user-enum via Kerberos is enumeration, allowed.",
    },
    "hydra": {
        "tier": "C", "routes_burp": False,
        "purpose": "Network login brute-force (many protocols).",
        "install": {"kali": "sudo apt install hydra", "other": "https://github.com/vanhauser-thc/thc-hydra"},
        "note": "CONFLICTS with HARD Rule 6 (no credential brute-force). Only default/known-cred checks or authorized spray — dictionary brute is refused.",
    },
}
