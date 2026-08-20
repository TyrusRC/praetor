"""Post-exploitation MCP tools: offline hash cracking + credential store.

  crack_hashes      - hashcat/john over captured loot; cracked -> credentials
  record_credential - add a captured/known credential to the reuse store
  list_credentials  - read the store (secrets redacted)

Cracking is OFFLINE (no network, no target) — outside HARD Rule 6 (which covers
online credential brute-force). Every crack run is recorded in the operator log
with ATT&CK T1110.002; cracked secrets auto-record as credentials so the next
lateral-movement step can reuse them (the OSEP loop: capture -> crack -> reuse).
"""

from __future__ import annotations

import re
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _check_tool, _run_cmd

from ._creds import list_credentials as _list_credentials
from ._creds import record_credential as _record_credential
from ._creds import redact
from ._oplog import record_action

# hash_type -> hashcat -m mode. Names match what the pipeline/loot store tags.
HASHCAT_MODES = {
    "ntlm": "1000", "asrep": "18200", "kerberoast": "13100", "tgs": "13100",
    "asrep_hash": "18200", "kerberoast_hash": "13100", "ntlm_hash": "1000",
    "netntlmv2": "5600", "netntlm": "5500", "md5": "0", "sha1": "100",
    "sha256": "1400", "sha512": "1700", "sha512crypt": "1800", "md5crypt": "500",
    "bcrypt": "3200", "mysql": "300", "mscache2": "2100", "wpa": "22000",
    # Timeroasting — DC-signed NTP MAC derived from a computer account's NT hash.
    "timeroast": "31300", "sntp": "31300", "timeroast_hash": "31300",
}
_COMMON_WORDLISTS = (
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
    "/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt",
)
# hash:password lines from `hashcat --show`. Username, when the hash format
# embeds one (AS-REP / kerberoast), is pulled out for the credential store.
_ASREP_USER = re.compile(r"\$krb5asrep\$\d+\$([^@:]+)@", re.I)
_TGS_USER = re.compile(r"\$krb5tgs\$\d+\$\*([^$]+)\$", re.I)
# Timeroast lines are `<RID>:$sntp-ms$...`; the RID maps to a computer account
# (resolve via BloodHound — RID -> IT-COMPUTER3$). Store the cred as RID-<n>.
_TIMEROAST_RID = re.compile(r"^(\d+):\$sntp-ms\$", re.I | re.M)


def _default_wordlist() -> str:
    for w in _COMMON_WORDLISTS:
        if Path(w).exists():
            return w
    return ""


def _username_from_hash(h: str) -> str:
    m = _ASREP_USER.search(h) or _TGS_USER.search(h)
    if m:
        return m.group(1)
    rid = _TIMEROAST_RID.search(h)
    return f"RID-{rid.group(1)}" if rid else ""


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def crack_hashes(
        domain: str,
        hash_type: str,
        hashes: str = "",
        loot_type: str = "",
        wordlist: str = "",
        timeout: int = 1800,
    ) -> str:
        """Crack captured hashes offline (hashcat, fallback john). Cracked ->
        credential store, logged to the operator log (ATT&CK T1110.002).

        Args:
            domain: engagement key.
            hash_type: ntlm | asrep | kerberoast | netntlmv2 | sha512crypt |
                md5crypt | bcrypt | md5 | ... (maps to the hashcat -m mode).
            hashes: hashes to crack (newline/space separated). Leave blank and
                set loot_type to pull every matching hash from the loot store.
            loot_type: pull hashes of this type from the loot store
                (asrep_hash | kerberoast_hash | ntlm_hash).
            wordlist: path; blank auto-detects rockyou / SecLists.
            timeout: seconds (default 1800).

        OFFLINE — not Rule-6 online brute. Returns cracked user:secret (secret
        redacted) and the credential ids created.
        """
        mode = HASHCAT_MODES.get(hash_type.lower())
        if not mode:
            return (f"Unknown hash_type {hash_type!r}. Known: {', '.join(sorted(set(HASHCAT_MODES)))}.")

        hash_list = [h for h in re.split(r"[\s]+", hashes.strip()) if h] if hashes.strip() else []
        if loot_type and not hash_list:
            from ._oplog import read_loot
            for row in read_loot(domain):
                if row.get("type") == loot_type:
                    p = Path(row.get("stored_path", ""))
                    if p.exists():
                        hash_list.append(p.read_text(encoding="utf-8").strip())
        if not hash_list:
            return "No hashes to crack (pass hashes= or a loot_type present in the loot store)."

        wl = wordlist or _default_wordlist()
        if not wl or not Path(wl).exists():
            return ("No wordlist found. Pass wordlist=/path, or install rockyou "
                    "(sudo apt install wordlists; gunzip /usr/share/wordlists/rockyou.txt.gz).")

        cracker = "hashcat" if _check_tool("hashcat") else ("john" if _check_tool("john") else "")
        if not cracker:
            return "Neither hashcat nor john installed. redteam_tool_guide(tool='hashcat')."

        # Write hashes to a workspace temp file; crack; then read back cracked pairs.
        from praetor.tools.network._store import write_tool_output
        hfile = write_tool_output(domain, "crack-input.hashes", "\n".join(hash_list))
        potfile = str(Path(hfile).with_suffix(".potfile"))

        if cracker == "hashcat":
            run = ["hashcat", "-m", mode, "-a", "0", str(hfile), wl,
                   "--potfile-path", potfile, "--quiet"]
            await _run_cmd(run, timeout=timeout, bypass_proxy=True)
            show = ["hashcat", "-m", mode, str(hfile), "--show",
                    "--potfile-path", potfile, "--quiet"]
            out, _err, _rc = await _run_cmd(show, timeout=120, bypass_proxy=True)
        else:  # john
            run = ["john", f"--format=raw-{hash_type}", f"--wordlist={wl}", str(hfile)]
            await _run_cmd(run, timeout=timeout, bypass_proxy=True)
            out, _err, _rc = await _run_cmd(["john", "--show", str(hfile)], timeout=120, bypass_proxy=True)

        # Parse `hash:password` lines; last colon-field is the password.
        cracked: list[tuple[str, str]] = []
        for line in out.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            h, _, pw = line.rpartition(":")
            if pw:
                cracked.append((h, pw))

        op_id = record_action(
            domain, cracker, " ".join(run), target="(offline)",
            description=f"crack {len(hash_list)} {hash_type} hashes",
            technique="T1110.002", tactic="Credential Access",
            output=f"{len(cracked)} cracked", returncode=0)

        if not cracked:
            return (f"crack_hashes: 0/{len(hash_list)} {hash_type} cracked with "
                    f"{Path(wl).name} [{cracker}, {op_id}]. Try a bigger wordlist / rules.")

        cred_ids, lines = [], []
        for h, pw in cracked:
            user = _username_from_hash(h) or (h[:16] + "…")
            row = _record_credential(domain, user, pw,
                                     secret_type="password" if hash_type != "ntlm" else "ntlm",
                                     source=f"cracked:{hash_type}:{op_id}")
            cred_ids.append(row["_id"])
            lines.append(f"    {user}:{redact(pw)} -> {row['_id']}")
        return (f"crack_hashes: {len(cracked)}/{len(hash_list)} cracked "
                f"[{cracker}, {op_id}] -> credentials {', '.join(cred_ids)}\n" + "\n".join(lines))

    @mcp.tool()
    async def record_credential(
        domain: str,
        username: str,
        secret: str,
        secret_type: str = "password",
        realm: str = "",
        source: str = "",
        valid_on: str = "",
    ) -> str:
        """Add a captured/known credential to the reuse store (secret redacted in output).

        Args:
            domain: engagement key.
            username: account name.
            secret: password / NT hash / AES key (kept usable on disk, redacted in logs).
            secret_type: password | ntlm | aes256 | aes128 | kerberos_ticket | ssh_key.
            realm: AD domain / host realm the cred belongs to.
            source: where it came from ('responder', 'secretsdump', 'cracked').
            valid_on: comma-separated hosts/IPs the cred is known to work on.
        """
        hosts = [h.strip() for h in valid_on.split(",") if h.strip()] if valid_on else []
        row = _record_credential(domain, username, secret, secret_type=secret_type, realm=realm,
                  source=source, valid_on=hosts)
        verb = "merged into" if row.get("merged") else "stored as"
        return (f"Credential {verb} {row['_id']}: "
                f"{(realm + chr(92)) if realm else ''}{username} [{secret_type}] "
                f"= {row['secret']} (source={source or '?'})")

    @mcp.tool()
    async def list_credentials(domain: str, realm: str = "") -> str:
        """List stored credentials (secrets redacted). Filter by realm when given."""
        creds = _list_credentials(domain, realm)
        if not creds:
            return f"No credentials stored for {domain!r}{f' realm={realm}' if realm else ''}."
        lines = [f"Credentials for {domain} ({len(creds)}):"]
        for c in creds:
            on = f" valid_on={','.join(c['valid_on'])}" if c.get("valid_on") else ""
            r = f"{c['realm']}\\" if c.get("realm") else ""
            lines.append(f"  {c['id']} {r}{c['username']} [{c['secret_type']}] "
                         f"= {c['secret']} (src {c.get('source', '?')}){on}")
        return "\n".join(lines)
