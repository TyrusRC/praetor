"""Red-team operator log + loot chain-of-custody — the non-Burp evidence store.

Network/AD/post-ex tools bypass Burp, so their evidence lands here: an
append-only operator log (Ghostwriter oplog schema) plus a loot manifest.
Files under .burp-intel/<domain>/network/: oplog.jsonl, loot.jsonl, loot/<id>
(the artifact itself; manifest keeps sha256 + redacted shape, not the secret).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from burpsuite_mcp.tools.notes._helpers import _findings_lock
from burpsuite_mcp.tools.workspace import ensure_workspace

# tool / action -> (ATT&CK tactic, technique id, technique name). Auto-tags an
# entry so the report and an ATT&CK Navigator layer come for free. Matched on
# the leading token of the tool name (impacket-secretsdump -> secretsdump).
ATTACK_MAP: dict[str, tuple[str, str, str]] = {
    "nmap": ("Discovery", "T1046", "Network Service Discovery"),
    "masscan": ("Discovery", "T1046", "Network Service Discovery"),
    "rustscan": ("Discovery", "T1046", "Network Service Discovery"),
    "gobuster": ("Discovery", "T1083", "File and Directory Discovery"),
    "feroxbuster": ("Discovery", "T1083", "File and Directory Discovery"),
    "ffuf": ("Discovery", "T1083", "File and Directory Discovery"),
    "enum4linux": ("Discovery", "T1087", "Account Discovery"),
    "enum4linux-ng": ("Discovery", "T1087", "Account Discovery"),
    "smbmap": ("Discovery", "T1135", "Network Share Discovery"),
    "bloodhound": ("Discovery", "T1482", "Domain Trust Discovery"),
    "bloodhound-python": ("Discovery", "T1482", "Domain Trust Discovery"),
    "sharphound": ("Discovery", "T1482", "Domain Trust Discovery"),
    "kerbrute": ("Credential Access", "T1110.003", "Password Spraying"),
    "responder": ("Credential Access", "T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay"),
    "ntlmrelayx": ("Credential Access", "T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay"),
    "secretsdump": ("Credential Access", "T1003", "OS Credential Dumping"),
    "mimikatz": ("Credential Access", "T1003.001", "LSASS Memory"),
    "lsassy": ("Credential Access", "T1003.001", "LSASS Memory"),
    "ntdsutil": ("Credential Access", "T1003.003", "NTDS"),
    "hashcat": ("Credential Access", "T1110.002", "Password Cracking"),
    "john": ("Credential Access", "T1110.002", "Password Cracking"),
    "hydra": ("Credential Access", "T1110", "Brute Force"),
    "certipy": ("Credential Access", "T1649", "Steal or Forge Authentication Certificates"),
    "getuserspns": ("Credential Access", "T1558.003", "Kerberoasting"),
    "getnpusers": ("Credential Access", "T1558.004", "AS-REP Roasting"),
    "netexec": ("Lateral Movement", "T1021", "Remote Services"),
    "crackmapexec": ("Lateral Movement", "T1021", "Remote Services"),
    "nxc": ("Lateral Movement", "T1021", "Remote Services"),
    "psexec": ("Execution", "T1569.002", "Service Execution"),
    "wmiexec": ("Execution", "T1047", "Windows Management Instrumentation"),
    "smbexec": ("Execution", "T1021.002", "SMB/Windows Admin Shares"),
    "evil-winrm": ("Execution", "T1021.006", "Windows Remote Management"),
    "ligolo-ng": ("Command and Control", "T1090", "Proxy"),
    "chisel": ("Command and Control", "T1090", "Proxy"),
    "linpeas": ("Discovery", "T1082", "System Information Discovery"),
    "winpeas": ("Discovery", "T1082", "System Information Discovery"),
    "msfvenom": ("Resource Development", "T1587.001", "Develop Capabilities: Malware"),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _next_seq(path: Path) -> int:
    """Next 1-based sequence number = existing line count + 1 (handle closed)."""
    if not path.exists():
        return 1
    with path.open(encoding="utf-8") as fh:
        return sum(1 for _ in fh) + 1


def _oplog_path(domain: str) -> Path:
    return ensure_workspace(domain)["network"] / "oplog.jsonl"


def _loot_manifest(domain: str) -> Path:
    return ensure_workspace(domain)["network"] / "loot.jsonl"


def attack_for(tool: str) -> tuple[str, str, str]:
    """(tactic, technique_id, technique_name) for a tool, or ('','','')."""
    key = (tool or "").lower().split("/")[-1]
    if key in ATTACK_MAP:
        return ATTACK_MAP[key]
    # impacket-secretsdump / GetUserSPNs.py style — match on any known token.
    for token, val in ATTACK_MAP.items():
        if token in key:
            return val
    return ("", "", "")


def record_action(
    domain: str,
    tool: str,
    command: str,
    *,
    description: str = "",
    source: str = "",
    target: str = "",
    output: str = "",
    output_path: str = "",
    user_context: str = "",
    operator: str = "",
    tactic: str = "",
    technique: str = "",
    tags: list[str] | None = None,
    detected: bool | None = None,
    returncode: int | None = None,
    start: str = "",
    end: str = "",
) -> str:
    """Append one operator-log entry (Ghostwriter schema). Returns oplog id.

    ATT&CK tactic/technique auto-fill from the tool when not supplied. `output`
    is truncated in the ledger; large output belongs in output_path (a file
    under material/tool-output/). Serialised under a lock so concurrent agents
    on one engagement don't interleave lines.
    """
    ts = _now()
    a_tactic, a_tech, a_name = attack_for(tool)
    tactic = tactic or a_tactic
    technique = technique or a_tech
    auto_tags = list(tags or [])
    if technique:
        auto_tags.append(f"ttp:{technique}")
    path = _oplog_path(domain)
    # Sequence = line count + 1, computed under the lock.
    with _findings_lock(path):
        seq = _next_seq(path)
        entry = {
            "id": f"op{seq:04d}",
            "seq": seq,
            "start": start or ts,
            "end": end or ts,
            "operator": operator,
            "source": source,
            "target": target,
            "tool": tool,
            "command": command,
            "description": description,
            "output": (output[:2000] if output else ""),
            "output_path": output_path,
            "user_context": user_context,
            "tactic": tactic,
            "technique": technique,
            "technique_name": a_name if technique == a_tech else "",
            "tags": sorted(set(auto_tags)),
            "detected": detected,
            "returncode": returncode,
            "recorded": ts,
        }
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    return entry["id"]


def read_oplog(domain: str) -> list[dict]:
    path = _oplog_path(domain)
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _shape(value: str) -> str:
    """Redacted preview — enough to recognise, never the whole secret."""
    v = value.strip()
    if not v:
        return ""
    if len(v) <= 12:
        return v[:2] + "…"
    return f"{v[:6]}…{v[-4:]} (len {len(v)})"


def record_loot(
    domain: str,
    loot_type: str,
    value: str,
    *,
    source_host: str = "",
    obtained_via: str = "",
    oplog_id: str = "",
    is_path: bool = False,
) -> dict:
    """Record a captured artifact with chain-of-custody. Returns the manifest row.

    The artifact bytes go to network/loot/<id> (gitignored operator disk); the
    manifest stores type, provenance, sha256, size and a redacted shape — never
    the plaintext secret. `value` is the artifact string, or a path when
    is_path=True (the file is copied into the loot store).
    """
    paths = ensure_workspace(domain)
    loot_dir = paths["loot"]
    manifest = _loot_manifest(domain)

    if is_path:
        src = Path(value)
        data = src.read_bytes()
        preview = f"file:{src.name}"
    else:
        data = value.encode("utf-8", "replace")
        preview = _shape(value)

    sha = _sha256(data)
    with _findings_lock(manifest):
        seq = _next_seq(manifest)
        loot_id = f"loot{seq:04d}"
        stored = loot_dir / loot_id
        stored.write_bytes(data)
        row = {
            "id": loot_id,
            "type": loot_type,
            "source_host": source_host,
            "obtained_via": obtained_via,
            "oplog_id": oplog_id,
            "sha256": sha,
            "size": len(data),
            "preview": preview,
            "stored_path": str(stored),
            "recorded": _now(),
        }
        with manifest.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
    return row


def read_loot(domain: str) -> list[dict]:
    path = _loot_manifest(domain)
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out
