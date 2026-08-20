"""Credential store — the reuse substrate for the OSEP kill-chain loop.

Captured or cracked credentials live here so the next step (spray, authenticated
enum, lateral movement) can reuse them. Stored at
`.burp-intel/<domain>/network/credentials.json` (gitignored operator disk).

The secret is kept usable (spraying needs it) but every tool that RENDERS a
credential redacts it to a shape — the plaintext never reaches the transcript.
Deduped by (realm, username, secret_type, secret).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from burpsuite_mcp.tools.notes._helpers import _findings_lock, atomic_write_json
from burpsuite_mcp.tools.workspace import ensure_workspace

VALID_TYPES = {"password", "ntlm", "aes256", "aes128", "kerberos_ticket", "ssh_key"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _path(domain: str) -> Path:
    return ensure_workspace(domain)["network"] / "credentials.json"


def _load(domain: str) -> list[dict]:
    p = _path(domain)
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []


def redact(secret: str) -> str:
    """Shape preview — recognisable, never the whole secret."""
    s = (secret or "").strip()
    if not s:
        return ""
    if len(s) <= 8:
        return s[:2] + "…"
    return f"{s[:4]}…{s[-2:]} (len {len(s)})"


def record_credential(
    domain: str,
    username: str,
    secret: str,
    *,
    secret_type: str = "password",
    realm: str = "",
    source: str = "",
    valid_on: list[str] | None = None,
) -> dict:
    """Add/merge a credential. Returns the stored row (secret redacted for logs).

    Deduped by (realm, username, secret_type, secret); a repeat merges valid_on
    hosts rather than duplicating.
    """
    stype = secret_type if secret_type in VALID_TYPES else "password"
    path = _path(domain)
    with _findings_lock(path):
        creds = _load(domain)
        key = (realm.lower(), username.lower(), stype, secret)
        for c in creds:
            if (c.get("realm", "").lower(), c.get("username", "").lower(),
                    c.get("secret_type"), c.get("secret")) == key:
                hosts = set(c.get("valid_on", [])) | set(valid_on or [])
                c["valid_on"] = sorted(h for h in hosts if h)
                c["last_seen"] = _now()
                atomic_write_json(path, creds, prefix=".creds-")
                return {**c, "secret": redact(c["secret"]), "_id": c["id"], "merged": True}
        cid = f"cred{len(creds) + 1:03d}"
        row = {
            "id": cid, "username": username, "secret": secret,
            "secret_type": stype, "realm": realm, "source": source,
            "valid_on": sorted(set(valid_on or [])), "recorded": _now(), "last_seen": _now(),
        }
        creds.append(row)
        atomic_write_json(path, creds, prefix=".creds-")
        return {**row, "secret": redact(secret), "_id": cid, "merged": False}


def list_credentials(domain: str, realm: str = "") -> list[dict]:
    """Return credentials (secret redacted). Filter by realm when given."""
    out = []
    for c in _load(domain):
        if realm and c.get("realm", "").lower() != realm.lower():
            continue
        out.append({**c, "secret": redact(c.get("secret", ""))})
    return out


def get_secret(domain: str, cred_id: str) -> dict | None:
    """Return the FULL credential (unredacted) for internal use (spray/auth)."""
    for c in _load(domain):
        if c.get("id") == cred_id:
            return c
    return None

