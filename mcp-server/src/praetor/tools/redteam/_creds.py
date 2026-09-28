"""Credential store — the reuse substrate for the OSEP kill-chain loop.

Captured or cracked credentials live here so the next step (spray, authenticated
enum, lateral movement) can reuse them. Stored at
`.burp-intel/<domain>/network/credentials.json` (gitignored operator disk).

Secrets are ENCRYPTED AT REST (Fernet / AES-128-CBC+HMAC) — the plaintext never
touches the JSON on disk, and a stray `grep`/accidental commit can't leak it.
Each row keeps only `secret_enc` (ciphertext), `secret_preview` (a redacted
shape for display) and `secret_fp` (a keyed fingerprint for dedup). The plaintext
is recovered only by `get_secret()` for actual reuse (spray/auth), and every
render still shows the redacted shape — the plaintext never reaches the transcript.

Key: `$PRAETOR_CRED_KEY` (any passphrase, derived to a Fernet key) if set,
otherwise a random key generated once into `<workspace>/network/credentials.key`
(0600, gitignored). record_credential surfaces the key location in a note — LOSE
THE KEY AND THE STORED SECRETS ARE UNRECOVERABLE.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from praetor.tools.notes._helpers import _findings_lock, atomic_write_json
from praetor.tools.workspace import ensure_workspace

VALID_TYPES = {"password", "ntlm", "aes256", "aes128", "kerberos_ticket", "ssh_key"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _path(domain: str) -> Path:
    return ensure_workspace(domain)["network"] / "credentials.json"


def _key_path(domain: str) -> Path:
    return ensure_workspace(domain)["network"] / "credentials.key"


def _load_key(domain: str) -> tuple[bytes, str]:
    """Return (fernet_key, human source). Env passphrase wins; else a per-
    workspace random key file (created 0600 on first use)."""
    env = os.environ.get("PRAETOR_CRED_KEY")
    if env:
        # Any passphrase → a valid 32-byte urlsafe-b64 Fernet key.
        derived = base64.urlsafe_b64encode(hashlib.sha256(env.encode()).digest())
        return derived, "$PRAETOR_CRED_KEY"
    kp = _key_path(domain)
    if kp.exists():
        return kp.read_bytes().strip(), str(kp)
    key = Fernet.generate_key()
    kp.write_bytes(key)
    try:
        os.chmod(kp, 0o600)
    except OSError:
        pass
    return key, str(kp)


def _fernet(domain: str) -> Fernet:
    return Fernet(_load_key(domain)[0])


def _encrypt(domain: str, secret: str) -> str:
    return _fernet(domain).encrypt((secret or "").encode()).decode()


def _decrypt(domain: str, token: str) -> str:
    try:
        return _fernet(domain).decrypt((token or "").encode()).decode()
    except (InvalidToken, ValueError):
        return ""


def _fingerprint(domain: str, secret: str) -> str:
    """Deterministic keyed fingerprint for dedup (Fernet ciphertext is random,
    so dedup can't compare it). Non-reversible; needs the key to reproduce."""
    key = _load_key(domain)[0]
    return hmac.new(key, (secret or "").encode(), hashlib.sha256).hexdigest()[:16]


def _load(domain: str) -> list[dict]:
    p = _path(domain)
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []


def _plaintext(domain: str, row: dict) -> str:
    """Recover a row's plaintext — from secret_enc, or a legacy plaintext row."""
    if row.get("secret_enc"):
        return _decrypt(domain, row["secret_enc"])
    return row.get("secret", "")   # pre-encryption row (migrated on next write)


def _public(row: dict) -> dict:
    """Row safe to return/render: ciphertext + fingerprint stripped, secret shown
    as its redacted preview only."""
    out = {k: v for k, v in row.items() if k not in ("secret_enc", "secret_fp", "secret")}
    out["secret"] = row.get("secret_preview") or redact(row.get("secret", ""))
    return out


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
        _, key_src = _load_key(domain)
        fp = _fingerprint(domain, secret)
        # Dedup on the keyed fingerprint (ciphertext is non-deterministic); a
        # legacy plaintext row is matched by re-fingerprinting its secret.
        key = (realm.lower(), username.lower(), stype, fp)
        for c in creds:
            c_fp = c.get("secret_fp") or _fingerprint(domain, c.get("secret", ""))
            if (c.get("realm", "").lower(), c.get("username", "").lower(),
                    c.get("secret_type"), c_fp) == key:
                hosts = set(c.get("valid_on", [])) | set(valid_on or [])
                c["valid_on"] = sorted(h for h in hosts if h)
                c["last_seen"] = _now()
                # Migrate a legacy plaintext row to encrypted-at-rest in place.
                if "secret" in c and not c.get("secret_enc"):
                    c["secret_enc"] = _encrypt(domain, c.pop("secret"))
                    c["secret_preview"] = redact(secret)
                    c["secret_fp"] = fp
                atomic_write_json(path, creds, prefix=".creds-")
                return {**_public(c), "_id": c["id"], "merged": True,
                        "key_note": _key_note(key_src)}
        cid = f"cred{len(creds) + 1:03d}"
        row = {
            "id": cid, "username": username,
            "secret_enc": _encrypt(domain, secret),
            "secret_preview": redact(secret),
            "secret_fp": fp,
            "secret_type": stype, "realm": realm, "source": source,
            "valid_on": sorted(set(valid_on or [])), "recorded": _now(), "last_seen": _now(),
        }
        creds.append(row)
        atomic_write_json(path, creds, prefix=".creds-")
        return {**_public(row), "_id": cid, "merged": False,
                "key_note": _key_note(key_src)}


def _key_note(src: str) -> str:
    return (f"secret encrypted at rest (Fernet); decryption key = {src}. "
            "Back it up — losing the key makes stored secrets unrecoverable.")


def list_credentials(domain: str, realm: str = "") -> list[dict]:
    """Return credentials (secret redacted). Filter by realm when given."""
    out = []
    for c in _load(domain):
        if realm and c.get("realm", "").lower() != realm.lower():
            continue
        out.append(_public(c))
    return out


def get_secret(domain: str, cred_id: str) -> dict | None:
    """Return the FULL credential with DECRYPTED secret for internal reuse
    (spray/auth). Never render this row directly — it carries the plaintext."""
    for c in _load(domain):
        if c.get("id") == cred_id:
            return {**c, "secret": _plaintext(domain, c)}
    return None

