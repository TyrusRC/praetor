"""Encrypted-OAST crypto + pool helpers for the Collaborator tools."""

import asyncio
import base64
import os
import re
from pathlib import Path

# --- Encrypted OAST (blind-exfil data protection) --------------------------
# When a blind-exfil payload smuggles data out over DNS/HTTP to a Collaborator
# (or operator callback), the OOB provider logs the *content* in cleartext. A
# local symmetric key lets the target encrypt the value client-side (before it
# hits the wire) so the provider only ever sees ciphertext; the operator
# decrypts locally. The key is target-visible (it rides in the injection
# payload) but never reaches the OOB provider — that is the threat model.
#
# Key lives under .burp-intel/_oast_key/ (already gitignored via .burp-intel/),
# dir 0700 / key 0600. Rule 9a is untouched: the real callback domain still
# comes from generate_collaborator_payload / an operator-provided callback —
# this layer only wraps the exfiltrated DATA.

_OAST_KEY_NAME = "fernet.key"


def _oast_key_dir() -> Path:
    return Path.cwd() / ".burp-intel" / "_oast_key"


def _get_oast_fernet():
    """Load-or-create the local OAST symmetric key.

    Returns (fernet, key_str, error). `error` is a non-empty operator-facing
    message when the `cryptography` package is missing or the key can't be
    persisted; in that case fernet is None.
    """
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None, "", (
            "Encrypted OAST needs the `cryptography` package "
            "(uv pip install cryptography). Feature unavailable until installed."
        )
    key_dir = _oast_key_dir()
    key_path = key_dir / _OAST_KEY_NAME
    try:
        key_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(key_dir, 0o700)
        if key_path.exists():
            key = key_path.read_bytes().strip()
        else:
            key = Fernet.generate_key()
            # O_CREAT with 0600 so the secret is never briefly world-readable.
            fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(key)
        os.chmod(key_path, 0o600)
        return Fernet(key), key.decode("ascii"), ""
    except (OSError, ValueError) as exc:
        return None, "", f"failed to load/create OAST key at {key_path}: {exc}"


def _b32_dns_encode(token: bytes) -> str:
    """DNS-label-safe encoding of a Fernet token (base32, unpadded, lowercased)."""
    return base64.b32encode(token).decode("ascii").rstrip("=").lower()


def _b32_dns_decode(text: str) -> bytes:
    cleaned = re.sub(r"[^a-zA-Z2-7]", "", text).upper()
    pad = (-len(cleaned)) % 8
    return base64.b32decode(cleaned + "=" * pad)


# R23: in-process Collaborator pool. Pre-generated subdomains live here
# so OOB-heavy scans (auto_probe, fuzz_parameter with Collaborator-bound
# payloads) can pull from cache instead of one round-trip per probe.
# Concurrent FastMCP tool calls would otherwise race on pop()/append().
_COLLAB_POOL: list[dict] = []
_COLLAB_POOL_LOCK: asyncio.Lock | None = None


def _pool_lock() -> asyncio.Lock:
    global _COLLAB_POOL_LOCK
    if _COLLAB_POOL_LOCK is None:
        _COLLAB_POOL_LOCK = asyncio.Lock()
    return _COLLAB_POOL_LOCK
