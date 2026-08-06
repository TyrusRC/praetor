"""Append-only operation ledger. Written by the tool layer, never by the model.

Every call that reaches Burp passes through `client.get/post/delete`, so
recording there produces a record of what was actually sent that no amount of
narration can contradict. The model can claim it sent a request; only this file
says whether one left the process.

Deliberately metadata-only — method, URL, status, byte count, elapsed. Request
and response bodies are never written here: the ledger would otherwise become
the place session cookies, bearer tokens and customer data get archived in
plaintext, and it is read far more casually than any capture is.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

_LOCK = threading.Lock()
_SEQ = 0

# Field names are single letters on disk. A ledger that grows for the whole
# engagement is read by tools and rendered for humans, so the long names would
# be paid for on every line and read on none. Roughly halves the file.
#   q seq · t ts · n tool · a api · h host · u url · m method
#   s status · b bytes · e elapsed_ms · o outcome · x error
_SHORT = {
    "seq": "q", "ts": "t", "tool": "n", "api": "a", "host": "h", "url": "u",
    "method": "m", "status": "s", "bytes": "b", "elapsed_ms": "e",
    "outcome": "o", "error": "x",
}
_LONG = {v: k for k, v in _SHORT.items()}

# Burp API paths that mutate state worth auditing even though no target URL is
# involved — annotations and findings are claims, and a claim with no ledger
# entry is exactly what this file exists to expose.
_AUDITED_APIS = ("/api/annotations", "/api/notes/findings", "/api/organizer")

# Rotate past this size, keeping one previous generation. An engagement that
# runs for days should cost megabytes, not gigabytes.
_MAX_BYTES = 2 * 1024 * 1024

# Query-string keys whose values are credentials rather than test input. The URL
# is the one recorded field that routinely carries them.
_SECRET_QUERY_KEYS = (
    "token", "access_token", "refresh_token", "id_token", "code",
    "api_key", "apikey", "key", "secret", "password", "passwd", "pwd",
    "session", "sessionid", "sid", "auth", "authorization", "signature", "sig",
)

_MAX_URL = 512


def oplog_path() -> Path:
    """Ledger location. Resolved per call — cwd changes between engagements."""
    return Path.cwd() / ".burp-intel" / "_oplog.jsonl"


def redact_url(url: str) -> str:
    """Strip credential-bearing query values, keeping the parameter names.

    `?token=eyJhbGc...` becomes `?token=<redacted>`: the shape stays reviewable
    (you can still see the endpoint took a token) without archiving the value.
    """
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url[:_MAX_URL]
    if not parts.query:
        return url[:_MAX_URL]

    out = []
    for pair in parts.query.split("&"):
        if "=" not in pair:
            out.append(pair)
            continue
        k, v = pair.split("=", 1)
        out.append(f"{k}=<redacted>" if k.lower() in _SECRET_QUERY_KEYS and v else f"{k}={v}")
    rebuilt = parts._replace(query="&".join(out)).geturl()
    return rebuilt[:_MAX_URL]


def is_evidentiary(entry: dict) -> bool:
    """True when an operation is worth a ledger line.

    Reads of Burp's own state — proxy history, scope, sitemap, findings list —
    are the bulk of API traffic and prove nothing about the target: nobody
    disputes whether a listing was fetched. Logging them would bury the sends
    that citations actually rest on. Kept: anything that hit a target URL,
    anything that mutated an auditable record, and every error.
    """
    if entry.get("url"):
        return True
    if entry.get("outcome") == "error":
        return True
    api = str(entry.get("api", ""))
    return any(p in api for p in _AUDITED_APIS) and "GET " not in api


def _rotate_if_needed(path: Path) -> None:
    try:
        if path.exists() and path.stat().st_size > _MAX_BYTES:
            path.replace(path.with_suffix(".1.jsonl"))
    except OSError:
        pass


def record(entry: dict) -> None:
    """Append one operation. Best-effort: never raises into the caller.

    A failed write must not fail the request the operator is making — and it is
    not silently lost either: a missing entry surfaces as unattributed Burp
    history in verify_operation_log, which is the direction that matters.
    """
    global _SEQ
    if os.environ.get("PRAETOR_OPLOG") == "off":
        return
    if not is_evidentiary(entry):
        return
    try:
        path = oplog_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with _LOCK:
            _rotate_if_needed(path)
            _SEQ += 1
            # Redact here, at the write boundary, not only in the caller. A
            # second call site that forgot would otherwise be the one that
            # archives a session token in plaintext.
            if entry.get("url"):
                entry = {**entry, "url": redact_url(str(entry["url"]))}
            full = {
                "seq": _SEQ,
                # Second precision, no microseconds — a ledger line is matched
                # to Burp by URL, not by timestamp.
                "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                **entry,
            }
            packed = {_SHORT.get(k, k): v for k, v in full.items()}
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(packed, default=str, separators=(",", ":")) + "\n")
    except Exception:
        pass


def _unpack(row: dict) -> dict:
    return {_LONG.get(k, k): v for k, v in row.items()}


def read_entries(
    host: str = "",
    tool: str = "",
    api: str = "",
    status: int = 0,
    outcome: str = "",
    since_seq: int = 0,
    sent_only: bool = False,
) -> list[dict]:
    """Read and filter the ledger. Malformed lines are skipped, not fatal."""
    out: list[dict] = []
    # Previous generation first so sequence order survives a rotation.
    paths = [p for p in (oplog_path().with_suffix(".1.jsonl"), oplog_path()) if p.exists()]
    if not paths:
        return []
    try:
        for path in paths:
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = _unpack(json.loads(line))
                    except ValueError:
                        continue
                    if since_seq and e.get("seq", 0) <= since_seq:
                        continue
                    if host and host.lower() not in str(e.get("host", "")).lower():
                        continue
                    if tool and tool.lower() not in str(e.get("tool", "")).lower():
                        continue
                    if api and api.lower() not in str(e.get("api", "")).lower():
                        continue
                    if status and int(e.get("status") or 0) != status:
                        continue
                    if outcome and str(e.get("outcome", "")) != outcome:
                        continue
                    if sent_only and not e.get("url"):
                        continue
                    out.append(e)
    except OSError:
        return out
    return out
