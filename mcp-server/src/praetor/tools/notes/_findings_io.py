"""notes findings I/O: path resolution, load/write, atomic write, lock."""

import contextlib
import json
import re
from pathlib import Path
from urllib.parse import urlparse


def _intel_dir() -> Path:
    """Resolve the .burp-intel directory at call time (cwd may change)."""
    return Path.cwd() / ".burp-intel"


def _sanitized(domain: str) -> str:
    cleaned = re.sub(r'[^a-zA-Z0-9._-]', '_', domain).strip(".")
    if not cleaned or ".." in cleaned:
        raise ValueError(f"Invalid domain: {domain!r}")
    return cleaned


def _safe_findings_path(domain: str) -> Path:
    """Resolve findings.json for a domain with path-traversal guard."""
    base = _intel_dir().resolve()
    sub = _sanitized(domain)
    candidate = (base / sub / "findings.json").resolve()
    if base != candidate and base not in candidate.parents:
        raise ValueError(f"Domain escapes intel root: {domain!r}")
    return _intel_dir() / sub / "findings.json"


def _domain_from_endpoint(endpoint: str) -> str:
    """Best-effort host extraction from an endpoint URL or bare host."""
    if not endpoint:
        return ""
    if "://" in endpoint:
        return urlparse(endpoint).hostname or ""
    return ""


def _load_findings_file(path: Path) -> dict:
    if not path.exists():
        return {"findings": [], "last_modified": ""}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"findings": [], "last_modified": ""}


def atomic_write_json(path: Path, data, *, prefix: str = ".tmp-") -> None:
    """Atomically write `data` as JSON to `path`.

    Render to a temp file in the same directory, then os.replace() — POSIX-atomic
    on the same filesystem — so a concurrent reader/writer never sees a partial
    file. Shared by the findings, network-inventory, and credential stores.
    """
    import os
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=prefix, suffix=".json", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _write_findings_file(path: Path, data: dict) -> None:
    """Atomic findings.json write — concurrent agents saving to the same domain
    mustn't corrupt it by interleaving partial writes."""
    atomic_write_json(path, data, prefix=".findings-")


@contextlib.contextmanager
def _findings_lock(path: Path):
    """Serialise the read-modify-write of a domain's findings.json.

    ``_write_findings_file`` is atomic — no torn file — but the callers do
    load -> mutate -> write as three separate steps with no lock. With the
    3-4 concurrent agents AGENTS.md permits, two saves to the same domain can
    each load the same base, append a different finding, and the second write
    drops the first (a silent lost update). Hold this exclusive lock across the
    whole load+mutate+write to serialise them.

    Advisory ``flock`` on a sidecar ``.lock`` file, a fresh fd per acquire so
    separate threads and processes contend. Best-effort: on a platform without
    ``fcntl`` (Windows) the body runs unlocked rather than crashing — the
    atomic write still prevents corruption there, only the lost-update window
    remains.
    """
    import os

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        import fcntl
    except ImportError:
        yield
        return
    lock_path = path.with_name(path.name + ".lock")
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
