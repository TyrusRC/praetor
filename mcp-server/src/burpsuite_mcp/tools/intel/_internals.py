"""Storage primitives, scope helpers, and recon-gate logic shared by every
intel-tool submodule. Kept here (private leading underscore) so the public
intel/__init__.py re-exports stay narrow."""

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def _intel_root() -> Path:
    """Resolve the .burp-intel directory at call time (cwd may change)."""
    return Path.cwd() / ".burp-intel"


# Knowledge dir — three parents up: intel/_internals.py -> tools/ -> burpsuite_mcp/ -> knowledge/
KNOWLEDGE_DIR = Path(__file__).parent.parent.parent / "knowledge"


VALID_CATEGORIES = ("profile", "endpoints", "coverage", "findings", "fingerprint", "patterns")


def _intel_path(domain: str) -> Path:
    """Return the intel directory path for a domain, with sanitized name.

    Rejects any sanitized name that would escape the intel root (path traversal guard).
    """
    sanitized = re.sub(r'[^a-zA-Z0-9._-]', '_', domain)
    sanitized = sanitized.strip(".")
    if not sanitized or ".." in sanitized:
        raise ValueError(f"Invalid domain for intel path: {domain!r}")
    base = _intel_root().resolve()
    candidate = (base / sanitized).resolve()
    if base != candidate and base not in candidate.parents:
        raise ValueError(f"Domain escapes intel root: {domain!r}")
    return _intel_root() / sanitized


def _ensure_dir(domain: str) -> Path:
    """Create the intel directory for a domain if needed, return its Path."""
    path = _intel_path(domain)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _atomic_write_json(path: Path, data: dict | list) -> None:
    """Write JSON to a temp file then atomically replace the target (prevents corruption)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


_KNOWLEDGE_VERSION_CACHE: tuple[float, str] | None = None


def _knowledge_version() -> str:
    """SHA256 hash (first 12 chars) of all knowledge/*.json files concatenated.

    Cached against the directory mtime so repeat calls (auto_probe coverage
    check fires on every probe) don't re-read all 55 JSON files each time.
    """
    global _KNOWLEDGE_VERSION_CACHE
    try:
        latest = 0.0
        for p in KNOWLEDGE_DIR.glob("*.json"):
            try:
                latest = max(latest, p.stat().st_mtime)
            except OSError:
                pass
    except OSError:
        latest = 0.0
    if _KNOWLEDGE_VERSION_CACHE is not None and _KNOWLEDGE_VERSION_CACHE[0] == latest:
        return _KNOWLEDGE_VERSION_CACHE[1]
    h = hashlib.sha256()
    for p in sorted(KNOWLEDGE_DIR.glob("*.json")):
        h.update(p.read_bytes())
    digest = h.hexdigest()[:12]
    _KNOWLEDGE_VERSION_CACHE = (latest, digest)
    return digest


def _empty_structure(category: str) -> dict:
    """Return an empty dict matching the schema for each category."""
    if category == "profile":
        return {"domain": "", "tech_stack": [], "frameworks": [], "notes": ""}
    if category == "endpoints":
        return {"endpoints": []}
    if category == "coverage":
        return {"knowledge_version": "", "entries": []}
    if category == "findings":
        return {"findings": []}
    if category == "fingerprint":
        return {"pages": []}
    if category == "patterns":
        return {"patterns": []}
    return {}


def _finding_vuln_type(finding: dict) -> str:
    """Get vulnerability type from either 'vulnerability_type' or 'category' field."""
    return finding.get("vulnerability_type") or finding.get("category") or ""


def recon_gate_check(domain: str) -> str | None:
    """Return None if recon intel exists for the domain, else an actionable error string.

    Used by save_finding and auto_probe to enforce hunting Rule 20a — a finding can't
    be persisted and probes should warn unless the operator has actually recorded recon
    for the target. Empty .burp-intel/<domain>/ means no recon has been done.
    """
    if not domain:
        return None  # caller chose not to persist; gate doesn't apply
    path = _intel_path(domain)
    profile = path / "profile.json"
    if not path.exists() or not profile.exists():
        return (
            f"RECON GATE: no intel for '{domain}'. Run recon first:\n"
            f"  1. browser_crawl('https://{domain}', max_pages=20)\n"
            f"  2. full_recon(session=<name>) or discover_attack_surface(...)\n"
            f"  3. save_target_intel('{domain}', 'profile', {{...}})\n"
            f"Then retry. Override with force_recon_gate=True only if recon is in-flight."
        )
    return None


def _deduplicate_finding(existing_list: list[dict], new_finding: dict) -> list[dict]:
    """If same endpoint + vulnerability type + parameter exists, update it; otherwise append."""
    new_type = _finding_vuln_type(new_finding)
    new_endpoint = new_finding.get("endpoint", "")
    new_param = new_finding.get("parameter", "")
    for i, item in enumerate(existing_list):
        if (
            item.get("endpoint") == new_endpoint
            and _finding_vuln_type(item) == new_type
            and item.get("parameter") == new_param
        ):
            existing_list[i] = {**item, **new_finding}
            return existing_list
    existing_list.append(new_finding)
    return existing_list


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Backwards-compat shim: many call sites read INTEL_DIR directly.
def __getattr__(name: str):
    if name == "INTEL_DIR":
        return _intel_root()
    raise AttributeError(name)
