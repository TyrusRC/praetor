"""Snapshot / dedup-index / endpoint-match helpers for findings_diff."""

from __future__ import annotations

import fnmatch
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from praetor.tools.notes._helpers import _load_findings_file, _safe_findings_path


def _snapshot_dir(domain: str) -> Path:
    d = _safe_findings_path(domain).parent / "_snapshots"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _archive_current(domain: str) -> Path | None:
    src = _safe_findings_path(domain)
    if not src.exists():
        return None
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = _snapshot_dir(domain) / f"findings-{ts}.json"
    target.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def _list_snapshots(domain: str) -> list[Path]:
    d = _snapshot_dir(domain)
    return sorted(d.glob("findings-*.json"))


def _findings_list(raw) -> list[dict]:
    """_load_findings_file returns dict or list depending on schema; normalise."""
    if isinstance(raw, dict):
        return raw.get("findings", []) or []
    if isinstance(raw, list):
        return raw
    return []


def _index_by_dedup_key(findings: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for f in findings:
        key = "|".join(str(f.get(k) or "") for k in ("endpoint", "vuln_type", "parameter", "title"))
        out[key] = f
    return out


def _load_endpoints(domain: str) -> tuple[list[dict], Path]:
    """Load endpoints.json (same shape rank_attack_targets/predict_paths read):
    `{"endpoints"|"targets": [...]}` or a bare list. Returns (list, path)."""
    path = _safe_findings_path(domain).parent / "endpoints.json"
    if not path.exists():
        return [], path
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], path
    if isinstance(data, list):
        return data, path
    return (data.get("endpoints") or data.get("targets") or []), path


def _ep_path(ep: dict) -> str:
    return ep.get("path") or ep.get("url") or ""


def _ep_params(ep: dict) -> list[str]:
    """Every user-controlled param name on an endpoint, across all locations."""
    out: list[str] = []
    for p in ep.get("parameters") or []:
        name = p if isinstance(p, str) else (p.get("name") or p.get("parameter"))
        if name:
            out.append(name)
    for key in ("body_keys", "cookie_keys", "header_keys", "path_params", "query_keys"):
        for k in ep.get(key) or []:
            if k:
                out.append(k)
    # preserve order, drop dups
    seen: set = set()
    return [x for x in out if not (x in seen or seen.add(x))]


def _norm_path(s: str) -> str:
    """Reduce an endpoint URL or bare path to its path component for comparison."""
    s = (s or "").strip()
    if "://" in s:
        return urlparse(s).path or "/"
    return s


def _path_matches(pattern: str, ep_path: str) -> bool:
    """Simple glob / prefix / exact path match. Glob chars trigger fnmatch;
    otherwise exact or segment-boundary prefix (`/api/` matches `/api/users`)."""
    if not pattern or not ep_path:
        return False
    if any(c in pattern for c in "*?["):
        return fnmatch.fnmatch(ep_path, pattern)
    if ep_path == pattern:
        return True
    return ep_path.startswith(pattern.rstrip("/") + "/")
