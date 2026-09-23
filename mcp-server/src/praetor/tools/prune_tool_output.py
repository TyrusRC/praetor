"""Safe disk-reclaim for raw external-tool output — never evidence, leads, or context.

Scope is a single directory: `.burp-intel/<domain>/material/tool-output/`, where
raw ffuf/nuclei/katana/gau/subfinder dumps land (see project CLAUDE.md workspace
layout). Nothing else under `.burp-intel/<domain>/` is ever a candidate — not
findings.json, not artifacts/, not reports/, not findings/, not the domain-root
machine state (checkpoint.json, coverage.json, endpoints.json, profile.json,
patterns.json, notes.md, fingerprint.json).

Guarantees:
- **dry-run by default.** `apply=False` (default) deletes nothing; it only reports
  candidate files, their size, and total reclaimable bytes.
- **Hard path guard.** Every candidate's realpath is verified to resolve strictly
  inside the resolved tool-output directory before it is even listed, and again
  immediately before unlink. This blocks path traversal and symlinks that point
  outside the directory — such a path is silently excluded, never deleted.
- **Age + keep-recent gating.** A file is a candidate only if it is older than
  `max_age_days` AND not among the `keep_recent` newest files in the directory
  (by mtime) — the newest few are always kept regardless of age.
- **Ingested-only guard (heuristic, not a per-URL diff).** If `endpoints.json` or
  `coverage.json` for the domain is missing, unreadable, or empty, nothing is
  pruned at all and the reason is reported — leads from raw tool output may not
  yet have been pulled into intel. This is an age+ingestion PROXY: it does not
  verify that any specific URL from a given dump was actually read into
  `endpoints.json`/`coverage.json`. When unsure, the file is kept.
"""

import json
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor.tools.intel._internals import _intel_path

_INGESTION_FILES = (("endpoints.json", "endpoints"), ("coverage.json", "entries"))


def _ingestion_gate(root: Path) -> str | None:
    """Return a skip reason if leads may not be ingested yet, else None.

    Conservative proxy check only: existence + non-empty list on both
    endpoints.json and coverage.json. Not a per-URL diff against the raw dumps.
    """
    for name, list_key in _INGESTION_FILES:
        path = root / name
        if not path.exists():
            return f"{name} does not exist for '{root.name}' — leads not yet ingested, pruning nothing"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            return f"{name} unreadable ({exc}) — pruning nothing"
        if not isinstance(data, dict) or not data.get(list_key):
            return f"{name} is empty — leads not yet ingested, pruning nothing"
    return None


def _contained(resolved: Path, resolved_dir: Path) -> bool:
    """True only if `resolved` is strictly inside `resolved_dir` (guards traversal/symlinks)."""
    return resolved_dir in resolved.parents


async def prune_tool_output(
    domain: str,
    apply: bool = False,
    max_age_days: int = 7,
    keep_recent: int = 5,
) -> dict:
    """Reclaim disk space from raw tool-output dumps for a domain. Evidence/leads/context untouched.

    Only ever deletes files strictly inside
    `.burp-intel/<domain>/material/tool-output/` — never findings, artifacts,
    reports, or domain-root machine state. Dry-run by default (`apply=False`):
    returns the candidate list and reclaimable bytes without deleting anything.
    Pass `apply=True` to actually delete. See module docstring for the full
    safety contract (age+keep-recent gating, ingestion guard, path containment).

    Args:
        domain: target domain (as used elsewhere in `.burp-intel/<domain>/`).
        apply: if True, delete the candidates. Default False (report only).
        max_age_days: minimum file age in days to be prune-eligible.
        keep_recent: always keep this many newest files regardless of age.

    Returns:
        dict with domain, dir, dry_run, candidates (name/bytes/age_days),
        total_bytes, deleted (only when apply=True), and a human-readable
        `summary` line. `skipped_reason` is set (and nothing is touched) when
        the ingestion guard blocks pruning or the directory doesn't exist yet.
    """
    try:
        root = _intel_path(domain)
    except ValueError as exc:
        return {"error": str(exc)}

    tool_output_dir = root / "material" / "tool-output"

    result: dict = {
        "domain": domain,
        "dir": str(tool_output_dir),
        "dry_run": not apply,
        "candidates": [],
        "total_bytes": 0,
        "deleted": [],
    }

    if not tool_output_dir.exists():
        result["skipped_reason"] = "material/tool-output/ does not exist yet — nothing to prune"
        result["summary"] = result["skipped_reason"]
        return result

    gate_reason = _ingestion_gate(root)
    if gate_reason:
        result["skipped_reason"] = gate_reason
        result["summary"] = gate_reason
        return result

    resolved_dir = tool_output_dir.resolve()

    entries: list[tuple[Path, Path, float, int]] = []
    for candidate in tool_output_dir.rglob("*"):
        if not candidate.is_file():
            continue
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if not _contained(resolved, resolved_dir):
            continue  # traversal / symlink escape — never a candidate
        try:
            st = candidate.stat()
        except OSError:
            continue
        entries.append((candidate, resolved, st.st_mtime, st.st_size))

    entries.sort(key=lambda e: e[2], reverse=True)  # newest first
    protected = {e[1] for e in entries[:keep_recent]}

    now = time.time()
    candidates: list[tuple[Path, Path, int, float]] = []
    for path, resolved, mtime, size in entries:
        if resolved in protected:
            continue
        age_days = (now - mtime) / 86400
        if age_days <= max_age_days:
            continue
        candidates.append((path, resolved, size, age_days))

    result["candidates"] = [
        {
            "name": str(path.relative_to(tool_output_dir)),
            "bytes": size,
            "age_days": round(age_days, 1),
        }
        for path, _resolved, size, age_days in candidates
    ]
    result["total_bytes"] = sum(c["bytes"] for c in result["candidates"])

    if not apply:
        result["summary"] = (
            f"[dry-run] {len(result['candidates'])} candidate(s), "
            f"{result['total_bytes']} bytes reclaimable from {tool_output_dir}"
        )
        return result

    deleted: list[str] = []
    for path, resolved, _size, _age_days in candidates:
        if not _contained(resolved, resolved_dir):
            continue  # defense in depth — re-checked immediately before unlink
        try:
            path.unlink()
        except OSError:
            continue
        deleted.append(str(path.relative_to(tool_output_dir)))

    result["deleted"] = deleted
    result["summary"] = (
        f"Deleted {len(deleted)} file(s), reclaimed {result['total_bytes']} bytes "
        f"from {tool_output_dir}"
    )
    return result


def register(mcp: FastMCP) -> None:
    mcp.tool()(prune_tool_output)
