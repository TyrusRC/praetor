"""Shared helpers for the notes/ package: path resolution, file I/O, dedup."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from burpsuite_mcp import client


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
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {"findings": [], "last_modified": ""}


def _write_findings_file(path: Path, data: dict) -> None:
    """Atomic write — concurrent agents saving to the same domain mustn't
    corrupt findings.json by interleaving partial writes. Render to a temp
    file in the same directory, then os.replace() — POSIX-atomic on the
    same filesystem."""
    import os
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".findings-", suffix=".json", dir=str(path.parent))
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


def _find_by_id(findings: list[dict], finding_id: str) -> tuple[int, dict | None]:
    """Linear scan for a finding by its persistent ID. Returns (index, finding)
    or (-1, None) if not found."""
    for i, f in enumerate(findings):
        if f.get("id") == finding_id:
            return i, f
    return -1, None


def _format_proof_for_review(f: dict) -> str:
    """Render a finding's evidence in a compact human-readable block, used when
    the FP-delete tool needs the operator to confirm a borderline-confidence
    deletion. Pulls the fields a triager would care about."""
    lines = [
        f"  ID:          {f.get('id', '?')}",
        f"  Title:       {f.get('title', '')[:120]}",
        f"  Severity:    {f.get('severity', 'INFO')}",
        f"  Confidence:  {f.get('confidence', 0.0):.2f}",
        f"  Status:      {f.get('status', 'suspected')}",
        f"  Vuln class:  {f.get('vuln_type', '')}",
        f"  Endpoint:    {f.get('endpoint', '')}",
        f"  Parameter:   {f.get('parameter', '')}",
    ]
    et = (f.get("evidence_text") or "").strip()
    if et:
        clip = et if len(et) <= 400 else et[:400] + "..."
        lines.append(f"  Evidence:    {clip}")
    ev = f.get("evidence") or {}
    if isinstance(ev, dict):
        for key in ("logger_index", "proxy_history_index", "collaborator_interaction_id"):
            if ev.get(key) is not None:
                lines.append(f"  evidence.{key}: {ev[key]}")
    if f.get("reproductions"):
        lines.append(f"  Reproductions: {len(f['reproductions'])} entries")
    if f.get("chain_with"):
        lines.append(f"  Chain anchors: {', '.join(f['chain_with'])}")
    if f.get("human_verified"):
        lines.append("  Human-verified: yes")
    return "\n".join(lines)


def _compact_and_remap_findings(findings: list[dict]) -> tuple[list[dict], dict[str, str]]:
    """Renumber survivors to contiguous f001..f00N and rewrite chain_with[]
    references in-place. Returns (compacted_list, old_to_new_id_map).

    Survivors are renumbered in their current list order. chain_with entries
    pointing at IDs no longer present (deleted) are dropped — they would
    otherwise become orphan anchors that bypass the dead-anchor gate in
    save_finding (anchor is gone, not 'likely_false_positive'/'stale')."""
    id_map: dict[str, str] = {}
    for i, f in enumerate(findings, start=1):
        old_id = f.get("id", "")
        new_id = f"f{i:03d}"
        if old_id:
            id_map[old_id] = new_id
        f["id"] = new_id
    for f in findings:
        chain = f.get("chain_with") or []
        if chain:
            remapped = [id_map[c] for c in chain if c in id_map]
            f["chain_with"] = remapped
    return findings, id_map


async def _hard_delete_finding(domain: str, finding: dict) -> tuple[bool, str]:
    """Remove a finding from .burp-intel/<domain>/findings.json AND from Burp's
    in-memory store. Remaining findings are compacted (IDs renumbered
    contiguously, chain_with[] rewritten / dead refs dropped).
    Returns (deleted_locally, burp_msg)."""
    findings_path = _safe_findings_path(domain)
    deleted_locally = False
    if findings_path.exists():
        store = _load_findings_file(findings_path)
        all_findings = store.get("findings", [])
        target_id = finding.get("id")
        keep = [f for f in all_findings if f.get("id") != target_id]
        if len(keep) != len(all_findings):
            keep, _id_map = _compact_and_remap_findings(keep)
            store["findings"] = keep
            store["last_modified"] = datetime.now(timezone.utc).isoformat()
            _write_findings_file(findings_path, store)
            deleted_locally = True
            from ._projection import remove_finding_projection
            remove_finding_projection(domain, target_id)
    burp_msg = ""
    burp_id = (finding.get("burp_id") or "")
    ev = finding.get("evidence") or {}
    if not burp_id and isinstance(ev, dict):
        burp_id = str(ev.get("burp_id") or "")
    if burp_id:
        resp = await client.delete(f"/api/notes/findings/{burp_id}")
        if isinstance(resp, dict) and "error" not in resp:
            burp_msg = f"Burp in-memory: removed (id={burp_id})"
        else:
            burp_msg = f"Burp in-memory: skip ({resp.get('error', 'no response')})"
    else:
        burp_msg = "Burp in-memory: no burp_id recorded — Burp store not touched (will not re-appear after extension reload)"
    return deleted_locally, burp_msg


def _dedupe_finding(existing: list[dict], new: dict) -> tuple[list[dict], str, int]:
    """Merge `new` into `existing` by (endpoint + vuln_type + title + parameter).

    vuln_type is part of the key so two distinct classes (e.g. xss vs csrf)
    that happen to share an endpoint+title don't silently collapse — that
    used to delete the earlier finding's evidence on the second save.

    Returns (updated_list, action, index) where action is 'created' or 'updated'
    and index points at the finding's position in the returned list.
    """
    key_ep = new.get("endpoint", "")
    key_vuln = (new.get("vuln_type", "") or "").lower()
    key_title = new.get("title", "").lower()
    key_param = new.get("parameter", "")

    for i, f in enumerate(existing):
        same_ep = f.get("endpoint", "") == key_ep
        same_vuln = (f.get("vuln_type", "") or "").lower() == key_vuln
        same_title = f.get("title", "").lower() == key_title
        same_param = f.get("parameter", "") == key_param
        if same_ep and same_vuln and same_title and same_param:
            merged = {**f, **new, "id": f.get("id")}
            existing[i] = merged
            return existing, "updated", i
    existing.append(new)
    return existing, "created", len(existing) - 1
