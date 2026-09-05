"""Checkpoint load/merge/render/stall logic + task-state constants."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from praetor.tools.workspace import workspace_paths


_TASK_STATES = ("pending", "in_progress", "done", "blocked")
_OPEN_STATES = ("pending", "in_progress", "blocked")  # anything not done


def _checkpoint_path(domain: str) -> Path:
    """Canonical checkpoint location. Raises ValueError on path-traversal input."""
    return workspace_paths(domain)["root"] / "checkpoint.json"


def load_checkpoint_data(domain: str) -> dict:
    """Read the checkpoint dict for a domain, or {} if absent/unreadable/bad domain.

    Never raises — a bad domain or corrupt file returns {} so callers (resume,
    grow-agent, the completion judge) can branch on emptiness safely.
    """
    if not domain:
        return {}
    try:
        path = _checkpoint_path(domain)
    except ValueError:
        return {}
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write(domain: str, data: dict) -> None:
    path = _checkpoint_path(domain)
    path.parent.mkdir(parents=True, exist_ok=True)
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _norm_status(value: str) -> str:
    v = (value or "").strip().lower()
    return v if v in _TASK_STATES else "pending"


def merge_checkpoint(
    domain: str,
    *,
    phase: str = "",
    round: int | None = None,
    next_action: str = "",
    objective: str = "",
    tasks: list[dict] | None = None,
    open_threads: list[str] | None = None,
    progress: dict | None = None,
) -> dict:
    """Upsert the checkpoint. Returns the persisted dict (or {} on bad domain).

    Merge semantics:
      - Scalars (phase/round/next_action/objective) overwrite only when a
        non-empty / non-None value is supplied — a partial write never blanks a
        field it didn't mean to touch.
      - `tasks` merge by `id`: an existing task is updated field-by-field with
        only the supplied non-empty fields (status is always normalised); new
        ids append. Order is preserved (existing first, then new).
      - `open_threads` append + dedupe (order-preserving). To CLEAR a resolved
        thread, pass the full desired list — an explicit empty list replaces.
      - `progress` (Spec E2.1, Magentic-One progress ledger): a per-round
        {progress_made, in_loop, request_satisfied, stall_reason} record. Latest
        overwrites; `consecutive_no_progress` auto-increments while progress_made
        is False and resets to 0 when True — deterministic stall/loop detection
        that fires before the coarse '3 zero-delta rounds' heuristic.
    """
    if not domain:
        return {}
    try:
        _checkpoint_path(domain)  # validate domain early
    except ValueError:
        return {}

    data = load_checkpoint_data(domain)
    data.setdefault("domain", domain)

    if phase:
        data["phase"] = phase.strip()
    if round is not None:
        data["round"] = int(round)
    if next_action:
        data["next_action"] = next_action.strip()
    if objective:
        data["objective"] = objective.strip()

    existing: list[dict] = data.get("tasks") if isinstance(data.get("tasks"), list) else []
    by_id: dict[str, dict] = {}
    order: list[str] = []
    for t in existing:
        if isinstance(t, dict) and t.get("id"):
            tid = str(t["id"])
            by_id[tid] = t
            order.append(tid)

    for t in tasks or []:
        if not isinstance(t, dict):
            continue
        tid = str(t.get("id") or "").strip()
        if not tid:
            continue
        row = by_id.get(tid)
        if row is None:
            row = {"id": tid, "title": "", "status": "pending", "note": ""}
            by_id[tid] = row
            order.append(tid)
        if t.get("title"):
            row["title"] = str(t["title"]).strip()
        if "status" in t:
            row["status"] = _norm_status(t.get("status", ""))
        if "note" in t and t.get("note") is not None:
            row["note"] = str(t["note"]).strip()
    data["tasks"] = [by_id[i] for i in order]

    if open_threads is not None:
        if isinstance(open_threads, list) and not open_threads:
            data["open_threads"] = []  # explicit clear
        else:
            cur = data.get("open_threads") if isinstance(data.get("open_threads"), list) else []
            seen = {str(x) for x in cur}
            for th in open_threads:
                s = str(th).strip()
                if s and s not in seen:
                    cur.append(s)
                    seen.add(s)
            data["open_threads"] = cur

    if progress is not None and isinstance(progress, dict):
        prev = data.get("progress") if isinstance(data.get("progress"), dict) else {}
        made = bool(progress.get("progress_made", True))
        cons = 0 if made else int(prev.get("consecutive_no_progress", 0)) + 1
        data["progress"] = {
            "progress_made": made,
            "in_loop": bool(progress.get("in_loop", False)),
            "request_satisfied": bool(progress.get("request_satisfied", False)),
            "stall_reason": str(progress.get("stall_reason", "")).strip(),
            "consecutive_no_progress": cons,
        }

    _write(domain, data)
    return data


def stall_alert(data: dict) -> str:
    """Deterministic stall/loop signal for the convener. Returns '' when healthy.

    Fires when the model reports it's looping, or when ≥2 consecutive rounds made
    no progress — the trigger for the agent-council convene-on-stall (Rule 4 pivot).
    """
    p = data.get("progress") if isinstance(data.get("progress"), dict) else {}
    if not p:
        return ""
    cons = int(p.get("consecutive_no_progress", 0))
    if p.get("in_loop") or cons >= 2:
        reason = p.get("stall_reason") or "no progress"
        return f"STALL: {cons} round(s) no progress ({reason}) — pivot/convene council"
    return ""


def _render(data: dict) -> str:
    """Token-lean resume view: enumerate OPEN tasks in full (they drive the next
    actions), collapse DONE tasks to an id list (keeps the plan-tree shape without
    spending tokens on titles/notes of finished work). This is the context-
    injection path — every token here is re-read on every resume."""
    tasks = [t for t in (data.get("tasks") or []) if isinstance(t, dict)]
    open_tasks = [t for t in tasks if t.get("status") in _OPEN_STATES]
    done_ids = [str(t.get("id", "?")) for t in tasks if t.get("status") == "done"]
    lines = [
        f"CHECKPOINT {data.get('domain', '?')} | phase={data.get('phase', '?')} "
        f"round={data.get('round', '?')} | updated={data.get('updated_at', '?')}",
        f"objective: {data.get('objective', '(unset)')}",
        f"next_action: {data.get('next_action', '(none)')}",
        f"tasks: {len(tasks)} total, {len(open_tasks)} open, {len(done_ids)} done",
    ]
    for t in open_tasks:
        note = f" — {t['note']}" if t.get("note") else ""
        lines.append(f"  [{t.get('status', '?'):>11}] {t.get('id', '?')} {t.get('title', '')}{note}")
    if done_ids:
        lines.append(f"  done: {', '.join(done_ids)}")
    threads = data.get("open_threads") or []
    if threads:
        lines.append(f"open_threads ({len(threads)}):")
        lines.extend(f"  - {th}" for th in threads)
    alert = stall_alert(data)
    if alert:
        lines.append(alert)
    return "\n".join(lines)


def _summary_line(data: dict) -> str:
    """One-line write confirmation. The writer already holds the full state, so a
    checkpoint write echoes back only what changed + resulting counts — not the
    whole tree (this runs every grow-agent round; the tree would be pure waste)."""
    tasks = [t for t in (data.get("tasks") or []) if isinstance(t, dict)]
    open_n = sum(1 for t in tasks if t.get("status") in _OPEN_STATES)
    threads = data.get("open_threads") or []
    alert = stall_alert(data)
    return (
        f"checkpoint saved: {data.get('domain', '?')} | "
        f"phase={data.get('phase', '?')} round={data.get('round', '?')} | "
        f"tasks {len(tasks)} ({open_n} open), {len(threads)} thread(s) | "
        f"next: {data.get('next_action') or '(none)'}"
        + (f" | {alert}" if alert else "")
    )
