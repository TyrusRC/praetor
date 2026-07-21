"""Durable engagement checkpoint + task ledger (W37).

Praetor persists coverage / findings / fingerprint per domain, but the *task
state* of a multi-round, multi-agent engagement lived only in prose (`notes.md`
audit lines) and in the model's context. On compaction or resume, a fresh agent
re-derived that state from prose. This module gives the engagement a single,
machine-readable checkpoint so `resume.md` and `grow-agent` reconstruct task
state in one read instead of scraping.

    .burp-intel/<domain>/checkpoint.json
    {
      "domain": "example.com",
      "objective": "broad coverage",
      "phase": "scan",                 # recon|scan|verify|chain|report|done
      "round": 4,
      "updated_at": "2026-07-21T...",
      "next_action": "dispatch finding-verifier on f-0007",
      "tasks": [
        {"id": "T1",   "title": "recon surface", "status": "done", "note": "42 eps"},
        {"id": "T1.1", "title": "js secrets",    "status": "done", "note": ""},
        {"id": "T2",   "title": "sqli /api/*",   "status": "in_progress", "note": "6/15"}
      ],
      "open_threads": ["500 on /api/export?format — revisit SSTI"]
    }

Task ids are hierarchical (`T1`, `T1.1`) so the ledger carries a plan tree, not
a flat list. Writes MERGE by task id — an update touches only the fields it
supplies, so a status flip never drops a title or note.

Design mirrors report/business_logic_gate: pure module-level functions
(`load_checkpoint_data` / `merge_checkpoint`) do the work and are unit-tested
directly; the @mcp.tool() wrappers are thin.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.workspace import workspace_paths

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

    _write(domain, data)
    return data


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
    return "\n".join(lines)


def _summary_line(data: dict) -> str:
    """One-line write confirmation. The writer already holds the full state, so a
    checkpoint write echoes back only what changed + resulting counts — not the
    whole tree (this runs every grow-agent round; the tree would be pure waste)."""
    tasks = [t for t in (data.get("tasks") or []) if isinstance(t, dict)]
    open_n = sum(1 for t in tasks if t.get("status") in _OPEN_STATES)
    threads = data.get("open_threads") or []
    return (
        f"checkpoint saved: {data.get('domain', '?')} | "
        f"phase={data.get('phase', '?')} round={data.get('round', '?')} | "
        f"tasks {len(tasks)} ({open_n} open), {len(threads)} thread(s) | "
        f"next: {data.get('next_action') or '(none)'}"
    )


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def write_checkpoint(
        domain: str,
        phase: str = "",
        round: int | None = None,
        next_action: str = "",
        objective: str = "",
        tasks: list[dict] | None = None,
        open_threads: list[str] | None = None,
    ) -> str:
        """Upsert the engagement checkpoint for a domain (task ledger + next action).

        Writes .burp-intel/<domain>/checkpoint.json — the single durable record of
        engagement task state that survives context compaction. grow-agent calls
        this at its CHECKPOINT step each round; resume.md reads it back on start.

        Merges, never clobbers: scalars overwrite only when supplied non-empty;
        `tasks` merge by `id` (field-by-field), so flipping one task's status
        keeps its title/note; `open_threads` append+dedupe (pass an explicit empty
        list to clear resolved threads).

        Returns a one-line confirmation (counts + next_action), not the full tree —
        the writer already holds the state, so echoing it back every round is token
        waste. Use load_checkpoint to read the full ledger on resume.

        Args:
            domain: Target domain (slug).
            phase: recon|scan|verify|chain|report|done. Empty = leave unchanged.
            round: Current round number. None = leave unchanged.
            next_action: Single directive for the next actor (e.g.
                'dispatch finding-verifier on f-0007'). Empty = leave unchanged.
            objective: Engagement objective. Empty = leave unchanged.
            tasks: List of {id, title?, status?, note?}. id is hierarchical
                (T1, T1.1). status ∈ pending|in_progress|done|blocked.
            open_threads: Anomalies/leads to revisit. Append+dedupe; [] clears.
        """
        if not domain:
            return "Error: domain is required."
        data = merge_checkpoint(
            domain, phase=phase, round=round, next_action=next_action,
            objective=objective, tasks=tasks, open_threads=open_threads,
        )
        if not data:
            return f"Error: invalid domain {domain!r}."
        return _summary_line(data)

    @mcp.tool()
    async def load_checkpoint(domain: str) -> str:
        """Load the engagement checkpoint for a domain (compact rendered summary).

        Reads .burp-intel/<domain>/checkpoint.json and returns a one-glance summary:
        phase, round, objective, next_action, the task tree (with open/done state),
        and open threads. Call this at session start (resume.md Step 1) to restore
        task state without scraping prose notes. Returns a NEW-target notice if no
        checkpoint exists yet.
        """
        if not domain:
            return "Error: domain is required."
        data = load_checkpoint_data(domain)
        if not data:
            return (
                f"No checkpoint for {domain}. This is a fresh engagement (or the "
                f"first checkpoint hasn't been written). After recon, call "
                f"write_checkpoint(domain, phase='recon', tasks=[...])."
            )
        return _render(data)
