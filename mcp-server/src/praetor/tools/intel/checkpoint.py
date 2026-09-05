"""Durable engagement checkpoint + task ledger (W37). Logic in _checkpoint_logic;
all public names re-exported here so `intel.checkpoint` imports are unchanged.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor.tools.workspace import workspace_paths
from . import _checkpoint_logic as _cl

_g = globals()
for _n in dir(_cl):
    if not _n.startswith("__"):
        _g[_n] = getattr(_cl, _n)
del _g, _n


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
        progress: dict | None = None,
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
            progress: Per-round progress ledger (Spec E2.1) —
                {progress_made: bool, in_loop: bool, request_satisfied: bool,
                stall_reason: str}. consecutive_no_progress auto-tracks; a STALL
                alert surfaces in load_checkpoint when it's ≥2 or in_loop=True,
                the deterministic trigger to pivot / convene the council.
        """
        if not domain:
            return "Error: domain is required."
        data = merge_checkpoint(
            domain, phase=phase, round=round, next_action=next_action,
            objective=objective, tasks=tasks, open_threads=open_threads,
            progress=progress,
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
