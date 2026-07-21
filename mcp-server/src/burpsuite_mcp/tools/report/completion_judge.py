"""Independent engagement-completion judge (W37-B).

grow-agent's stop condition is mechanical — round count, coverage_delta==0, WAF
streak. None of those verify the engagement was actually *finished*: open tasks,
un-revisited leads, or a skipped business-logic pass all pass the circuit
breaker. This module is the independent check that reads the durable state
(checkpoint task ledger + coverage + findings) and the existing business-logic
gate, and returns a structured verdict on whether "done" is earned.

It is deterministic on purpose: the judge is independent of the reasoning that
did the work precisely because it re-derives from persisted evidence, not from
the agent's own narrative. No LLM call, no network — cheap enough to gate every
report build. Reuses report/business_logic_gate rather than re-implementing it.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.intel.checkpoint import load_checkpoint_data, _OPEN_STATES
from burpsuite_mcp.tools.report.business_logic_gate import business_logic_gate
from burpsuite_mcp.tools.workspace import workspace_paths


def _read_json(domain: str, name: str) -> dict:
    try:
        path: Path = workspace_paths(domain)["root"] / name
    except ValueError:
        return {}
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def judge_completion_data(domain: str, objective: str = "") -> dict:
    """Return a structured completion verdict for a domain. Never raises.

    complete=True requires ALL of:
      - a checkpoint exists (the engagement was tracked at all),
      - no task is still open (pending/in_progress/blocked),
      - no unresolved open_threads,
      - the business-logic pass is proven (business_logic_gate clears),
      - coverage was recorded (at least one probe ran).

    confirmed_findings is reported but is NOT a gate — a clean target that was
    fully worked is legitimately complete with zero findings.
    """
    result: dict = {
        "domain": domain,
        "objective": objective or "",
        "complete": False,
        "confirmed_findings": 0,
        "open_tasks": [],
        "open_threads": [],
        "gaps": [],
        "recommended_next": "",
    }
    if not domain:
        result["gaps"].append("no domain supplied")
        return result

    gaps: list[str] = result["gaps"]
    ckpt = load_checkpoint_data(domain)
    if not ckpt:
        gaps.append(
            "no checkpoint — engagement task state was never recorded; call "
            "write_checkpoint after recon"
        )
    else:
        if objective and not result["objective"]:
            result["objective"] = objective
        result["objective"] = result["objective"] or ckpt.get("objective", "")
        open_tasks = [
            {"id": t.get("id"), "title": t.get("title"), "status": t.get("status")}
            for t in (ckpt.get("tasks") or [])
            if isinstance(t, dict) and t.get("status") in _OPEN_STATES
        ]
        result["open_tasks"] = open_tasks
        for t in open_tasks:
            gaps.append(f"open task {t['id']} ({t['status']}): {t.get('title') or ''}".strip())
        threads = [str(x) for x in (ckpt.get("open_threads") or []) if str(x).strip()]
        result["open_threads"] = threads
        for th in threads:
            gaps.append(f"unresolved thread: {th}")

    coverage = _read_json(domain, "coverage.json")
    entries = coverage.get("entries") if isinstance(coverage.get("entries"), list) else []
    if not entries:
        gaps.append("no coverage recorded — no probe/test has run for this domain")

    findings = _read_json(domain, "findings.json").get("findings") or []
    result["confirmed_findings"] = sum(
        1 for f in findings if isinstance(f, dict) and f.get("status") == "confirmed"
    )

    bl = business_logic_gate(domain)
    if bl:
        gaps.append(bl)

    result["complete"] = not gaps
    if result["complete"]:
        result["recommended_next"] = "engagement complete — generate_report(domain)"
    else:
        # Prefer the checkpoint's own next_action; else point at the first gap.
        result["recommended_next"] = (ckpt.get("next_action") if ckpt else "") or gaps[0]
    return result


def _render(v: dict) -> str:
    head = "COMPLETE" if v["complete"] else "NOT COMPLETE"
    lines = [
        f"ENGAGEMENT {head}: {v['domain']}"
        + (f" | objective: {v['objective']}" if v.get("objective") else ""),
        f"confirmed findings: {v['confirmed_findings']}",
    ]
    if v["gaps"]:
        lines.append(f"gaps ({len(v['gaps'])}):")
        lines.extend(f"  - {g}" for g in v["gaps"])
    lines.append(f"recommended_next: {v['recommended_next']}")
    return "\n".join(lines)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def judge_completion(domain: str, objective: str = "") -> str:
        """Independently judge whether the engagement for a domain is complete.

        Re-derives the verdict from persisted evidence — the checkpoint task
        ledger, coverage.json, findings.json, and the business-logic gate — not
        from the agent's own narrative. Use it before treating an engagement as
        done / before generate_report, and as grow-agent's real stop condition
        (the round circuit breaker only bounds effort, it doesn't prove
        completion).

        NOT complete unless: a checkpoint exists, every task is done, no
        open_threads remain, the business-logic pass is proven, and coverage was
        recorded. Zero confirmed findings does NOT block completion — a fully
        worked clean target is legitimately done.

        Args:
            domain: Target domain (slug).
            objective: Optional engagement objective for the report header
                (falls back to the checkpoint's stored objective).
        """
        if not domain:
            return "Error: domain is required."
        return _render(judge_completion_data(domain, objective))
