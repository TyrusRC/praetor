"""probe_workflow_reorder — multi-step business-flow permutation testing.

Take an ordered list of step requests (the legitimate workflow) and replay
them in permutations that should fail according to the documented business
rules:

  - skip      : drop one step at a time
  - reorder   : reverse / swap adjacent / out-of-order
  - replay    : double-fire each step
  - double-finalize : run the final step twice with different intermediate state

For each permutation, diff status/body vs the legitimate baseline.

Strix-derived. Pure black-box — only needs the step sequence the operator
already observed in a working flow.
"""

import json
from copy import deepcopy

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def _send_step(session: str, step: dict) -> dict:
    """A step is {method, path, headers?, body?}."""
    return {
        "session": session,
        "method": step.get("method", "POST"),
        "path": step["path"],
        "headers": step.get("headers", {"Content-Type": "application/json"}),
        "body": step.get("body", "") if isinstance(step.get("body"), str) else json.dumps(step.get("body", {})),
    }


def _summary(label: str, results: list[dict]) -> str:
    parts = []
    for i, r in enumerate(results):
        if "error" in r:
            parts.append(f"#{i}:ERR")
            continue
        parts.append(f"#{i}:{r.get('status', 0)}/{len(r.get('response_body', ''))}")
    return f"{label} -> {' '.join(parts)}"


def _final_succeeded(results: list[dict]) -> bool:
    if not results:
        return False
    last = results[-1]
    if "error" in last:
        return False
    return 200 <= last.get("status", 0) < 300


def register(mcp: FastMCP):

    @mcp.tool()
    async def probe_workflow_reorder(
        session: str,
        steps: list[dict],
        modes: list[str] | None = None,
    ) -> str:
        """Permute a multi-step workflow to find reorder/skip/replay flaws.

        Args:
            session: Auth session.
            steps: Ordered list of step requests. Each step is {method, path, headers?, body?}.
                   Body may be a dict (json-encoded) or a string.
            modes: Subset of ['skip','reorder_reverse','reorder_swap','replay','double_finalize']. Default = all.

        The baseline is the sequential happy-path. Any permutation whose final step
        returns 2xx (success) is flagged as a workflow violation candidate.
        """
        if len(steps) < 2:
            return "Error: need at least 2 steps to permute"
        if modes is None:
            modes = ["skip", "reorder_reverse", "reorder_swap", "replay", "double_finalize"]

        lines = [f"probe_workflow_reorder — {len(steps)} steps, modes={modes}", ""]

        # ── baseline: legitimate sequential ──
        baseline_results = []
        for step in steps:
            r = await client.post("/api/session/request", json=_send_step(session, step))
            baseline_results.append(r)
        lines.append(_summary("[baseline]", baseline_results))
        if not _final_succeeded(baseline_results):
            lines.append("WARNING: baseline final step did not return 2xx — flow may be misconfigured. Findings below are unreliable.")

        findings = []

        # ── skip ──
        if "skip" in modes:
            for i, dropped in enumerate(steps):
                permuted = [s for j, s in enumerate(steps) if j != i]
                results = []
                for step in permuted:
                    r = await client.post("/api/session/request", json=_send_step(session, step))
                    results.append(r)
                ok = _final_succeeded(results)
                lines.append(_summary(f"[skip step #{i} '{dropped.get('path', '?')}']", results) + (" *** FINAL=2xx ***" if ok else ""))
                if ok and i != len(steps) - 1:
                    findings.append(f"SKIP_STEP_BYPASS — workflow completes successfully without step #{i} ({dropped.get('path', '?')})")

        # ── reorder_reverse ──
        if "reorder_reverse" in modes:
            permuted = list(reversed(steps))
            results = []
            for step in permuted:
                r = await client.post("/api/session/request", json=_send_step(session, step))
                results.append(r)
            ok = _final_succeeded(results)
            lines.append(_summary("[reverse-order]", results) + (" *** FINAL=2xx ***" if ok else ""))
            if ok:
                findings.append("REVERSE_ORDER_ACCEPTED — workflow accepts steps in reverse order")

        # ── reorder_swap (adjacent pairs) ──
        if "reorder_swap" in modes:
            for i in range(len(steps) - 1):
                permuted = list(steps)
                permuted[i], permuted[i+1] = permuted[i+1], permuted[i]
                results = []
                for step in permuted:
                    r = await client.post("/api/session/request", json=_send_step(session, step))
                    results.append(r)
                ok = _final_succeeded(results)
                lines.append(_summary(f"[swap #{i}<->#{i+1}]", results) + (" *** FINAL=2xx ***" if ok else ""))
                if ok:
                    findings.append(f"SWAP_ACCEPTED — step #{i} and #{i+1} swappable without rejection")

        # ── replay (each step fired twice) ──
        if "replay" in modes:
            for i in range(len(steps)):
                permuted = steps[:i+1] + [steps[i]] + steps[i+1:]
                results = []
                for step in permuted:
                    r = await client.post("/api/session/request", json=_send_step(session, step))
                    results.append(r)
                ok = _final_succeeded(results)
                lines.append(_summary(f"[replay step #{i}]", results) + (" *** FINAL=2xx ***" if ok else ""))
                if ok:
                    findings.append(f"REPLAY_STEP_ACCEPTED — step #{i} ({steps[i].get('path','?')}) can be replayed without rollback")

        # ── double_finalize (last step twice) ──
        if "double_finalize" in modes and len(steps) >= 2:
            permuted = steps + [steps[-1]]
            results = []
            for step in permuted:
                r = await client.post("/api/session/request", json=_send_step(session, step))
                results.append(r)
            ok_first_final = "error" not in results[len(steps)-1] and 200 <= results[len(steps)-1].get("status", 0) < 300
            ok_second_final = "error" not in results[-1] and 200 <= results[-1].get("status", 0) < 300
            lines.append(_summary("[double-finalize]", results))
            if ok_first_final and ok_second_final:
                findings.append("DOUBLE_FINALIZE_ACCEPTED — final step succeeds twice (no transaction-completed lock)")

        lines.append("\n--- Summary ---")
        if findings:
            lines.append(f"Findings: {len(findings)}")
            for f in findings:
                lines.append(f"  [!] {f}")
            lines.append("\nVerify each by re-running and checking persistent side effects (DB rows, account balance, order state).")
        else:
            lines.append("No workflow-reorder violations detected.")
        return "\n".join(lines)
