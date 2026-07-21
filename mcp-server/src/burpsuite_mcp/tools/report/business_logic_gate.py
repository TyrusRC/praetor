"""Business-logic completion gate (W36-P1).

The recon gate (Rule 20a) is tool-enforced; the business-logic pass (Rule 27 +
`infer_business_invariants` / `test_business_logic` / `capture_business_context`)
was advisory — nothing checked it ran. This module makes it a *measured* pass.

A per-domain testcase matrix records which business-logic invariants were tested:

    .burp-intel/<domain>/testcases/business-logic-matrix.json
    {
      "domain": "example.com",
      "updated_at": "2026-07-21T...",
      "invariants": [
        {"invariant": "coupon one-use per account",
         "endpoint": "/api/redeem", "tested": true, "result": "held"}
      ]
    }

`business_logic_gate(domain)` returns an operator warning when the matrix is
absent or has zero tested invariants, and None otherwise. build_executive_summary
surfaces it in the report. Warning only — it never blocks report generation.
Mirrors the budget_gate pattern in tools/intel/cost_cap.py.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.workspace import workspace_paths


def _matrix_path(domain: str) -> Path:
    """Canonical matrix location. Raises ValueError on path-traversal input."""
    return workspace_paths(domain)["testcases"] / "business-logic-matrix.json"


def _load(domain: str) -> dict:
    try:
        path = _matrix_path(domain)
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
    path = _matrix_path(domain)
    path.parent.mkdir(parents=True, exist_ok=True)
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def business_logic_gate(domain: str) -> str | None:
    """Importable completion check for the report builder.

    Returns an operator-facing warning string when the business-logic pass is
    unproven for `domain` (matrix missing, or present but with zero tested
    invariants), else None. Sync + cheap; safe to call at report-build time.
    Never raises on a bad domain — returns None so it can't break a report.
    """
    if not domain:
        return None
    data = _load(domain)
    if not data:
        return (
            f"business-logic coverage gate: no testcase matrix for {domain}. "
            f"Rule 27 requires a business-logic pass — run infer_business_invariants, "
            f"test the proposals (test_business_logic / probe_workflow_reorder / "
            f"test_race_condition / probe_idempotency_key), and record each with "
            f"record_business_logic_test(domain, invariant, endpoint, result). "
            f"The engagement is not complete until at least one invariant is tested."
        )
    invariants = data.get("invariants") or []
    tested = [i for i in invariants if isinstance(i, dict) and i.get("tested")]
    if not tested:
        return (
            f"business-logic coverage gate: matrix for {domain} lists "
            f"{len(invariants)} invariant(s) but 0 are tested. Run the proposed "
            f"business-logic tests and mark each with record_business_logic_test "
            f"before treating the engagement as complete."
        )
    return None


def register(mcp: FastMCP):

    @mcp.tool()
    async def record_business_logic_test(
        domain: str,
        invariant: str,
        endpoint: str = "",
        result: str = "",
        tested: bool = True,
    ) -> str:
        """Record a business-logic invariant test into the domain's testcase matrix.

        Upserts a row into .burp-intel/<domain>/testcases/business-logic-matrix.json,
        keyed by (invariant, endpoint). Feeds the W36-P1 completion gate:
        generate_report warns until at least one invariant here is marked tested.
        Pair with infer_business_invariants (proposes the invariants) and
        test_business_logic / probe_workflow_reorder / test_race_condition /
        probe_idempotency_key (run them).

        Args:
            domain: Target domain.
            invariant: The business rule under test (e.g. 'coupon one-use per account').
            endpoint: Endpoint or flow the invariant guards.
            result: Free-text outcome (e.g. 'held', 'bypassed — refund replayed', 'suspected').
            tested: Mark the row tested (default True). Pass False to seed an untested row.
        """
        if not domain:
            return "Error: domain is required."
        if not invariant or not invariant.strip():
            return "Error: invariant is required."

        try:
            data = _load(domain)
        except Exception:  # noqa: BLE001 — never let a bad domain crash the tool
            data = {}
        data.setdefault("domain", domain)
        rows: list[dict] = data.get("invariants")
        if not isinstance(rows, list):
            rows = []

        inv = invariant.strip()
        ep = (endpoint or "").strip()
        row = {"invariant": inv, "endpoint": ep, "tested": bool(tested), "result": (result or "").strip()}

        for i, existing in enumerate(rows):
            if not isinstance(existing, dict):
                continue
            if existing.get("invariant") == inv and (existing.get("endpoint") or "") == ep:
                rows[i] = row
                break
        else:
            rows.append(row)

        data["invariants"] = rows
        _write(domain, data)

        tested_count = sum(1 for r in rows if isinstance(r, dict) and r.get("tested"))
        return (
            f"Recorded business-logic invariant for {domain}: {inv}"
            + (f" @ {ep}" if ep else "")
            + f" (tested={bool(tested)}). Matrix now: {tested_count}/{len(rows)} tested."
        )
