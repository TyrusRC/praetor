"""Decision-engine tools — the model tier for selection + triage (the "Jev" pattern).

`decide.py` and `scan/_prioritise.py` make the DETERMINISTIC decision (typed
envelope, relevance tiers). These tools add the calibrated MODEL decision from
`_decision.py` (native Jev via AI Gateway, any LLM, or off). They RANK and SCORE;
they never drop coverage (Rule 19) — the caller still runs the full set, just in
a smarter order, and verifies the highest-relevance leads first (Rule 13c/29).

Backend-off is not an error: the tools return `available: False` and the caller
keeps the deterministic order/verdict (keyless core, zero regression).
"""

from __future__ import annotations

import json

import httpx
from mcp.server.fastmcp import FastMCP

from praetor.tools import _decision

# A model backend is external and new — any of these degrades cleanly to the
# deterministic path rather than failing the tool call.
_BACKEND_ERRORS = (RuntimeError, httpx.HTTPError, ValueError, KeyError, TypeError)


def _as_list(v):
    if isinstance(v, list):
        return v
    if isinstance(v, str) and v.strip():
        try:
            d = json.loads(v)
            return d if isinstance(d, list) else [d]
        except ValueError:
            return []
    return []


def _as_dict(v):
    if isinstance(v, dict):
        return v
    if isinstance(v, str) and v.strip():
        try:
            d = json.loads(v)
            return d if isinstance(d, dict) else {}
        except ValueError:
            return {}
    return {}


def register(mcp: FastMCP):

    @mcp.tool()
    async def decision_status() -> dict:
        """Report the active decision-engine backend (jev | llm | off) + model + key shape.

        jev = TypeSafe Jev via Vercel AI Gateway (AI_GATEWAY_API_KEY). llm = any
        PRAETOR_LLM_* provider answering typed questions as JSON. off = no backend,
        deterministic ordering/verdicts stay in force. Call it at session start to
        know whether model-backed ranking/triage is live.
        """
        return _decision.status()

    @mcp.tool()
    async def decide_relevance(state: str = "", items: list | str | None = None,
                               top: int = 0) -> dict:
        """Rank candidate templates / probes / scanner-hits by a calibrated
        "worth running / worth verifying first" probability — the model-selection
        step for run_assay, auto_probe, and scanner-hit triage.

        It orders only; it never drops coverage (Rule 19). Use the order to spend
        the probe budget and the verification queue on the highest-relevance items
        first. Backend-off returns the items unchanged with `available: False`.

        Args:
            state: the target context shared by every item (tech stack, endpoint,
                auth state, program notes) — one string.
            items: list of {"key": <id>, "state": <item detail>, "label"?: <name>}.
            top: when >0, also return the top-N keys as `selected` (a budget hint;
                the rest are still testable — not a skip).
        """
        items = _as_list(items)
        if not items:
            return {"error": "items must be a non-empty list of {key, state, label?} (or its JSON)"}
        cfg = _decision.resolve_decision()
        if cfg.tier == "off":
            return {"available": False, "reason": cfg.reason,
                    "ranked": items, "note": "deterministic order kept — set AI_GATEWAY_API_KEY or a PRAETOR_LLM_* provider"}
        try:
            ranked = await _decision.rank_relevant(state, items, cfg=cfg)
        except _BACKEND_ERRORS as e:
            return {"available": False, "reason": f"decision backend error: {e}",
                    "ranked": items, "note": "deterministic order kept"}
        res = {"available": True, "tier": cfg.tier, "model": cfg.model, "ranked": ranked}
        if top > 0:
            res["selected"] = [it["key"] for it in ranked[:top]]
            res["budget_note"] = "selected = run/verify these first; the rest stay testable (Rule 19, no skip)"
        return res

    @mcp.tool()
    async def decide_questions(state: str = "", questions: dict | str | None = None) -> dict:
        """Answer typed questions about `state` with the decision engine — the raw
        Jev primitive (boolean | choice | score), one round trip, calibrated.

        For triage/routing a borderline hit (Rule 13b/33): e.g. a boolean
        "is this a reportable finding?", a score "exploitability 0..n", a choice of
        severity band. Backend-off returns `available: False` (keep the
        deterministic verdict). `questions` mirrors the Jev contract:
          {"<name>": {"type": "boolean"|"choice"|"score", "instructions": "...",
                      "criteria": {true,false} | {opt:desc} | [low..high]}}

        Args:
            state: the situation to evaluate (string or JSON string of a record).
            questions: the typed questions (above), or their JSON.
        """
        questions = _as_dict(questions)
        if not questions:
            return {"error": "questions must be a non-empty object of {name: {type, instructions, criteria?}} (or its JSON)"}
        cfg = _decision.resolve_decision()
        if cfg.tier == "off":
            return {"available": False, "reason": cfg.reason,
                    "note": "deterministic verdict stays in force (use decide / assess_finding)"}
        try:
            answers = await _decision.evaluate(state, questions, cfg=cfg)
        except _BACKEND_ERRORS as e:
            return {"available": False, "reason": f"decision backend error: {e}"}
        return {"available": True, "tier": cfg.tier, "model": cfg.model, "answers": answers}
