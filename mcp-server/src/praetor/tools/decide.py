"""decide — a JEV-style structured-decision layer over Praetor's existing deciders.

The agent→MCP orchestration branch points — "what do I run next?", "is this a
finding?", "are we done?" — are answered today by a scatter of tools that each
return their own shape: `route_signals` (a dict), `judge_completion` (a string),
the probe verdict dicts (`make_verdict`), `assess_finding` (a string). A driving
agent — Claude, or a tools-only peer like dsh / Codex — has to re-parse each one
and then *guess* the strategic move, which Rule 33 forbids and Rule 13b's third
outcome (INCONCLUSIVE) exists precisely to stop.

`decide` unifies them into ONE typed envelope — the "Jev" pattern already cited in
`tools/_calibration.py` (TypeSafe / RLCD): a typed CHOICE + a CALIBRATED confidence
+ an explicit routing ACTION. It re-decides nothing. It dispatches to the existing
DETERMINISTIC deciders, attaches a calibration-backed band from the global ledger
(`~/.praetor/calibration/ledger.jsonl`), and adds the one primitive that was
missing everywhere: `escalate` as a first-class action, returned when confidence
is low on a strategic branch — Rule 33 expressed as a value, not prose.

Actions:  run | ask | escalate | report | keep_testing | stop
Like `route_signals`, the server only SELECTS; the caller executes the route.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from mcp.server.fastmcp import FastMCP

from praetor.tools.report.completion_judge import judge_completion_data
from praetor.tools.router.route import route_signals

# Band thresholds mirror _verdict.py (confirmed >=0.70, suspected 0.45-0.69,
# below = failed/low). Keeping them identical means a probe's own confidence and
# a decision's band speak the same language.
_HIGH, _MED = 0.70, 0.45

# Classes where an INCONCLUSIVE result is worth an Opus escalation rather than a
# quiet "keep testing" — the authorization / auth / injection-to-sink families
# that Rule 29 says carry the impact. Canonical spellings + common aliases.
_HIGH_VALUE = {
    "sqli", "sqli_time", "sqli_blind", "rce", "command_injection", "ssti",
    "ssrf", "idor", "bola", "bfla", "bopla", "auth_bypass",
    "authentication_bypass", "xxe", "deserialization", "mass_assignment",
    "account_takeover", "privilege_escalation", "authz", "authorization",
}

# Starting confidences for a verdict when the caller doesn't pass one — the same
# hand-picked constants _verdict.py uses, and calibratable the same way.
_DEFAULT_CONF = {
    "CONFIRMED": 0.85, "SUSPECTED": 0.55,
    "FAILED": 0.10, "INCONCLUSIVE": 0.0, "ERROR": 0.0,
}

_ESCALATE_ROUTE = {
    "to": "opus",
    "via": "pentest-commander | redteam-commander | Agent(model='opus')",
    "input": "load_target_intel(domain,'all') + coverage_summary + get_findings + load_checkpoint",
}


def _band(conf: float) -> str:
    if conf >= _HIGH:
        return "high"
    if conf >= _MED:
        return "medium"
    return "low"


@dataclass
class Decision:
    """The single typed decision envelope every branch point returns."""

    question: str
    choice: str
    action: str  # run | ask | escalate | report | keep_testing | stop
    confidence: float
    band: str
    route: dict[str, Any]
    rationale: str = ""
    alternatives: list[dict[str, Any]] = field(default_factory=list)
    calibration: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["confidence"] = round(float(self.confidence), 3)
        d["human_summary"] = (
            f"{self.action.upper()} · conf={d['confidence']} [{self.band}] · "
            f"{self.choice}" + (f" — {self.rationale}" if self.rationale else "")
        )
        return d


def _class_calibration(vuln_type: str) -> dict[str, Any]:
    """Per-class calibration facts from the GLOBAL ledger (empty when none).

    Imported lazily — the ledger is best-effort instrumentation and a decision
    must still work on a host that has never recorded an outcome.
    """
    vt = (vuln_type or "").strip().lower()
    if not vt:
        return {}
    try:
        from praetor.tools._calibration import calibration_summary
        from praetor.tools.intel.calibration import _load_ledger
    except ImportError:
        return {}
    rows = _load_ledger(vt)
    if not rows:
        return {}
    s = calibration_summary(rows)
    out: dict[str, Any] = {"n": s.get("scored", 0), "brier": s.get("brier_score")}
    pc = next((r for r in s.get("per_class", []) if r["vuln_type"] == vt), None)
    if pc:
        out["tp_rate"] = pc["tp_rate"]
        out["cal_verdict"] = pc["verdict"]
        out["suggested_confidence"] = pc["suggested_confidence"]
    tr = next((r for r in s.get("trust", []) if r["vuln_type"] == vt), None)
    if tr:
        out["trust_lb"] = tr["trust_lb"]
        out["trust_status"] = tr["status"]
    return out


def _calibrate(confidence: float, cal: dict[str, Any]) -> float:
    """Pull an eyeballed confidence toward the data when the ledger disagrees.

    Fail-closed: an overconfident class (per the ledger, with enough samples) is
    capped at the observed true-positive rate. Thin or absent data never RAISES
    confidence — the constant stands until real outcomes lower it.
    """
    sug = cal.get("suggested_confidence")
    if cal.get("cal_verdict") == "overconfident" and sug is not None:
        return min(confidence, float(sug))
    return confidence


def _fmt_call(item: dict[str, Any]) -> str:
    tool = item.get("tool", "?")
    args = item.get("args") or {}
    if isinstance(args, dict) and args:
        inner = ", ".join(f"{k}={v!r}" for k, v in list(args.items())[:4])
    else:
        inner = ""
    return f"{tool}({inner})"


def _decide_complete(domain: str, objective: str) -> Decision:
    v = judge_completion_data(domain, objective)
    if v.get("complete"):
        return Decision(
            "complete", "complete", "stop", 0.9, "high",
            {"next": f"generate_report({domain!r})"},
            rationale="all gates cleared: checkpoint, tasks, threads, business-logic, coverage",
        )
    gaps = v.get("gaps", [])
    return Decision(
        "complete", "not_complete", "keep_testing", 0.9, "high",
        {"next": v.get("recommended_next", "")},
        rationale=(f"{len(gaps)} gap(s): " + "; ".join(gaps[:3])) if gaps else "gaps remain",
        alternatives=[{"choice": g, "confidence": None} for g in gaps[:5]],
    )


async def _decide_next(domain: str, objective: str,
                       signals: list[dict] | None) -> Decision:
    if not domain:
        return Decision(
            "next", "supply_domain", "ask", 0.0, "low",
            {"why": "decide(question='next') needs a domain to read engagement state"},
            rationale="no domain supplied",
        )
    # 1. Done? judge_completion_data is the deterministic stop condition.
    comp = judge_completion_data(domain, objective)
    if comp.get("complete"):
        return Decision(
            "next", "complete", "stop", 0.9, "high",
            {"next": f"generate_report({domain!r})"},
            rationale="engagement complete (judge_completion gates all clear)",
        )
    # 2. What to run — route_signals reads on-disk signals + any passed in, and
    #    already ask-gates blast-radius tools and drops HARD-denylisted args.
    plan = await route_signals(domain=domain, signals=signals or [])
    auto = plan.get("auto", []) or []
    ask = plan.get("ask", []) or []
    if auto:
        top = auto[0]
        conf = 0.75
        return Decision(
            "next", _fmt_call(top), "run", conf, _band(conf),
            {"tool": top.get("tool"), "args": top.get("args", {})},
            rationale=top.get("rationale", "highest-impact routable signal"),
            alternatives=[{"choice": _fmt_call(a), "confidence": 0.6} for a in auto[1:4]],
        )
    if ask:
        top = ask[0]
        conf = 0.6
        return Decision(
            "next", _fmt_call(top), "ask", conf, _band(conf),
            {"tool": top.get("tool"), "args": top.get("args", {}),
             "why": "blast-radius tool (red-team / cloud / exploit / expensive) — approve first"},
            rationale=top.get("rationale", "routable but needs operator approval"),
            alternatives=[{"choice": _fmt_call(a), "confidence": 0.5} for a in ask[1:4]],
        )
    # 3. Not complete AND no routable signal = a strategic branch with no signal.
    #    Rule 33: do not guess — escalate the "what next" decision to Opus. On a
    #    single-model / opus host this reads as "reassess with full intel".
    gaps = comp.get("gaps", []) or []
    fallback = comp.get("recommended_next") or (gaps[0] if gaps else "gather more intel")
    return Decision(
        "next", "escalate:strategic", "escalate", 0.2, "low",
        {**_ESCALATE_ROUTE, "fallback_next": fallback},
        rationale=("no routable signal and engagement not complete — Rule 33: "
                   "escalate the strategic decision, don't guess (single-model host: "
                   "reassess with full intel, then decide)"),
        alternatives=[{"choice": g, "confidence": None} for g in gaps[:5]],
    )


def _decide_verdict(vuln_type: str, verdict: str, confidence: float) -> Decision:
    v = (verdict or "").strip().upper()
    if not v:
        return Decision(
            "verdict", "missing_verdict", "ask", 0.0, "low",
            {"why": "pass verdict= (CONFIRMED/SUSPECTED/FAILED/INCONCLUSIVE/ERROR) "
                    "from the probe's make_verdict dict, plus vuln_type="},
            rationale="no verdict supplied",
        )
    cal = _class_calibration(vuln_type)
    base = confidence if confidence >= 0 else _DEFAULT_CONF.get(v, 0.3)
    conf = _calibrate(base, cal)
    band = _band(conf)
    high_value = (vuln_type or "").strip().lower() in _HIGH_VALUE

    if v == "CONFIRMED":
        return Decision(
            "verdict", "CONFIRMED", "report", conf, band,
            {"next": f"assess_finding({vuln_type!r}, ...) → save_finding (Rule 10 pipeline)"},
            rationale="replay-stable confirmation — run the 7-gate, then save",
            calibration=cal,
        )
    if v == "SUSPECTED":
        if band == "high":
            return Decision(
                "verdict", "SUSPECTED", "report", conf, band,
                {"next": "assess_finding → save_finding"},
                rationale="strong suspicion at high confidence — take it to the gate",
                calibration=cal,
            )
        return Decision(
            "verdict", "SUSPECTED", "keep_testing", conf, band,
            {"next": "replay 3x (Rule 10a) or add a variant to reach CONFIRMED"},
            rationale="suspicion below the report bar — needs replay/executable-context proof",
            calibration=cal,
        )
    if v == "INCONCLUSIVE":
        if high_value:
            return Decision(
                "verdict", "INCONCLUSIVE", "escalate", 0.2, "low",
                {**_ESCALATE_ROUTE,
                 "why": f"INCONCLUSIVE on high-value class {vuln_type!r} — prove the sink or escalate"},
                rationale="Rule 13b: test-validity unproven; the tuple stays OPEN, not benign",
                calibration=cal,
            )
        return Decision(
            "verdict", "INCONCLUSIVE", "keep_testing", 0.2, "low",
            {"next": "prove test-validity (positive control) or add a variant — do NOT mark covered"},
            rationale="Rule 13b: INCONCLUSIVE is neither a finding nor a covered-negative",
            calibration=cal,
        )
    if v == "FAILED":
        return Decision(
            "verdict", "FAILED", "run", conf, band,
            {"next": "move to the next class/param — covered-negative recorded (record_probe_outcome)"},
            rationale="valid negative on a proven test — this tuple is covered",
            calibration=cal,
        )
    # ERROR / unknown — the probe could not run: a Rule 32a blocker, not coverage.
    return Decision(
        "verdict", v, "ask", 0.0, "low",
        {"why": "probe errored (scope / network / missing dep) — Rule 32a: ask the operator "
                "to unblock; the tuple stays OPEN, never marked N/A"},
        rationale="ERROR is not a covered-negative",
        calibration=cal,
    )


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def decide(
        domain: str = "",
        question: str = "next",
        vuln_type: str = "",
        verdict: str = "",
        confidence: float = -1.0,
        objective: str = "",
        signals: list[dict] | None = None,
    ) -> dict:
        """Return ONE typed, calibrated, routed decision for an orchestration branch.

        The JEV-style decision boundary for the agent→MCP loop: a typed CHOICE, a
        CALIBRATED confidence (0-1, pulled toward the global calibration ledger),
        a band (high/medium/low), and an explicit routing ACTION the caller then
        executes — `run` (fire the tool), `ask` (operator approval first),
        `escalate` (Opus strategic decision, Rule 33), `report` (take a verdict to
        the save-finding gate), `keep_testing` (tuple stays OPEN, Rule 13b), or
        `stop` (engagement complete). It never re-decides — it dispatches to the
        existing deterministic deciders (route_signals, judge_completion) and
        normalises them into one envelope any host (Claude / dsh / Codex) consumes.

        Questions:
          - 'next' (default): the single best next move for `domain`. Reads
            judge_completion + route_signals; returns run/ask, or `escalate` when
            there is no routable signal and the engagement is not complete.
          - 'verdict': turn a probe's verdict into a routed decision. Pass
            `vuln_type` and `verdict` (CONFIRMED/SUSPECTED/FAILED/INCONCLUSIVE/
            ERROR) from the make_verdict dict, optionally its `confidence`.
            INCONCLUSIVE on a high-value class routes to `escalate`; below-bar
            SUSPECTED routes to `keep_testing`.
          - 'complete': is the engagement done? Wraps judge_completion.

        Args:
            domain: target domain (its .burp-intel workspace) — needed for
                'next' and 'complete'.
            question: 'next' (default) | 'verdict' | 'complete'.
            vuln_type: for 'verdict' — the probe's class (drives calibration +
                high-value escalation).
            verdict: for 'verdict' — the make_verdict verdict string.
            confidence: for 'verdict' — the probe's own confidence (0-1); omit
                (-1) to use the class default constant.
            objective: optional engagement objective (for 'next'/'complete').
            signals: optional extra signals to feed route_signals for 'next'
                (same shape route_signals accepts).

        Returns a dict: {question, choice, action, confidence, band, route,
        rationale, alternatives, calibration, human_summary}.
        """
        q = (question or "next").strip().lower()
        if q in ("verdict", "finding", "is_finding"):
            d = _decide_verdict(vuln_type, verdict, confidence)
        elif q in ("complete", "done", "completion"):
            d = _decide_complete(domain, objective)
        else:  # next / route / default
            d = await _decide_next(domain, objective, signals)
        return d.as_dict()
