"""Decision engine — a calibrated, typed decision layer for selection + triage.

Praetor already has the JEV *pattern* deterministically (`decide.py` typed
envelope, `scan/_prioritise.py` relevance ordering, `_calibration.py` bands).
This module adds the MODEL backend those points were missing, so "which template
/ probe is relevant to THIS target" and "is this hit worth verifying first"
become calibrated decisions, not static heuristics.

It is a CORE layer (always wired, always consulted), with three backends in
priority order so it never forces a key:

  1. jev  — TypeSafe Jev via Vercel AI Gateway `POST /v1/evaluate` (native typed
            Choice/Score/Boolean with calibrated probabilities). Key:
            AI_GATEWAY_API_KEY (or PRAETOR_DECISION_API_KEY).
  2. llm  — any provider through `_llm.complete`, answering the same questions as
            JSON (provider-agnostic; works with Ollama offline).
  3. off  — no backend: `available()` is False and callers keep their existing
            deterministic order/verdict unchanged (keyless core, zero regression).

Questions mirror the Jev contract exactly:
  boolean -> {probability}              (criteria {true,false})
  choice  -> {choice, probabilities}    (criteria {option: desc})
  score   -> {score, probabilities}     (criteria [low..high])

Several questions share one `state` and resolve in a single round trip.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

import httpx

from praetor.tools import _llm

_DEFAULT_BASE = "https://ai-gateway.vercel.sh"
_DEFAULT_MODEL = "typesafe-ai/jev"


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def _is_local(url: str) -> bool:
    u = (url or "").lower()
    return any(h in u for h in ("127.0.0.1", "localhost", "0.0.0.0", "[::1]"))


@dataclass
class DecisionConfig:
    tier: str          # "jev" | "llm" | "off"
    model: str
    base_url: str
    api_key: str
    reason: str = ""


def resolve_decision() -> DecisionConfig:
    """Pick the best available backend. PRAETOR_DECISION_PROVIDER forces one of
    jev|llm|off; otherwise auto: jev if an AI-Gateway key is set OR a local engine
    base_url is configured, else llm if an LLM is configured, else off. The jev
    tier serves BOTH the hosted API (key) and a self-hosted engine (keyless, local
    base_url) — same /v1/evaluate contract."""
    forced = _env("PRAETOR_DECISION_PROVIDER").lower()
    key = _env("PRAETOR_DECISION_API_KEY") or _env("AI_GATEWAY_API_KEY")
    model = _env("PRAETOR_DECISION_MODEL") or _DEFAULT_MODEL
    base_env = _env("PRAETOR_DECISION_BASE_URL")
    base = base_env or _DEFAULT_BASE
    # The key authenticates a REMOTE hosted gateway (Vercel AI Gateway). A
    # self-hosted engine on loopback (a local Haruspex / OpenJev server) needs
    # none — it is selected keyless whenever its base_url points at localhost.
    local_engine = bool(base_env) and _is_local(base)
    jev_ok = bool(key) or local_engine

    if forced == "off":
        return DecisionConfig("off", model, base, "", "disabled by PRAETOR_DECISION_PROVIDER=off")
    if forced == "jev":
        if jev_ok:
            return DecisionConfig("jev", model, base, key)
        return DecisionConfig("off", model, base, "",
                              "PRAETOR_DECISION_PROVIDER=jev but no key and PRAETOR_DECISION_BASE_URL "
                              "is not a local engine")
    if not forced and jev_ok:
        return DecisionConfig("jev", model, base, key)
    if forced == "llm" or not forced:
        if _llm.resolve_llm().ok:
            return DecisionConfig("llm", model, base, "", "")
        if forced == "llm":
            return DecisionConfig("off", model, base, "", "PRAETOR_DECISION_PROVIDER=llm but no LLM configured")
    return DecisionConfig("off", model, base, "",
                          "no decision backend — run a local engine "
                          "(PRAETOR_DECISION_BASE_URL=http://127.0.0.1:<port>), set AI_GATEWAY_API_KEY "
                          "for hosted Jev, or a PRAETOR_LLM_* provider; deterministic order/verdicts stay")


def available(cfg: DecisionConfig | None = None) -> bool:
    return (cfg or resolve_decision()).tier != "off"


def _state_str(state) -> str:
    return state if isinstance(state, str) else json.dumps(state, default=str)


async def evaluate(state, questions: dict, timeout: int = 45,
                   cfg: DecisionConfig | None = None) -> dict:
    """Answer `questions` about `state` in one round trip. Returns a dict keyed
    like `questions`, each value normalized to one of:
      {"type":"boolean","probability":float}
      {"type":"choice","choice":str,"probabilities":{opt:float}}
      {"type":"score","score":float,"probabilities":{idx:float}}
    Raises RuntimeError when the backend is off."""
    cfg = cfg or resolve_decision()
    if cfg.tier == "off":
        raise RuntimeError(cfg.reason or "decision backend off")
    if cfg.tier == "jev":
        return await _jev_evaluate(cfg, state, questions, timeout)
    return await _llm_evaluate(cfg, state, questions, timeout)


async def _jev_evaluate(cfg, state, questions, timeout) -> dict:
    # Hosted gateway (Vercel AI Gateway, OpenJev vLLM shim, …) authenticates with
    # the key; a keyless local engine gets no Authorization header.
    headers = {"Content-Type": "application/json"}
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"
    body = {"model": cfg.model, "state": state, "questions": questions}
    async with httpx.AsyncClient(timeout=timeout) as c:
        r = await c.post(cfg.base_url.rstrip("/") + "/v1/evaluate", headers=headers, json=body)
        r.raise_for_status()
        return r.json().get("answers", {})


async def _llm_evaluate(cfg, state, questions, timeout) -> dict:
    """Answer the same typed questions through any LLM as JSON."""
    spec = []
    for name, q in questions.items():
        qt = q.get("type")
        if qt == "choice":
            opts = list((q.get("criteria") or {}).keys())
            spec.append(f'- "{name}" (choice of {opts}): {q.get("instructions","")}')
        elif qt == "score":
            levels = q.get("criteria") or []
            spec.append(f'- "{name}" (score 0..{max(0, len(levels)-1)} over {levels}): {q.get("instructions","")}')
        else:
            spec.append(f'- "{name}" (boolean probability 0..1): {q.get("instructions","")}')
    system = ("You are a decision model. Answer each question about the STATE. Return ONLY a JSON "
              "object keyed by question name. boolean -> {\"probability\":0..1}; "
              "choice -> {\"choice\":\"<option>\"}; score -> {\"score\":<float>}. No prose.")
    prompt = "STATE:\n" + _state_str(state) + "\n\nQUESTIONS:\n" + "\n".join(spec)
    raw = await _llm.complete(prompt, system=system, max_tokens=800, timeout=timeout)
    s = raw.strip()
    if "```" in s:
        import re
        m = re.search(r"```(?:json)?\s*(.+?)```", s, re.DOTALL)
        if m:
            s = m.group(1).strip()
    try:
        data = json.loads(s)
    except ValueError:
        data = {}
    out: dict = {}
    for name, q in questions.items():
        a = data.get(name, {}) if isinstance(data, dict) else {}
        qt = q.get("type")
        if qt == "choice":
            out[name] = {"type": "choice", "choice": a.get("choice", ""),
                         "probabilities": a.get("probabilities", {})}
        elif qt == "score":
            try:
                out[name] = {"type": "score", "score": float(a.get("score", 0)),
                             "probabilities": a.get("probabilities", {})}
            except (TypeError, ValueError):
                out[name] = {"type": "score", "score": 0.0, "probabilities": {}}
        else:
            try:
                out[name] = {"type": "boolean", "probability": float(a.get("probability", 0))}
            except (TypeError, ValueError):
                out[name] = {"type": "boolean", "probability": 0.0}
    return out


async def rank_relevant(state_prefix: str, items: list[dict], timeout: int = 45,
                        cfg: DecisionConfig | None = None) -> list[dict]:
    """Rank `items` (each {"key","state","label"?}) by a calibrated "relevant?"
    probability, highest first. One round trip (all items as boolean questions).
    Returns each item + "relevance" (0..1); on backend-off raises RuntimeError.
    `state_prefix` names the target context shared by every question."""
    cfg = cfg or resolve_decision()
    if cfg.tier == "off":
        raise RuntimeError(cfg.reason or "decision backend off")
    qs = {}
    keymap = {}
    for i, it in enumerate(items):
        qn = f"q{i}"
        keymap[qn] = it
        qs[qn] = {"type": "boolean",
                  "instructions": f"Is this relevant/worth running for the target? {it.get('label') or it.get('key')}: {it.get('state','')}"}
    answers = await evaluate(state_prefix, qs, timeout=timeout, cfg=cfg)
    ranked = []
    for qn, it in keymap.items():
        prob = 0.0
        a = answers.get(qn) or {}
        try:
            prob = float(a.get("probability", 0))
        except (TypeError, ValueError):
            prob = 0.0
        ranked.append({**it, "relevance": prob})
    ranked.sort(key=lambda x: -x["relevance"])
    return ranked


def _shape(k: str) -> str:
    return (f"{k[:4]}...{k[-2:]} ({len(k)}B)" if len(k) > 8 else ("set" if k else "(unset)"))


def status() -> dict:
    cfg = resolve_decision()
    return {
        "tier": cfg.tier,
        "available": cfg.tier != "off",
        "model": cfg.model if cfg.tier != "off" else "(none)",
        "base_url": cfg.base_url if cfg.tier == "jev" else ("(via _llm)" if cfg.tier == "llm" else "(none)"),
        "api_key": _shape(cfg.api_key) if cfg.tier == "jev" else "(n/a)",
        "reason": cfg.reason,
        "note": ("decision backend active — selection ranking + triage use it; "
                 "deterministic order/verdicts remain the fallback"
                 if cfg.tier != "off" else
                 "no backend — deterministic ordering/verdicts in force (keyless core)"),
    }
