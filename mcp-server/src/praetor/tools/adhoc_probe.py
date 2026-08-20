"""run_adhoc_probe — F1 (Spec F): validate + run a Claude-authored ad-hoc probe.

NL->probe without a weekly KB-file drop. Claude reasons the matcher JSON (Praetor
tools stay deterministic — no hidden LLM here, per the debate_triage principle);
this tool VALIDATES the probe against the MatcherEngine matcher-type allowlist
(fail-closed on any unknown type) and the Rule-5 destructive denylist, then runs
it through the same `/api/session/auto-probe` path the knowledge base uses.

Ephemeral by default: a confirmed ad-hoc probe is promoted to a persistent KB
file only through the operator-gated proposals/ flow — autonomy proposes, the
operator curates. This is the freshness engine behind the weekly KB cadence.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools.exploit._safety import validate_payload


# Mirror of MatcherEngine.KNOWN_MATCHER_TYPES (burp-extension). Unknown types
# fail closed in the engine; we reject them here too so the caller gets a clear
# error instead of a silently-dead matcher.
KNOWN_MATCHER_TYPES = frozenset({
    "status", "not_status", "word", "not_word", "regex", "timing",
    "differential_timing", "length_diff", "length_delta", "word_count_diff",
    "header", "not_header", "header_change", "header_added", "header_removed",
    "mime_changes", "reflection", "literal", "collaborator",
    "shape_fingerprint", "valid_vs_invalid_baseline",
})


def validate_probe_context(ctx: dict) -> tuple[bool, list[str]]:
    """Validate an ad-hoc probe context. Returns (ok, errors).

    ok is True only when the schema is well-formed, every matcher type is known
    (fail-closed), AND no payload trips the Rule-5 destructive denylist.
    """
    errors: list[str] = []
    if not isinstance(ctx, dict):
        return False, ["context must be a dict"]
    probes = ctx.get("probes")
    if not isinstance(probes, list) or not probes:
        return False, ["context has no non-empty 'probes' list"]

    for i, p in enumerate(probes):
        if not isinstance(p, dict):
            errors.append(f"probe[{i}] is not a dict")
            continue
        if "payload" not in p:
            errors.append(f"probe[{i}] missing 'payload'")
        matchers = p.get("matchers")
        if not isinstance(matchers, list) or not matchers:
            errors.append(f"probe[{i}] has no 'matchers' list")
        for m in matchers or []:
            if not isinstance(m, dict):
                errors.append(f"probe[{i}] matcher is not a dict")
                continue
            t = m.get("type")
            if t not in KNOWN_MATCHER_TYPES:
                errors.append(
                    f"probe[{i}] unknown matcher type {t!r} — fail-closed "
                    f"(valid: {sorted(KNOWN_MATCHER_TYPES)[:6]}...)")
        ok, why = validate_payload(str(p.get("payload", "")), "")
        if not ok:
            errors.append(f"probe[{i}] payload rejected (Rule 5 destructive): {why}")

    return (not errors), errors


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_adhoc_probe(
        context_name: str,
        probes: list[dict],
        targets: list[dict],
        session: str = "",
        tech_match: list[str] | None = None,
        param_match: list[str] | None = None,
        max_probes_per_param: int = 0,
    ) -> dict:
        """Validate + run a Claude-authored ad-hoc probe without a KB-file drop (F1).

        You (the model) author the probe matcher JSON — Praetor validates it against
        the MatcherEngine matcher-type allowlist (fail-closed on unknown types) and
        the Rule-5 destructive denylist, then runs it through the same engine the KB
        uses. Use this to test a fresh technique/CVE the hand-authored KB doesn't yet
        cover; promote a confirmed winner to a KB file via the proposals/ flow.

        Args:
            context_name: short name for this ad-hoc context (e.g. 'cve_2026_x_test').
            probes: list of {payload, description?, matchers:[{type,...}], severity?,
                confidence_boost?, variables?}. Matcher `type` must be a known
                MatcherEngine type or the whole run is rejected.
            targets: list of {url, parameter?} to probe (same shape as auto_probe).
            session: optional session name for authenticated probing.
            tech_match / param_match: optional gating lists for the context.
            max_probes_per_param: 0 = engine default.

        Returns: {ok, errors?, findings?, probes_sent?}. On validation failure,
        `ok=False` + `errors` and NOTHING is sent.
        """
        ctx: dict[str, Any] = {
            "description": f"ad-hoc probe ({context_name})",
            "tech_match": tech_match or [],
            "param_match": param_match or [],
            "probes": probes or [],
        }
        ok, errors = validate_probe_context(ctx)
        if not ok:
            return {"ok": False, "errors": errors,
                    "note": "nothing sent — fix the probe and retry (fail-closed)"}

        if not targets:
            return {"ok": False, "errors": ["no targets supplied"]}

        knowledge = [{"category": f"adhoc_{context_name}", "contexts": {context_name: ctx}}]
        data = await client.post("/api/session/auto-probe", json={
            "session": session,
            "targets": targets,
            "knowledge": knowledge,
            "max_probes_per_param": max_probes_per_param,
        })
        if isinstance(data, dict) and "error" in data:
            return {"ok": False, "errors": [data["error"]]}

        findings = data.get("findings", []) if isinstance(data, dict) else []
        return {
            "ok": True,
            "probes_sent": data.get("total_probes_sent", 0) if isinstance(data, dict) else 0,
            "parameters_tested": data.get("parameters_tested", 0) if isinstance(data, dict) else 0,
            "findings": findings,
            "note": ("ad-hoc probe ran through the KB engine. Promote a confirmed "
                     "winner to a persistent KB file via the proposals/ flow."),
        }
