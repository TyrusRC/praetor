"""fuzz_with_feedback — feedback-driven mutation loop for bypass discovery.

Sends a clean baseline, then iterates mutation variants of a seed payload
against a chosen injection point. Scores each variant against operator-
defined signals (status, length delta, body regex, header change, timing
delta) and returns ranked hits. Designed for WAF/filter bypass where
auto_probe scored 0 but partial-signal evidence said "something's
happening here, try harder."

Routes every request through Burp's /api/http/curl endpoint so all traffic
appears in Logger and is replayable. Rule 26a compliant.
"""

import asyncio
import time
from typing import Any

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools.mutate import generate_variants
from ._verdict import error_verdict, make_verdict
from ._fuzz_feedback_helpers import _inject, _normalize, _score, _send


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def fuzz_with_feedback(  # cost: medium (clamped to max_iters)
        url: str,
        parameter: str,
        seed: str,
        signals: dict,
        method: str = "GET",
        body: str = "",
        headers: dict | None = None,
        cookies: dict | None = None,
        location: str = "query",
        mutation_classes: list[str] | None = None,
        max_iters: int = 30,
        early_stop: bool = True,
        concurrency: int = 5,
    ) -> dict:
        """Feedback-driven mutation loop for WAF/filter bypass discovery. Returns VerdictResult.

        Sends one clean baseline then up to max_iters mutated variants of seed, scoring each against signals; returns ranked hits with mutation_class.

        Args:
            url: Target URL.
            parameter: Parameter (or path placeholder) to inject into.
            seed: Starting payload — mutated by mutate_payload classes.
            signals: Predicate dict: status_in/status_changed/length_delta_min/regex/regex_not_in_baseline/header_present/header_changed/timing_delta_ms/reflected.
            method: HTTP method.
            body: Base request body (body_form/body_json locations).
            headers: Base headers.
            cookies: Base cookies.
            location: query | body_form | body_json | header | cookie | path.
            mutation_classes: Mutation classes (default productive subset; see mutate_payload).
            max_iters: Max variants. Default 30.
            early_stop: Stop on first match (default True); False ranks all.
            concurrency: Parallel in-flight requests (default 5).
        """
        if not seed:
            return error_verdict("seed payload is required", vuln_type="fuzz_feedback")
        if not signals or not isinstance(signals, dict):
            return error_verdict(
                "signals dict is required (status_in / regex / length_delta_min / ...)",
                vuln_type="fuzz_feedback",
            )

        baseline_resp = await _send(method, url, headers, body, cookies)
        baseline = _normalize(baseline_resp)
        if baseline.get("error"):
            return error_verdict(
                f"baseline failed: {baseline['error']}",
                vuln_type="fuzz_feedback",
            )

        variants = generate_variants(seed, classes=mutation_classes, count=max_iters)
        if not variants:
            return error_verdict(
                "no variants generated — pass a non-empty seed and valid mutation classes",
                vuln_type="fuzz_feedback",
            )

        sem = asyncio.Semaphore(max(1, concurrency))
        results: list[dict] = []
        stop_event = asyncio.Event()

        async def _one(v: dict) -> None:
            if early_stop and stop_event.is_set():
                return
            async with sem:
                if early_stop and stop_event.is_set():
                    return
                u, b, h, c = _inject(url, method, body, headers, cookies, parameter, v["variant"], location)
                resp = await _send(method, u, h, b, c)
                probe = _normalize(resp)
                signals_with_payload = dict(signals)
                signals_with_payload["_current_payload"] = v["variant"]
                matched, score = _score(probe, baseline, signals_with_payload)
                if probe.get("error"):
                    results.append({
                        "variant": v["variant"][:80],
                        "mutation_class": v["mutation_class"],
                        "mutator": v["mutator"],
                        "error": probe["error"],
                        "score": 0,
                        "matched": [],
                    })
                    return
                results.append({
                    "variant": v["variant"][:80],
                    "mutation_class": v["mutation_class"],
                    "mutator": v["mutator"],
                    "status": probe["status"],
                    "length": probe["length"],
                    "elapsed_ms": probe["elapsed_ms"],
                    "score": score,
                    "matched": matched,
                    "history_index": resp.get("history_index", -1),
                })
                if early_stop and score > 0:
                    stop_event.set()

        await asyncio.gather(*(_one(v) for v in variants), return_exceptions=True)

        results.sort(key=lambda r: (r["score"], len(r.get("matched", []))), reverse=True)
        hits = [r for r in results if r["score"] > 0]
        sent = len(results)

        lines = [
            f"fuzz_with_feedback: seed={seed[:60]!r} location={location} sent={sent}/{len(variants)}",
            f"Baseline: status={baseline['status']} len={baseline['length']} elapsed={baseline['elapsed_ms']}ms",
            "",
        ]
        if not hits:
            lines.append("No variants matched any signal. Try: different mutation_classes, weaker thresholds, or escalate to manual craft.")
            top = results[:3]
            if top:
                lines.append("\nTop-3 non-hit responses (for triage):")
                for r in top:
                    lines.append(f"  [{r['mutation_class']}/{r['mutator']}] status={r.get('status', '?')} len={r.get('length', '?')} delta={r.get('length', 0) - baseline['length']:+d}")
            return make_verdict(
                "FAILED", 0.1,
                "no variants matched any signal — try different mutation_classes or escalate to manual craft",
                vuln_type="fuzz_feedback",
                details={"variants_sent": sent, "best_score": 0},
                summary="\n".join(lines),
            )

        lines.append(f"Hits: {len(hits)}\n")
        for r in hits[:20]:
            label = f"{r['mutation_class']}/{r['mutator']}"
            lines.append(
                f"  [score={r['score']:>3d}] [{label}] status={r.get('status', '?')} "
                f"len={r.get('length', '?')} hist={r.get('history_index', -1)}"
            )
            lines.append(f"           variant: {r['variant']}")
            lines.append(f"           matched: {', '.join(r['matched'])}")
        lines.append("\nReplay the top variant via resend_with_modification(history_index) or save with save_finding(evidence={...}).")

        human = "\n".join(lines)
        best_score = hits[0]["score"] if hits else 0
        logger_indices = [
            int(h["history_index"]) for h in hits[:5]
            if isinstance(h.get("history_index"), int) and h["history_index"] >= 0
        ]
        # Score-based verdict mapping — fuzz_feedback signals are tunable so
        # the actual semantic depends on operator-chosen thresholds. Treat
        # >= 50 score as CONFIRMED (multiple strong signals); 1-49 SUSPECTED.
        if best_score >= 50:
            verdict, confidence = "CONFIRMED", min(0.9, 0.65 + best_score / 200)
            ev = f"fuzz feedback: best variant scored {best_score} ({len(hits)} hits) — strong bypass candidate"
        elif best_score > 0:
            verdict, confidence = "SUSPECTED", 0.55
            ev = f"fuzz feedback: best variant scored {best_score} ({len(hits)} hits) — partial signal, manual escalate"
        else:
            verdict, confidence = "FAILED", 0.1
            ev = "fuzz feedback: no signals matched"

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="fuzz_feedback",
            logger_indices=logger_indices,
            details={
                "url": url, "parameter": parameter, "seed": seed[:60],
                "variants_sent": sent, "hits": len(hits),
                "best_score": best_score,
                "top_variant": hits[0]["variant"] if hits else None,
            },
            summary=human,
        )
