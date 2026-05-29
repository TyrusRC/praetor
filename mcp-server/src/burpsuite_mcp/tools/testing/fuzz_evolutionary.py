"""fuzz_evolutionary — multi-round closed-loop payload feedback (W7, T4).

Single-pass fuzz_with_feedback already exists. This adds the evolutionary
loop: best-K variants of round N become seeds for round N+1, producing
combinations the static mutator pool cannot reach in one pass.

Loop shape per round
--------------------
  1. Take current seeds (round 1 = [user_seed]; later rounds = top-K from prev).
  2. Mutate each seed → variants. Concurrent send through Burp.
  3. Score every probe vs baseline using the same signals as fuzz_with_feedback.
  4. Pick top-K scorers as next-round seeds. Always keep the all-time best.
  5. Early stop if confidence threshold hit or no improvement for 2 rounds.

This is the "senior engineer" loop — try, observe, mutate, try again.
Anti-slop: bounded by max_rounds + per-round max_iters; every variant routes
through Burp so logger_index evidence is preserved for assess_finding.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.mutate import generate_variants

from .fuzz_feedback import _inject, _normalize, _score, _send
from ._verdict import make_verdict


def _diversity_filter(seeds: list[str]) -> list[str]:
    """Drop near-duplicates by 8-prefix to avoid wasted compute."""
    seen: set[str] = set()
    out: list[str] = []
    for s in seeds:
        key = s[:8]
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def fuzz_evolutionary(  # cost: high (rounds * iters_per_round)
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
        rounds: int = 5,
        iters_per_round: int = 12,
        top_k: int = 3,
        concurrency: int = 5,
        confidence_threshold: int = 80,
    ) -> dict:
        """Closed-loop evolutionary payload fuzzer — mutate → fire → score → re-mutate.

        Each round mutates the top-K winners of the previous round, giving the
        operator combinations a single-pass mutator can't reach. Use when
        fuzz_with_feedback finds partial signal but no clear winner.

        Returns a structured VerdictResult dict with: best variant, round
        history, top hits, total Burp Logger indices captured.

        Args:
            url, parameter, seed, signals: same as fuzz_with_feedback.
            method, body, headers, cookies, location: request shape.
            mutation_classes: passed to mutate_payload (default: productive subset).
            rounds: max rounds (default 5).
            iters_per_round: variants per round (default 12).
            top_k: variants carried to next round (default 3).
            concurrency: in-flight requests cap (default 5).
            confidence_threshold: stop early when best score >= this (default 80).
        """
        if not seed:
            return make_verdict("ERROR", 0.0, "seed payload required",
                                vuln_type="fuzz_feedback",
                                details={"error": "no seed"})
        if not signals or not isinstance(signals, dict):
            return make_verdict("ERROR", 0.0, "signals dict required",
                                vuln_type="fuzz_feedback",
                                details={"error": "no signals"})

        baseline_resp = await _send(method, url, headers, body, cookies)
        baseline = _normalize(baseline_resp)
        if baseline.get("error"):
            return make_verdict("ERROR", 0.0, f"baseline failed: {baseline['error']}",
                                vuln_type="fuzz_feedback",
                                details={"error": baseline["error"]})

        current_seeds = [seed]
        all_hits: list[dict[str, Any]] = []
        round_log: list[dict[str, Any]] = []
        best_score = 0
        plateau_rounds = 0
        sem = asyncio.Semaphore(max(1, concurrency))

        async def _fire(variant: dict) -> dict | None:
            async with sem:
                u, b, h, c = _inject(url, method, body, headers, cookies,
                                     parameter, variant["variant"], location)
                resp = await _send(method, u, h, b, c)
                probe = _normalize(resp)
                sig = dict(signals)
                sig["_current_payload"] = variant["variant"]
                matched, score = _score(probe, baseline, sig)
                if probe.get("error"):
                    return None
                return {
                    "variant": variant["variant"],
                    "mutation_class": variant["mutation_class"],
                    "mutator": variant["mutator"],
                    "status": probe["status"],
                    "length": probe["length"],
                    "elapsed_ms": probe["elapsed_ms"],
                    "score": score,
                    "matched": matched,
                    "history_index": resp.get("history_index", -1),
                }

        for round_idx in range(1, rounds + 1):
            current_seeds = _diversity_filter(current_seeds)
            per_seed = max(2, iters_per_round // max(1, len(current_seeds)))
            variants: list[dict] = []
            for s in current_seeds:
                variants.extend(generate_variants(s, classes=mutation_classes, count=per_seed))
            if not variants:
                round_log.append({"round": round_idx, "skipped": "no variants generated"})
                break

            t0 = time.perf_counter()
            round_results = await asyncio.gather(
                *(_fire(v) for v in variants), return_exceptions=True
            )
            round_dur_ms = int((time.perf_counter() - t0) * 1000)
            round_hits = [r for r in round_results if isinstance(r, dict) and r["score"] > 0]
            round_hits.sort(key=lambda r: r["score"], reverse=True)
            all_hits.extend(round_hits)
            top = round_hits[:top_k]
            round_log.append({
                "round": round_idx,
                "seeds_in": len(current_seeds),
                "variants_sent": len(variants),
                "hits": len(round_hits),
                "top_score": (top[0]["score"] if top else 0),
                "elapsed_ms": round_dur_ms,
            })

            new_best = max((r["score"] for r in round_hits), default=0)
            if new_best <= best_score:
                plateau_rounds += 1
            else:
                plateau_rounds = 0
                best_score = new_best

            if best_score >= confidence_threshold:
                round_log[-1]["stop"] = "confidence_threshold"
                break
            if plateau_rounds >= 2:
                round_log[-1]["stop"] = "plateau"
                break
            if not top:
                round_log[-1]["stop"] = "no_hits"
                break

            current_seeds = [r["variant"] for r in top]

        all_hits.sort(key=lambda r: r["score"], reverse=True)
        unique: list[dict] = []
        seen_variants: set[str] = set()
        for h in all_hits:
            if h["variant"][:32] in seen_variants:
                continue
            seen_variants.add(h["variant"][:32])
            unique.append(h)
            if len(unique) >= 10:
                break

        logger_indices = [h["history_index"] for h in unique if isinstance(h.get("history_index"), int) and h["history_index"] >= 0]
        if best_score >= confidence_threshold:
            verdict, confidence = "CONFIRMED", min(0.95, 0.7 + best_score / 200)
            ev = f"evolutionary fuzz found bypass — best score {best_score} after {len(round_log)} rounds"
        elif best_score >= 40:
            verdict, confidence = "SUSPECTED", 0.55
            ev = f"partial bypass signal — best score {best_score}; iterate manually"
        else:
            verdict, confidence = "FAILED", 0.1
            ev = "no bypass found in evolutionary loop"

        human_lines = [
            f"fuzz_evolutionary: seed={seed[:60]!r} location={location}",
            f"Baseline: status={baseline['status']} len={baseline['length']} elapsed={baseline['elapsed_ms']}ms",
            f"Rounds run: {len(round_log)} | Total hits: {len(all_hits)} | Best score: {best_score}",
            "",
        ]
        for r in round_log:
            human_lines.append(f"  Round {r['round']}: {r.get('variants_sent', 0)} sent, "
                               f"{r.get('hits', 0)} hits, top={r.get('top_score', 0)}, "
                               f"{r.get('elapsed_ms', 0)}ms"
                               + (f" [STOP: {r['stop']}]" if r.get("stop") else ""))
        human_lines.append("")
        if unique:
            human_lines.append(f"Top-{min(len(unique), 5)} unique winners:")
            for h in unique[:5]:
                human_lines.append(
                    f"  [score={h['score']:>3d}] [{h['mutation_class']}/{h['mutator']}] "
                    f"status={h['status']} len={h['length']} hist={h['history_index']}"
                )
                human_lines.append(f"    variant: {h['variant']}")
                human_lines.append(f"    matched: {', '.join(h['matched'])}")

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="fuzz_feedback",
            logger_indices=logger_indices,
            details={
                "rounds_run": len(round_log),
                "round_log": round_log,
                "top_hits": unique[:5],
                "best_score": best_score,
                "baseline": {"status": baseline["status"], "length": baseline["length"]},
            },
            summary="\n".join(human_lines),
        )
