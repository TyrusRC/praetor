"""auto_probe helpers: target ranking, coverage read/write, and annotation.

Pure structural extraction from auto_probe.py — the tool wrapper stays thin and
these carry the coverage-filter (R13), coverage-write (R20), risk-ordering
(W36-P5) and proxy-annotation (Rule 31) blocks.
"""

import asyncio
import json

from praetor import client


def _rank_order_targets(targets: list[dict]) -> list[dict]:
    """Order probe targets highest-risk-first (W36-P5, Burp 2026.6 parity).

    Reuses the exact scoring engine behind rank_attack_targets — no
    reimplemented math — so early probes hit the most valuable surface.
    Safe default: any failure falls back to the caller's original order.
    """
    try:
        from .rank_targets import (
            _METHOD_WEIGHT,
            _LOCATION_WEIGHT,
            _endpoint_score,
            _param_score,
        )

        def _score(t: dict) -> int:
            ep_s, _ = _endpoint_score(t.get("path") or t.get("url") or "")
            p_s, _ = _param_score(t.get("parameter") or "")
            m_s = _METHOD_WEIGHT.get((t.get("method") or "GET").upper(), 5)
            loc_s = _LOCATION_WEIGHT.get(t.get("location") or "", 5)
            return ep_s + p_s + m_s + loc_s

        return sorted(targets, key=_score, reverse=True)
    except Exception:
        return targets


def filter_covered_targets(
    domain: str,
    skip_already_covered: bool,
    targets: list[dict],
    categories: list[str] | None,
    knowledge: list[dict],
) -> tuple[list[dict], int, str]:
    """R13: drop (endpoint, param) targets whose every active category is already
    covered at the current knowledge_version. Returns (targets, skipped_count,
    kb_drift_hint)."""
    skipped_count = 0
    kb_drift_hint = ""
    if domain and skip_already_covered:
        try:
            from praetor.tools.intel import _knowledge_version, _intel_path
            cov_path = _intel_path(domain) / "coverage.json"
            if cov_path.exists():
                cov = json.loads(cov_path.read_text(encoding="utf-8"))
                cur_kv = _knowledge_version()
                recorded_kv = cov.get("knowledge_version")
                covered_keys: set[tuple] = set()
                stale_tuples = 0
                for entry in cov.get("entries", []):
                    if entry.get("knowledge_version") == cur_kv:
                        covered_keys.add((
                            entry.get("endpoint", ""),
                            entry.get("parameter", ""),
                            entry.get("category", ""),
                        ))
                    else:
                        stale_tuples += 1
                if recorded_kv is not None and recorded_kv != cur_kv and stale_tuples:
                    kb_drift_hint = (
                        f"  [hint] knowledge_version drift: {stale_tuples} tuple(s) tested at "
                        f"v{recorded_kv} are eligible for re-test at v{cur_kv}. "
                        f"Re-run with skip_already_covered=False to pick them up.\n"
                    )
                if covered_keys:
                    active_cats = set(categories or [
                        k.get("category") for k in knowledge
                    ])
                    new_targets = []
                    for t in targets:
                        ep = t.get("path", "")
                        par = t.get("parameter", "")
                        cats_to_run = [c for c in active_cats if (ep, par, c) not in covered_keys]
                        if cats_to_run:
                            new_targets.append(t)
                        else:
                            skipped_count += 1
                    targets = new_targets
        except (OSError, json.JSONDecodeError, ValueError):
            pass
    return targets, skipped_count, kb_drift_hint


async def annotate_findings(findings_sorted: list[dict]) -> int:
    """Auto-annotate proxy history (Rule 31). Gathers concurrently — sequential
    awaits cost ~50ms each, compounded to 1-2s on 30-finding runs. Returns the
    count of successfully annotated entries."""
    async def _annotate(finding: dict) -> bool:
        idx = finding.get("history_index") or finding.get("proxy_index") or finding.get("logger_index")
        if idx is None:
            return False
        conf = finding.get("confidence", 0) or 0
        # Capped at ORANGE on purpose. Per the Rule 18 colour convention
        # RED means "confirmed critical/high" — a claim only verification
        # can make. auto_probe's confidence is a matcher score, so painting
        # it RED produced a history full of red entries that no finding
        # backed, and every later reader had to re-derive which were real.
        color = (
            "ORANGE" if conf >= 0.60 else
            "YELLOW" if conf >= 0.30 else
            "GRAY"
        )
        cat = finding.get("category", "?")
        ctx = finding.get("context", "?")
        param = finding.get("parameter", "?")
        # Self-identifying as unverified: the comment states what produced
        # it and what it is not, so it is never mistaken for PoC evidence.
        comment = (
            f"auto_probe UNVERIFIED | {cat}/{ctx} | param={param} | "
            f"match_confidence={conf:.2f} | verify before citing"
        )
        try:
            await client.post("/api/annotations/set", json={
                "index": int(idx),
                "color": color,
                "comment": comment[:300],
                "endpoint": finding.get("endpoint", "") or "",
            })
            return True
        except Exception:
            return False

    ann_results = await asyncio.gather(*(_annotate(f) for f in findings_sorted), return_exceptions=True)
    return sum(1 for r in ann_results if r is True)


def record_coverage(domain: str, data: dict) -> None:
    """R20 economy lever — record every (endpoint, parameter, category) tuple
    the server reports having probed so a follow-on auto_probe with
    skip_already_covered=True doesn't re-test them. Best-effort."""
    if not domain:
        return
    try:
        from praetor.tools.intel import _knowledge_version, _intel_path
        cov_path = _intel_path(domain) / "coverage.json"
        cov_path.parent.mkdir(parents=True, exist_ok=True)
        cov = {"entries": []}
        if cov_path.exists():
            try:
                cov = json.loads(cov_path.read_text(encoding="utf-8")) or {"entries": []}
            except (OSError, json.JSONDecodeError):
                cov = {"entries": []}
        if "entries" not in cov or not isinstance(cov["entries"], list):
            cov["entries"] = []
        kv = _knowledge_version()
        # Index existing entries so we update kv in place rather than
        # appending duplicates each run.
        seen: set[tuple] = set()
        for e in cov["entries"]:
            seen.add((e.get("endpoint", ""), e.get("parameter", ""), e.get("category", "")))
        # Record ONLY the categories the server reports having actually
        # probed. The previous version recorded every category in the
        # loaded knowledge base, so a run that sent 20 probes marked
        # ~135 classes covered — and skip_already_covered=True (the
        # default) then made those classes permanently unreachable on
        # this target. A coverage entry is a claim that a class was
        # tested; writing one for an untested class is the same defect
        # as citing evidence that was never collected.
        probed = data.get("probed_categories") or []
        for rec in probed:
            if not isinstance(rec, dict):
                continue
            ep = rec.get("path", "")
            par = rec.get("parameter", "")
            for cat in rec.get("categories") or []:
                key = (ep, par, cat)
                if key in seen:
                    for e in cov["entries"]:
                        if (e.get("endpoint"), e.get("parameter"), e.get("category")) == key:
                            e["knowledge_version"] = kv
                            break
                else:
                    cov["entries"].append({
                        "endpoint": ep,
                        "parameter": par,
                        "category": cat,
                        "knowledge_version": kv,
                    })
                    seen.add(key)
        # Compact on disk. coverage.json is re-read by load_target_intel
        # on every session start; indent=2 on a few thousand four-key
        # records was 65 KB of mostly whitespace and repeated keys.
        cov_path.write_text(
            json.dumps(cov, separators=(",", ":")), encoding="utf-8"
        )
    except Exception:
        # coverage write is best-effort; failure must not break the
        # main probe response.
        pass
