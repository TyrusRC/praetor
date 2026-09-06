"""Implementation for test_ssti — split from test_ssti.py to keep the tool
wrapper thin. The wrapper in test_ssti.py owns the @mcp.tool() signature +
docstring and delegates here."""

from __future__ import annotations

import time

from praetor.tools.testing._verdict import make_verdict

from ._ssti_payloads import _POLYGLOT, _POLYGLOT_HINTS, _DISTINGUISHERS, _CAPABILITIES, _BLIND_SLEEPS
from ._ssti_helpers import _build_request, _send, _logger_index, _body


async def _run_test_ssti(
    endpoint: str,
    parameter: str,
    method: str = "GET",
    session: str = "",
    blind: bool = False,
    blind_seconds: int = 5,
    engine_hint: str = "",
) -> dict:
    secs = max(2, min(15, int(blind_seconds)))
    report: list[str] = [
        f"test_ssti — endpoint={endpoint} parameter={parameter} method={method.upper()}",
        "",
    ]
    evidence_idx = -1
    detected: str | None = None
    confidence = "none"
    capabilities: list[tuple[str, int, bool]] = []  # (cap_name, idx, hit)

    # ── Phase 1: polyglot ────────────────────────────────────────
    report.append("Phase 1 (polyglot):")
    poly_req = _build_request(endpoint, parameter, method, _POLYGLOT)
    poly_resp = await _send(poly_req, session)
    if isinstance(poly_resp, dict) and "error" in poly_resp:
        return f"polyglot probe failed: {poly_resp['error']}"
    poly_idx = _logger_index(poly_resp)
    poly_body = _body(poly_resp)
    poly_status = poly_resp.get("status_code", "?")
    polyglot_hint: str | None = None
    for engine, patterns in _POLYGLOT_HINTS:
        if any(p in poly_body for p in patterns):
            polyglot_hint = engine
            break
    report.append(f"  status={poly_status} idx={poly_idx} "
                  f"hint={polyglot_hint or 'none'}")
    if polyglot_hint:
        evidence_idx = max(evidence_idx, poly_idx)

    # ── Phase 2: distinguisher (skipped if engine_hint provided) ─
    if engine_hint:
        detected = engine_hint.lower().strip()
        confidence = "operator"
        report.append("")
        report.append(f"Phase 2 (math): SKIPPED — engine_hint={detected}")
    else:
        report.append("")
        report.append("Phase 2 (math distinguisher):")
        best: tuple[str, int, list[str]] | None = None  # (payload, idx, engines)
        for payload, marker, engines in _DISTINGUISHERS:
            req = _build_request(endpoint, parameter, method, payload)
            resp = await _send(req, session)
            if isinstance(resp, dict) and "error" in resp:
                continue
            idx = _logger_index(resp)
            body = _body(resp)
            hit = marker in body
            tag = "MATCH" if hit else "miss"
            report.append(
                f"  {tag} payload={payload!r:24} marker={marker!r:>10} "
                f"engines={','.join(engines)} idx={idx}"
            )
            if hit:
                evidence_idx = max(evidence_idx, idx)
                # First single-engine match wins; otherwise keep the
                # narrowest family for capability phase.
                if len(engines) == 1:
                    detected = engines[0]
                    confidence = "high"
                    best = (payload, idx, engines)
                    break
                if best is None or len(engines) < len(best[2]):
                    best = (payload, idx, engines)
        if detected is None and best is not None:
            # Multiple candidates — refine with polyglot hint if it
            # narrowed something, else take the first as default and
            # let Phase 3 prove the rest.
            if polyglot_hint and polyglot_hint in best[2]:
                detected = polyglot_hint
                confidence = "medium (polyglot+math)"
            else:
                detected = best[2][0]
                confidence = f"low (family={','.join(best[2])})"

    if detected is None:
        report.append("")
        report.append("Verdict: NO SSTI detected. Math distinguishers all "
                      "missed. If you suspect SSTI in an output-suppressed "
                      "context, re-run with blind=True.")
        if blind:
            # Phase 4 still runs even when math missed — useful for
            # blind-only cases.
            pass
        else:
            return "\n".join(report)

    # ── Phase 3: capability probes ──────────────────────────────
    if detected:
        report.append("")
        report.append(f"Phase 3 (capabilities, engine={detected}):")
        probes = _CAPABILITIES.get(detected, [])
        if not probes:
            report.append(f"  no capability probes registered for {detected}")
        for cap, payload, marker in probes:
            req = _build_request(endpoint, parameter, method, payload)
            resp = await _send(req, session)
            if isinstance(resp, dict) and "error" in resp:
                report.append(f"  ERR   {cap:18} {resp['error'][:60]}")
                continue
            idx = _logger_index(resp)
            body = _body(resp)
            hit = marker in body if marker else len(body) > 0
            capabilities.append((cap, idx, hit))
            tag = "YES" if hit else "no "
            report.append(f"  {tag}  {cap:18} idx={idx} marker={marker!r}")
            if hit:
                evidence_idx = max(evidence_idx, idx)

    # ── Phase 4: blind (opt-in) ─────────────────────────────────
    blind_verdict: str | None = None
    if blind:
        report.append("")
        engine_for_blind = detected or polyglot_hint
        if engine_for_blind and engine_for_blind in _BLIND_SLEEPS:
            gadget = _BLIND_SLEEPS[engine_for_blind].replace("__SECS__", str(secs))
            # Baseline
            base_req = _build_request(endpoint, parameter, method, "x")
            t0 = time.monotonic()
            base_resp = await _send(base_req, session)
            base_ms = int((time.monotonic() - t0) * 1000)
            base_idx = _logger_index(base_resp) if isinstance(base_resp, dict) else -1
            # Sleep probe
            sleep_req = _build_request(endpoint, parameter, method, gadget)
            t0 = time.monotonic()
            sleep_resp = await _send(sleep_req, session)
            sleep_ms = int((time.monotonic() - t0) * 1000)
            sleep_idx = _logger_index(sleep_resp) if isinstance(sleep_resp, dict) else -1
            delta_ms = sleep_ms - base_ms
            expected_ms = secs * 1000
            # Consider it a hit if the delta is at least 70% of the
            # requested sleep duration — tolerates jitter.
            hit = delta_ms >= int(expected_ms * 0.7)
            report.append(
                f"Phase 4 (blind, engine={engine_for_blind}, sleep={secs}s):"
            )
            report.append(
                f"  baseline {base_ms}ms (idx={base_idx})  "
                f"sleep {sleep_ms}ms (idx={sleep_idx})  "
                f"delta {delta_ms}ms  expected≥{int(expected_ms*0.7)}ms"
            )
            report.append(f"  result: {'TIMING HIT' if hit else 'no delta'}")
            if hit:
                blind_verdict = engine_for_blind
                evidence_idx = max(evidence_idx, sleep_idx)
                if detected is None:
                    detected = engine_for_blind
                    confidence = "blind (timing only)"
        else:
            report.append(f"Phase 4 (blind): no sleep gadget for engine="
                          f"{engine_for_blind or 'unknown'} — skipped")

    # ── Verdict ─────────────────────────────────────────────────
    report.append("")
    if detected and (any(h for _, _, h in capabilities) or blind_verdict):
        confirmed_caps = [c for c, _, h in capabilities if h]
        report.append(
            f"Verdict: SSTI CONFIRMED — engine={detected} "
            f"(confidence={confidence})"
        )
        if confirmed_caps:
            report.append(f"  capabilities: {', '.join(confirmed_caps)}")
        if blind_verdict:
            report.append(f"  blind: timing hit on {blind_verdict}")
        report.append(f"  evidence anchor: logger_index={evidence_idx}")
        report.append("")
        report.append("Next steps:")
        report.append(
            f"  - confirm_ssti(endpoint={endpoint!r}, parameter={parameter!r}, "
            f"engine={detected!r})  # math reflection sanity check"
        )
        report.append(
            f"  - confirm_rce(endpoint={endpoint!r}, parameter={parameter!r}, "
            f"command='id')           # only if engine allows OS exec"
        )
        report.append(
            f"  - assess_finding(vuln_type='ssti', logger_index={evidence_idx}, "
            f"evidence='test_ssti engine={detected} caps={','.join(confirmed_caps) or 'reflection'}')"
        )
    elif detected:
        report.append(
            f"Verdict: REFLECTION ONLY — engine={detected} "
            f"(confidence={confidence}) but no capability probe confirmed."
        )
        report.append("  Treat as suspected, not confirmed. Re-run with blind=True "
                      "if output is suppressed, or move on if reflection alone "
                      "(no exploit primitive) doesn't qualify for the program.")
    else:
        report.append("Verdict: NO SSTI — math/blind all negative.")

    human = "\n".join(report)
    logger_indices = [evidence_idx] if evidence_idx >= 0 else []

    if confirmed_caps:
        verdict, conf_score = "CONFIRMED", 0.85
        ev = f"SSTI confirmed engine={detected}; capabilities={','.join(confirmed_caps)}"
    elif detected:
        verdict, conf_score = "SUSPECTED", 0.6
        ev = f"SSTI reflection-only — engine={detected} (no capability probe confirmed)"
    else:
        verdict, conf_score = "FAILED", 0.1
        ev = "no SSTI — math/blind probes all negative"

    return make_verdict(
        verdict, conf_score, ev,
        vuln_type="ssti",
        logger_indices=logger_indices,
        details={
            "endpoint": endpoint,
            "parameter": parameter,
            "engine": detected,
            "confidence_label": confidence,
            "confirmed_capabilities": confirmed_caps,
        },
        summary=human,
    )
