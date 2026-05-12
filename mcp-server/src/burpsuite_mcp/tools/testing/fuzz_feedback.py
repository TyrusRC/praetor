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
import re
import time
import urllib.parse
from typing import Any

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.mutate import generate_variants


def _inject(
    url: str,
    method: str,
    body: str,
    headers: dict | None,
    cookies: dict | None,
    param: str,
    payload: str,
    location: str,
) -> tuple[str, str, dict | None, dict | None]:
    """Return (url, body, headers, cookies) with payload injected at location."""
    h = dict(headers or {})
    c = dict(cookies or {})
    if location == "query":
        parsed = urllib.parse.urlparse(url)
        q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        q[param] = payload
        new_q = urllib.parse.urlencode(q, doseq=True, safe="")
        url = urllib.parse.urlunparse(parsed._replace(query=new_q))
        return url, body, h, c
    if location == "body_form":
        b = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
        b[param] = payload
        body = urllib.parse.urlencode(b, doseq=True, safe="")
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        return url, body, h, c
    if location == "body_json":
        import json as _json
        try:
            obj = _json.loads(body) if body else {}
        except Exception:
            obj = {}
        if not isinstance(obj, dict):
            obj = {}
        obj[param] = payload
        body = _json.dumps(obj)
        h.setdefault("Content-Type", "application/json")
        return url, body, h, c
    if location == "header":
        h[param] = payload
        return url, body, h, c
    if location == "cookie":
        c[param] = payload
        return url, body, h, c
    if location == "path":
        url = url.replace(f"{{{param}}}", urllib.parse.quote(payload, safe=""))
        return url, body, h, c
    return url, body, h, c


async def _send(
    method: str,
    url: str,
    headers: dict | None,
    body: str,
    cookies: dict | None,
) -> dict:
    payload: dict[str, Any] = {"method": method, "url": url, "follow_redirects": False}
    if headers:
        payload["headers"] = headers
    if body:
        payload["body"] = body
    if cookies:
        payload["cookies"] = cookies
    t0 = time.perf_counter()
    resp = await client.post("/api/http/curl", json=payload)
    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    resp["_elapsed_ms"] = elapsed_ms
    return resp


def _normalize(resp: dict) -> dict:
    """Pull (status, body, headers_dict, length, elapsed_ms) out of a curl response."""
    if "error" in resp:
        return {"error": resp["error"]}
    body_raw = resp.get("body", "") or ""
    headers_obj = resp.get("headers", {}) or {}
    # Normalize header dict: lowercased keys.
    h_norm: dict[str, str] = {}
    if isinstance(headers_obj, dict):
        for k, v in headers_obj.items():
            h_norm[str(k).lower()] = str(v)
    elif isinstance(headers_obj, list):
        for item in headers_obj:
            if isinstance(item, dict) and "name" in item and "value" in item:
                h_norm[str(item["name"]).lower()] = str(item["value"])
    return {
        "status": int(resp.get("status", 0) or 0),
        "body": body_raw,
        "headers": h_norm,
        "length": len(body_raw),
        "elapsed_ms": int(resp.get("_elapsed_ms", 0)),
    }


def _score(probe: dict, baseline: dict, signals: dict) -> tuple[list[str], int]:
    """Return (matched_signals, total_score) for a probe vs baseline."""
    matched: list[str] = []
    score = 0
    if not probe or probe.get("error"):
        return matched, 0
    if "status_in" in signals:
        targets = signals["status_in"]
        if isinstance(targets, list) and probe["status"] in targets:
            matched.append(f"status={probe['status']}")
            score += 30
    if "status_changed" in signals and signals["status_changed"]:
        if probe["status"] != baseline["status"]:
            matched.append(f"status_changed:{baseline['status']}→{probe['status']}")
            score += 25
    if "length_delta_min" in signals:
        delta = abs(probe["length"] - baseline["length"])
        if delta >= int(signals["length_delta_min"]):
            matched.append(f"length_delta={delta}")
            score += 15
    if "regex" in signals:
        pattern = signals["regex"]
        try:
            if re.search(pattern, probe["body"]):
                matched.append(f"regex:/{pattern[:40]}/")
                score += 35
        except re.error:
            pass
    if "regex_not_in_baseline" in signals:
        pattern = signals["regex_not_in_baseline"]
        try:
            in_probe = bool(re.search(pattern, probe["body"]))
            in_base = bool(re.search(pattern, baseline["body"]))
            if in_probe and not in_base:
                matched.append(f"regex_new:/{pattern[:40]}/")
                score += 40
        except re.error:
            pass
    if "header_present" in signals:
        name = str(signals["header_present"]).lower()
        if name in probe["headers"]:
            matched.append(f"header:{name}")
            score += 10
    if "header_changed" in signals:
        name = str(signals["header_changed"]).lower()
        pv = probe["headers"].get(name)
        bv = baseline["headers"].get(name)
        if pv != bv:
            matched.append(f"header_changed:{name}")
            score += 15
    if "timing_delta_ms" in signals:
        thresh = int(signals["timing_delta_ms"])
        delta = probe["elapsed_ms"] - baseline["elapsed_ms"]
        if delta >= thresh:
            matched.append(f"timing_delta={delta}ms")
            score += 30
    if "reflected" in signals and signals["reflected"]:
        payload_str = signals.get("_current_payload", "")
        if payload_str and payload_str in probe["body"]:
            matched.append("reflected_raw")
            score += 20
    return matched, score


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
    ) -> str:
        """Feedback-driven mutation loop for WAF/filter bypass discovery.

        Sends one clean baseline, then up to `max_iters` mutated variants of
        `seed`, scoring each against `signals`. Returns ranked hits with
        mutation_class so the operator can save the winning variant.

        Args:
            url: Target URL.
            parameter: Parameter name (or path placeholder) to inject into.
            seed: Starting payload — mutated by mutate_payload classes.
            signals: Dict of signal predicates. Keys:
                status_in=[400,500], status_changed=True,
                length_delta_min=200, regex="error|Exception",
                regex_not_in_baseline="root:x:", header_present="X-Debug",
                header_changed="server", timing_delta_ms=3000,
                reflected=True.
            method: HTTP method.
            body: Base request body (used for body_form / body_json locations).
            headers: Base headers.
            cookies: Base cookies.
            location: Where to inject — query | body_form | body_json |
                header | cookie | path.
            mutation_classes: Mutation classes to use (default: productive
                subset). See mutate_payload docs.
            max_iters: Max variants to send. Default 30.
            early_stop: Stop on first signal match (default True). False =
                evaluate all variants and rank.
            concurrency: Parallel in-flight requests (default 5).
        """
        if not seed:
            return "Error: seed payload is required."
        if not signals or not isinstance(signals, dict):
            return "Error: signals dict is required (status_in / regex / length_delta_min / etc.)."

        baseline_resp = await _send(method, url, headers, body, cookies)
        baseline = _normalize(baseline_resp)
        if baseline.get("error"):
            return f"Error sending baseline: {baseline['error']}"

        variants = generate_variants(seed, classes=mutation_classes, count=max_iters)
        if not variants:
            return "Error: no variants generated. Pass a non-empty seed and valid mutation classes."

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
            return "\n".join(lines)

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
        return "\n".join(lines)
