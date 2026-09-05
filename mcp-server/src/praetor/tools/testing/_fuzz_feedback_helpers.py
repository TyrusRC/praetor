"""Inject / send / normalize / score helpers for fuzz_with_feedback."""

import re
import time
import urllib.parse
from typing import Any

from praetor import client


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
    if signals.get("status_changed"):
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
    if signals.get("reflected"):
        payload_str = signals.get("_current_payload", "")
        if payload_str and payload_str in probe["body"]:
            matched.append("reflected_raw")
            score += 20
    return matched, score


