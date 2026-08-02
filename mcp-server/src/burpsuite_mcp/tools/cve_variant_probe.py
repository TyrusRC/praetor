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

import time
from typing import Any

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict

# Split 2026-07-23: generators + scoring live in sibling modules; re-exported
# here so `from ...cve_variant_probe import _resolve_class/_GENERATORS/...` and
# the generator/scoring names keep resolving for callers and tests.
from burpsuite_mcp.tools._cve_variant_gen import (  # noqa: F401
    _CVE_TO_CLASS, _resolve_class, _GENERATORS,
    _rsc_variants, _nextjs_cache_variants, _trpc_variants, _proto_variants,
    _nextjs_ws_ssrf_variants, _generic_variants, _nextjs_middleware_variants,
)
from burpsuite_mcp.tools._cve_variant_score import _score_response

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
        """Send bounded CVE-aware PoC variants — confirm or fail fast, first-CONFIRMED short-circuit.

        Args:
            cve_id: e.g. "CVE-2025-55182" or alias; maps to a class, else `generic`.
            target_url: Full target URL (path is part of the variant).
            vuln_class: Optional override: react_server_components/nextjs_cache_poisoning/trpc_sspp/prototype_pollution/generic.
            baseline_payload: Public PoC body; __CANARY__ is substituted per call.
            action_id: RSC/Next.js Server Action ID; zero-stub if empty.
            extra_headers: Headers merged into every variant (cookies/bearer/CSRF).
            max_variants: Request cap. Default 12, ceiling 50.
            per_request_timeout: Per-request seconds. Default 15.
            total_budget_seconds: Whole-call wall budget. Default 60.
            session: Burp session name (auth-aware).

        Returns VerdictResult dict (CONFIRMED on canary echo / class marker; SUSPECTED on partial; FAILED otherwise).
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
            if v.get("url_suffix"):  # path suffix (e.g. .rsc) — before query
                url = f"{url}{v['url_suffix']}"
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
