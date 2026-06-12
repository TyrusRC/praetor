"""confirm_with_clean_room — XBOW exploration/validation split.

XBOW's confidence comes from running discovery and verification as SEPARATE
processes. Discovery may pull in many heuristics and false leads; the second
process re-runs the exact PoC from scratch with NO exploration context, only
the canonical reproduction recipe. If the markers come back, it's real.

This is a pre-promotion gate for save_finding: replay the captured Logger
entry, look for the originally-claimed markers, return CONFIRMED/FAILED.

Inputs:
  - The Logger index from the original confirming replay (or a list).
  - Expected markers (substring(s) that must appear in response body).
  - Optional: status_code expectation, header substring expectations.

The replay uses `/api/logger/resend/<index>` so it carries the same method,
URL, headers, body — verbatim. No path is taken from the exploration's
internal reasoning.

Returns VerdictResult.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import make_verdict, error_verdict


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def confirm_with_clean_room(
        logger_index: int,
        expected_markers: list[str],
        expected_status: int | None = None,
        expected_header_contains: dict[str, str] | None = None,
        replays: int = 3,
        require_all_markers: bool = True,
    ) -> dict:
        """Replay a captured PoC `replays` times from clean state, verify markers.

        This is the canonical second-pass confirmation: re-fire the original
        request without ANY of the exploration heuristics that may have
        produced the suspected finding. Marker check only; no interpretation.

        Args:
            logger_index: Logger index of the confirming replay (the entry
                whose response originally proved the finding).
            expected_markers: list of substrings that must appear in the
                response body (or headers — checked together).
            expected_status: optional exact status code expectation.
            expected_header_contains: optional {header_name: substring}
                map. Each header must contain the substring.
            replays: how many times to replay (default 3 — matches Rule 10a
                timing/blind reproduction floor).
            require_all_markers: when True, ALL markers must match per
                replay; when False, ANY marker counts. Default True.

        Returns: VerdictResult — CONFIRMED if every replay matches all
        criteria; SUSPECTED if some replays match; FAILED if none match.
        """
        if logger_index < 0:
            return error_verdict("logger_index must be >= 0",
                                 vuln_type="clean_room_confirm")
        if not expected_markers:
            return error_verdict(
                "expected_markers cannot be empty — clean-room confirmation "
                "requires explicit marker(s) to look for",
                vuln_type="clean_room_confirm",
            )

        reproductions: list[dict] = []
        logger_indices: list[int] = []
        confirmed_count = 0

        for attempt in range(max(1, replays)):
            resp = await client.post("/api/logger/resend", json={
                "index": logger_index,
            })
            new_li = resp.get("logger_index", -1)
            status = resp.get("status_code") or resp.get("status")
            body = resp.get("response_body") or ""
            headers = resp.get("response_headers") or {}
            if isinstance(new_li, int) and new_li >= 0:
                logger_indices.append(new_li)

            marker_results = {m: (m in body) for m in expected_markers}
            if require_all_markers:
                markers_ok = all(marker_results.values())
            else:
                markers_ok = any(marker_results.values())

            status_ok = (expected_status is None or status == expected_status)

            header_ok = True
            if expected_header_contains:
                hdr_map = _normalise_headers(headers)
                for hk, needle in expected_header_contains.items():
                    if needle not in hdr_map.get(hk.lower(), ""):
                        header_ok = False
                        break

            replay_match = markers_ok and status_ok and header_ok
            if replay_match:
                confirmed_count += 1

            reproductions.append({
                "attempt": attempt + 1,
                "logger_index": new_li,
                "status_code": status,
                "markers_matched": [m for m, ok in marker_results.items() if ok],
                "markers_missed": [m for m, ok in marker_results.items() if not ok],
                "status_ok": status_ok,
                "header_ok": header_ok,
                "replay_match": replay_match,
            })

        if confirmed_count == replays:
            return make_verdict(
                "CONFIRMED", 0.95,
                f"Clean-room reproduction succeeded {confirmed_count}/{replays} "
                "times — markers + status + header expectations all matched "
                "on every replay.",
                vuln_type="clean_room_confirm",
                logger_indices=logger_indices,
                reproductions=reproductions,
                details={"replays": replays, "confirmed": confirmed_count,
                         "source_logger_index": logger_index,
                         "expected_markers": expected_markers},
                summary=f"CONFIRMED via clean-room replay ({confirmed_count}/{replays})",
            )

        if confirmed_count > 0:
            return make_verdict(
                "SUSPECTED", 0.55,
                f"Partial reproduction: {confirmed_count}/{replays} replays "
                "matched all criteria. Flaky finding — investigate timing, "
                "race conditions, or stateful-once-only behaviour before "
                "promoting to CONFIRMED.",
                vuln_type="clean_room_confirm",
                logger_indices=logger_indices,
                reproductions=reproductions,
                details={"replays": replays, "confirmed": confirmed_count,
                         "source_logger_index": logger_index},
                summary=f"SUSPECTED — flaky clean-room replay ({confirmed_count}/{replays})",
            )

        return make_verdict(
            "FAILED", 0.05,
            f"Clean-room replay failed on every attempt ({replays}/{replays}). "
            "Markers, status, or headers did not reproduce. Likely false "
            "positive from exploration heuristics OR target patched between "
            "discovery and verification.",
            vuln_type="clean_room_confirm",
            logger_indices=logger_indices,
            reproductions=reproductions,
            details={"replays": replays, "source_logger_index": logger_index,
                     "expected_markers": expected_markers},
            summary=f"FAILED clean-room replay — likely FP or target changed",
        )


def _normalise_headers(headers) -> dict[str, str]:
    """Accept either dict-of-strings or list-of-{name,value} shape."""
    out: dict[str, str] = {}
    if isinstance(headers, dict):
        for k, v in headers.items():
            out[k.lower()] = str(v)
    elif isinstance(headers, list):
        for h in headers:
            if isinstance(h, dict):
                out[(h.get("name") or "").lower()] = h.get("value") or ""
    return out
