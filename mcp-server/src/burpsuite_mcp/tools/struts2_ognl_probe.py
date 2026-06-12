"""Struts2 OGNL injection probe — Rapid7 InsightAppSec May 2026 parity.

Detects OGNL evaluation via arithmetic echo: %{1337*1338} → 1788906.
Covers S2-057 / S2-059 / S2-061 family plus generic OGNL-in-parameter
classes. Also tests Spring SpEL #{...} engine.

Benign payloads only — arithmetic-echo, never destructive (Rule 5).
Returns VerdictResult.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import make_verdict, error_verdict


_ARITHMETIC_MARKER = "1788906"  # 1337 * 1338

_OGNL_PAYLOADS = [
    ("ognl_curly", "%{1337*1338}"),
    ("ognl_paren", "%{(1337*1338)}"),
    ("ognl_at",    "%{@java.lang.Math@abs(-1337)*1338}"),
    ("spel_hash",  "#{1337*1338}"),
    ("spel_t",     "#{T(java.lang.Math).abs(-1337)*1338}"),
    ("jinja_like", "${1337*1338}"),  # Java JSP EL / FreeMarker-ish
    ("freemarker", "${1337?long * 1338}"),
]

_INJECTION_LOCATIONS = ("query", "header_referer", "path_segment")

_PER_PROBE_TIMEOUT = 15


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_struts2_ognl(
        target_url: str,
        parameter: str = "",
        method: str = "GET",
        session: str = "",
    ) -> dict:
        """Probe a Java endpoint for Struts2 OGNL / Spring SpEL / FreeMarker EL injection.

        Sends benign arithmetic-echo payloads (1337*1338=1788906) across 7
        engine syntaxes and 3 injection locations (query param, Referer
        header, path segment). Detect via 1788906 in response body.

        Args:
            target_url: target endpoint URL.
            parameter: optional query parameter name. When empty, payload is
                injected as path-segment + Referer-header variants only.
            method: HTTP method (default GET).
            session: optional session name for authenticated probing.

        Returns: VerdictResult — CONFIRMED at any 1788906 echo; SUSPECTED if
        a 500 with OGNL stack-trace marker; FAILED otherwise.
        """
        if not target_url:
            return error_verdict("target_url required", vuln_type="struts2_ognl")

        reproductions: list[dict] = []
        logger_indices: list[int] = []
        confirmed_hits: list[dict] = []
        suspected_hits: list[dict] = []

        for engine_label, payload in _OGNL_PAYLOADS:
            for location in _INJECTION_LOCATIONS:
                if location == "query" and not parameter:
                    continue
                resp = await _send_payload(
                    target_url, method, parameter, payload, location, session,
                )
                status = resp.get("status_code") or resp.get("status")
                body = resp.get("response_body", "") or ""
                logger_idx = resp.get("logger_index", -1)
                if isinstance(logger_idx, int) and logger_idx >= 0:
                    logger_indices.append(logger_idx)
                entry = {
                    "engine": engine_label,
                    "location": location,
                    "status_code": status,
                    "logger_index": logger_idx,
                }
                if _ARITHMETIC_MARKER in body:
                    entry["matched"] = "arithmetic_echo"
                    confirmed_hits.append(entry)
                elif status == 500 and _has_ognl_stack_marker(body):
                    entry["matched"] = "ognl_stack_marker"
                    suspected_hits.append(entry)
                reproductions.append(entry)

        if confirmed_hits:
            first = confirmed_hits[0]
            return make_verdict(
                "CONFIRMED",
                0.92,
                f"OGNL/SpEL injection — arithmetic echo (1788906) from "
                f"{first['engine']}/{first['location']} "
                f"and {len(confirmed_hits)} total variant(s)",
                vuln_type="struts2_ognl",
                logger_indices=logger_indices,
                reproductions=reproductions,
                details={
                    "confirmed_count": len(confirmed_hits),
                    "first_hit": first,
                },
                summary=(
                    f"CONFIRMED OGNL/SpEL injection on {target_url} via "
                    f"{first['engine']} in {first['location']}"
                ),
            )

        if suspected_hits:
            return make_verdict(
                "SUSPECTED",
                0.55,
                f"OGNL stack-trace marker in {len(suspected_hits)} response(s) "
                "but no arithmetic echo — engine likely present but locked down "
                "or sandboxed. Manual review recommended.",
                vuln_type="struts2_ognl",
                logger_indices=logger_indices,
                reproductions=reproductions,
                details={"suspected_count": len(suspected_hits)},
                summary=f"SUSPECTED OGNL surface on {target_url} (no arithmetic echo)",
            )

        return make_verdict(
            "FAILED",
            0.10,
            f"No OGNL/SpEL evaluation signal across {len(reproductions)} probe variants",
            vuln_type="struts2_ognl",
            logger_indices=logger_indices,
            reproductions=reproductions,
            summary=f"FAILED — no OGNL/SpEL injection on {target_url}",
        )


_OGNL_STACK_MARKERS = (
    "ognl.OgnlException",
    "ognl.ParseException",
    "ognl.MethodFailedException",
    "org.apache.struts2",
    "freemarker.core.ParseException",
    "org.springframework.expression.spel.SpelEvaluationException",
)


def _has_ognl_stack_marker(body: str) -> bool:
    if not body:
        return False
    sample = body[:8192]
    return any(marker in sample for marker in _OGNL_STACK_MARKERS)


async def _send_payload(
    target_url: str, method: str, parameter: str, payload: str,
    location: str, session: str,
) -> dict:
    """Inject payload at one of {query, header_referer, path_segment}."""
    from urllib.parse import quote, urlsplit, urlunsplit

    url = target_url
    headers: list[dict] = []

    if location == "query":
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{parameter}={quote(payload, safe='')}"
    elif location == "header_referer":
        headers.append({"name": "Referer", "value": payload})
    elif location == "path_segment":
        parts = urlsplit(url)
        new_path = parts.path.rstrip("/") + "/" + quote(payload, safe="")
        url = urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))

    if session:
        return await client.post("/api/session/request", json={
            "session": session,
            "method": method,
            "url": url,
            "headers": headers,
        })
    return await client.post("/api/http/curl", json={
        "url": url,
        "method": method,
        "headers": headers,
    })
