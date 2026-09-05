"""CVE→class map + variant generators — extracted from cve_variant_probe.py (split 2026-07-23)."""

from __future__ import annotations

from typing import Any
from ._cve_variant_defs import (
    _rsc_variants, _nextjs_cache_variants, _trpc_variants, _proto_variants,
    _nextjs_ws_ssrf_variants, _generic_variants, _nextjs_middleware_variants,
)


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


_GENERATORS: dict[str, Any] = {
    "react_server_components": _rsc_variants,
    "nextjs_cache_poisoning":  _nextjs_cache_variants,
    "nextjs_middleware_bypass": _nextjs_middleware_variants,
    "trpc_sspp":               _trpc_variants,
    "prototype_pollution":     _proto_variants,
    "nextjs_ws_upgrade_ssrf":  _nextjs_ws_ssrf_variants,
    "generic":                 _generic_variants,
}

