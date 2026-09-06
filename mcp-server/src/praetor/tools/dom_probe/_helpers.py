"""Marker generation, target-URL construction, in-app click-crawl, init-script
loader. All consumed by the probe entry point in __init__.py."""

import time
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qsl

from ._constants import (
    _CSPP_DEFAULT_KEYS,
    _DESTRUCTIVE_HREFS,
    _FRAGMENT_SHAPES,
    _POLYGLOTS,
)


_INIT_JS_PATH = Path(__file__).parent / "dom_probe_init.js"
_INIT_JS_CACHE: str | None = None


def _load_init_js() -> str:
    global _INIT_JS_CACHE
    if _INIT_JS_CACHE is None:
        _INIT_JS_CACHE = _INIT_JS_PATH.read_text(encoding="utf-8")
    return _INIT_JS_CACHE


def _make_marker(suffix: str = "") -> str:
    seq = int(time.time() * 1000) % 100_000_000
    return f"swk{seq:x}{suffix}"


def _validate_probe_inputs(
    source_kinds: list[str] | None,
    polyglots: list[str] | None,
    fragment_shapes: list[str] | None,
    cspp_known_keys: list[str] | None,
):
    """Resolve + validate the probe knobs.

    Returns a 4-tuple (kinds, active_polys, active_shapes, active_cspp_keys) on
    success, or an error string on the first invalid value.
    """
    kinds = source_kinds or ["query", "fragment", "fragment_kv", "fragment_shapes", "referrer"]
    valid_kinds = {"query", "fragment", "fragment_kv", "fragment_shapes", "referrer"}
    bad = [k for k in kinds if k not in valid_kinds]
    if bad:
        return f"Error: unknown source_kind(s) {bad}. Choose from {sorted(valid_kinds)}."

    active_polys = polyglots or ["plain", "angular_csti", "proto_pollute", "xss_svg"]
    bad_p = [p for p in active_polys if p not in _POLYGLOTS]
    if bad_p:
        return f"Error: unknown polyglot(s) {bad_p}. Choose from {sorted(_POLYGLOTS)}."

    active_shapes = fragment_shapes or [
        "bare", "param", "qs_in_hash", "hash_route", "hash_route_kv", "hashbang_kv",
    ]
    bad_s = [s for s in active_shapes if s not in _FRAGMENT_SHAPES]
    if bad_s:
        return f"Error: unknown fragment_shape(s) {bad_s}. Choose from {sorted(_FRAGMENT_SHAPES)}."

    if cspp_known_keys is None:
        active_cspp_keys = list(_CSPP_DEFAULT_KEYS)
    else:
        active_cspp_keys = [str(k) for k in cspp_known_keys if isinstance(k, str) and k]

    return kinds, active_polys, active_shapes, active_cspp_keys


def _build_target_url(
    base_url: str,
    payload: str,
    source_param: str,
    source_kind: str,
    fragment_shape: str = "bare",
) -> tuple[str, dict]:
    parsed = urlparse(base_url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    fragment = parsed.fragment
    extra_headers: dict = {}

    if source_kind == "query":
        query[source_param] = payload
    elif source_kind == "fragment":
        fragment = payload
    elif source_kind == "fragment_kv":
        fragment = f"{source_param}={payload}"
    elif source_kind == "fragment_shapes":
        shape = _FRAGMENT_SHAPES.get(fragment_shape, "{payload}")
        fragment = shape.format(param=source_param, payload=payload)
    elif source_kind == "referrer":
        extra_headers["Referer"] = f"https://attacker.example/?{source_param}={payload}"
    else:
        raise ValueError(f"Unknown source_kind: {source_kind}")

    new_url = parsed._replace(
        query=urlencode(query, doseq=True),
        fragment=fragment,
    ).geturl()
    return new_url, extra_headers


async def _click_crawl(page, max_clicks: int = 4, wait_each_ms: int = 1500) -> None:
    """Click up to N visible same-origin anchors, waiting between each.
    Skips destructive links. Best-effort — stays defensive on stale DOM."""
    try:
        same_origin = await page.evaluate(
            """() => {
                const out = [];
                const origin = location.origin;
                document.querySelectorAll('a[href]').forEach(a => {
                    try {
                        const href = a.href;
                        if (!href || !href.startsWith(origin)) return;
                        const txt = (a.textContent || '').trim().slice(0, 40);
                        if (a.offsetParent === null) return;  // not visible
                        out.push(href);
                    } catch (e) {}
                });
                // De-dupe, keep first 10
                return Array.from(new Set(out)).slice(0, 10);
            }"""
        )
    except Exception:
        return

    if not same_origin:
        return

    candidates = [
        h for h in same_origin
        if not any(d in h.lower() for d in _DESTRUCTIVE_HREFS)
    ][:max_clicks]

    for href in candidates:
        try:
            await page.goto(href, wait_until="domcontentloaded", timeout=15000)
            await page.wait_for_timeout(wait_each_ms)
        except Exception:
            continue
