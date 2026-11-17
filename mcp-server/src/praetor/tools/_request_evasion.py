"""Request evasion layer — randomize outbound traffic patterns.

Blue-team tools (WAF, IDS, SIEM correlation, bot-detection) fingerprint
pentest traffic by its PREDICTABILITY: identical UA on every request,
identical header order, uniform timing, no Accept-Language variation, no
Referer. A human with a browser produces none of those patterns.

This module makes outbound requests look like varied organic browser traffic:
  1. Fingerprint rotation — multiple browser profiles, not one static UA.
  2. Header order shuffling — randomize header key order per request.
  3. Decoy header injection — occasionally add benign extra headers.
  4. Accept-Language variation — rotate locale preferences.
  5. Cache-control variation — sporadic cache headers like a real browser.
  6. Referer injection — plausible same-origin referer when absent.

Configure via set_evasion_profile() or PRAETOR_EVASION env var.
Default is 'light' (fingerprint rotation + accept-language variation).

The evasion layer sits BETWEEN the realistic-header merge and the final
header dict. apply_realistic_headers() calls apply_evasion() when active.
"""

from __future__ import annotations

import os
import random
import time
from urllib.parse import urlparse

# ── Browser fingerprint pool ────────────────────────────────────────────────
# Real-world UA + sec-ch-ua sets. Each is a coherent browser identity.

_FINGERPRINTS: list[dict[str, str]] = [
    {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Sec-Ch-Ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Ch-Ua-Mobile": "?0",
    },
    {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "Sec-Ch-Ua": '"Google Chrome";v="130", "Chromium";v="130", "Not_A Brand";v="24"',
        "Sec-Ch-Ua-Platform": '"macOS"',
        "Sec-Ch-Ua-Mobile": "?0",
    },
    {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
        "Sec-Ch-Ua": "",  # Firefox does not send sec-ch-ua
        "Sec-Ch-Ua-Platform": "",
        "Sec-Ch-Ua-Mobile": "",
    },
    {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
        "Sec-Ch-Ua": "",  # Safari does not send sec-ch-ua
        "Sec-Ch-Ua-Platform": "",
        "Sec-Ch-Ua-Mobile": "",
    },
    {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Sec-Ch-Ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "Sec-Ch-Ua-Platform": '"Linux"',
        "Sec-Ch-Ua-Mobile": "?0",
    },
    {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
        "Sec-Ch-Ua": '"Microsoft Edge";v="129", "Chromium";v="129", "Not_A Brand";v="24"',
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Ch-Ua-Mobile": "?0",
    },
]

# ── Accept-Language variants ────────────────────────────────────────────────
_ACCEPT_LANGS: list[str] = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,vi;q=0.8",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,de;q=0.8,fr;q=0.7",
    "en,en-US;q=0.9",
    "en-US,en;q=0.9,ja;q=0.8",
    "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
]

# ── Decoy headers — benign headers real browsers send sporadically ──────────
_DECOY_HEADERS: list[tuple[str, str]] = [
    ("DNT", "1"),
    ("X-Requested-With", "XMLHttpRequest"),
    ("Cache-Control", "no-cache"),
    ("Cache-Control", "max-age=0"),
    ("Pragma", "no-cache"),
    ("Priority", "u=0, i"),
    ("Priority", "u=1"),
]

# ── Sec-Fetch variation (context-dependent values real Chrome rotates) ──────
_SEC_FETCH_SITE: list[str] = ["none", "same-origin", "same-site", "cross-site"]
_SEC_FETCH_MODE: list[str] = ["navigate", "cors", "no-cors", "same-origin"]
_SEC_FETCH_DEST: list[str] = ["document", "empty", "script", "style", "image"]

# ── Per-host session state ──────────────────────────────────────────────────
# Tracks which fingerprint index a host is on (rotates every N requests).

_ROTATION_INTERVAL = 15  # rotate fingerprint every ~15 requests per host
_host_state: dict[str, dict] = {}

# ── Profile configuration ───────────────────────────────────────────────────
# off:      no evasion (default)
# light:    fingerprint rotation + accept-language variation only
# moderate: + header shuffling + decoy injection + sec-fetch variation
# full:     + referer injection + cache-control randomization

_PROFILES = {"off", "light", "moderate", "full"}

_current_profile = (
    os.environ.get("PRAETOR_EVASION", "light") or "light"
).strip().lower()
if _current_profile not in _PROFILES:
    _current_profile = "light"


def get_profile() -> str:
    return _current_profile


def set_profile(name: str) -> str:
    global _current_profile
    name = (name or "off").strip().lower()
    if name not in _PROFILES:
        raise ValueError(
            f"unknown evasion profile '{name}'. "
            f"Valid: {', '.join(sorted(_PROFILES))}"
        )
    _current_profile = name
    return name


def stats() -> dict:
    return {
        "profile": _current_profile,
        "hosts": {h: s.get("count", 0) for h, s in _host_state.items()},
        "rotation_interval": _ROTATION_INTERVAL,
    }


def _host_from_url(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except (ValueError, TypeError):
        return ""


def _get_host_state(host: str) -> dict:
    if host not in _host_state:
        _host_state[host] = {
            "fp_idx": random.randint(0, len(_FINGERPRINTS) - 1),
            "count": 0,
            "rng": random.Random(time.monotonic_ns()),
        }
    return _host_state[host]


def _pick_fingerprint(state: dict) -> dict[str, str]:
    """Pick the current fingerprint, rotate every _ROTATION_INTERVAL requests."""
    state["count"] += 1
    if state["count"] % _ROTATION_INTERVAL == 0:
        state["fp_idx"] = (state["fp_idx"] + 1) % len(_FINGERPRINTS)
    return _FINGERPRINTS[state["fp_idx"]]


def _shuffle_headers(headers: dict, rng: random.Random) -> dict:
    """Randomize header key order. HTTP/1.1 order is not significant but
    bot-detection fingerprints it."""
    items = list(headers.items())
    rng.shuffle(items)
    return dict(items)


def _inject_decoys(headers: dict, rng: random.Random) -> dict:
    """With ~30% probability, add one benign decoy header."""
    if rng.random() < 0.30:
        key, val = rng.choice(_DECOY_HEADERS)
        lc_keys = {k.lower() for k in headers}
        if key.lower() not in lc_keys:
            headers[key] = val
    return headers


def _vary_accept_language(
    headers: dict, rng: random.Random, protected: set[str] | None = None,
) -> dict:
    if protected and "accept-language" in protected:
        return headers
    lc_keys = {k.lower(): k for k in headers}
    if "accept-language" in lc_keys:
        real_key = lc_keys["accept-language"]
        headers[real_key] = rng.choice(_ACCEPT_LANGS)
    return headers


def _vary_sec_fetch(
    headers: dict, rng: random.Random, protected: set[str] | None = None,
) -> dict:
    """Rotate Sec-Fetch-* values to match varied navigation contexts."""
    _p = protected or set()
    lc_map = {k.lower(): k for k in headers}
    if "sec-fetch-site" in lc_map and "sec-fetch-site" not in _p and rng.random() < 0.4:
        headers[lc_map["sec-fetch-site"]] = rng.choice(_SEC_FETCH_SITE)
    if "sec-fetch-mode" in lc_map and "sec-fetch-mode" not in _p and rng.random() < 0.3:
        headers[lc_map["sec-fetch-mode"]] = rng.choice(_SEC_FETCH_MODE)
    if "sec-fetch-dest" in lc_map and "sec-fetch-dest" not in _p and rng.random() < 0.3:
        headers[lc_map["sec-fetch-dest"]] = rng.choice(_SEC_FETCH_DEST)
    return headers


def _inject_referer(
    headers: dict, url: str, rng: random.Random, protected: set[str] | None = None,
) -> dict:
    """With ~40% probability, add a plausible same-origin Referer."""
    if protected and "referer" in protected:
        return headers
    lc_keys = {k.lower() for k in headers}
    if "referer" in lc_keys:
        return headers
    if rng.random() < 0.40:
        try:
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}/"
            headers["Referer"] = origin
        except (ValueError, TypeError):
            pass
    return headers


def _vary_cache_control(
    headers: dict, rng: random.Random, protected: set[str] | None = None,
) -> dict:
    """With ~20% probability, add a cache directive like a real browser reload."""
    _p = protected or set()
    if "cache-control" in _p or "pragma" in _p:
        return headers
    lc_keys = {k.lower() for k in headers}
    if "cache-control" in lc_keys or "pragma" in lc_keys:
        return headers
    r = rng.random()
    if r < 0.10:
        headers["Cache-Control"] = "no-cache"
        headers["Pragma"] = "no-cache"
    elif r < 0.20:
        headers["Cache-Control"] = "max-age=0"
    return headers


# ── Public API ──────────────────────────────────────────────────────────────

def apply_evasion(
    headers: dict,
    url: str,
    caller_keys: set[str] | None = None,
) -> dict:
    """Apply evasion transformations to a header dict.

    Called by apply_realistic_headers() after the merge, before returning.
    Returns a new dict. No-op when profile is 'off'.

    caller_keys: lowercased header names the operator explicitly set.
    Evasion never overrides these — caller-supplied headers always win.
    """
    profile = _current_profile
    if profile == "off":
        return headers

    protected = caller_keys or set()
    host = _host_from_url(url)
    state = _get_host_state(host)
    rng = state["rng"]

    result = dict(headers)

    # ── light: fingerprint rotation + accept-language variation ──────────
    fp = _pick_fingerprint(state)
    existing_lc = {k.lower() for k in result}
    for k, v in fp.items():
        k_lc = k.lower()
        if k_lc in protected:
            continue
        if v and k_lc not in existing_lc:
            result[k] = v
        elif v and k_lc in existing_lc:
            for rk in list(result):
                if rk.lower() == k_lc:
                    result[rk] = v
                    break
        elif not v:
            for rk in list(result):
                if rk.lower() == k_lc:
                    del result[rk]
                    break

    result = _vary_accept_language(result, rng, protected)

    if profile == "light":
        return result

    # ── moderate: + header shuffling + decoys + sec-fetch variation ──────
    result = _inject_decoys(result, rng)
    result = _vary_sec_fetch(result, rng, protected)
    result = _shuffle_headers(result, rng)

    if profile == "moderate":
        return result

    # ── full: + referer + cache-control ─────────────────────────────────
    result = _inject_referer(result, url, rng, protected)
    result = _vary_cache_control(result, rng, protected)
    result = _shuffle_headers(result, rng)

    return result
