"""Per-host outbound-request noise governor — paces ALL traffic a session
sends to a target host, not just within one burst tool call.

Gap found reviewing ARTEX (egress/pace.go): Praetor has Rule 6a's bounded
volume per call (concurrent_requests, send_to_intruder_configured) but
nothing that throttles the WHOLE engagement's request rate per host across
every call, which is what actually matters for staying under a WAF/IDS
per-minute threshold across a session.

Token-bucket + jitter per host, four profiles (default `off`, matching
every existing test's expectations — this never changes send timing unless
the operator opts in):
    off        no pacing (default)
    quiet      ~0.5 req/s per host, burst 2   — slow, WAF-safe
    balanced   ~2 req/s per host, burst 5     — default "on" choice
    aggressive ~10 req/s per host, burst 20   — light pacing, fast hunting

Wired into client.post() for the paths that actually dispatch a fresh
request carrying a target `url` (curl/concurrent/raw/send/resend/repeater).
Paths that only read or manage Burp's own state (proxy history, organizer,
findings, annotate, ...) are never paced — there is no target traffic to
throttle.
"""

from __future__ import annotations

import asyncio
import os
import random
import time
from urllib.parse import urlsplit

# profile -> (tokens/second refill rate, bucket capacity, max jitter seconds)
_PROFILES: dict[str, tuple[float, int, float] | None] = {
    "off": None,
    "quiet": (0.5, 2, 0.4),
    "balanced": (2.0, 5, 0.2),
    "aggressive": (10.0, 20, 0.05),
}

_current_profile = (os.environ.get("PRAETOR_NOISE_PROFILE", "off") or "off").strip().lower()
if _current_profile not in _PROFILES:
    _current_profile = "off"

_lock = asyncio.Lock()


class _Bucket:
    """Classic token bucket. `reserve()` always consumes a token (can go
    negative under sustained overrun, same contract as ARTEX's Governor) and
    returns how long the caller must sleep before sending."""

    __slots__ = ("rate", "capacity", "tokens", "last")

    def __init__(self, rate: float, capacity: int) -> None:
        self.rate = rate
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.last = time.monotonic()

    def reserve(self) -> float:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
        self.last = now
        wait = 0.0
        if self.tokens < 1:
            wait = (1 - self.tokens) / self.rate
        self.tokens -= 1
        return max(0.0, wait)


_buckets: dict[str, _Bucket] = {}
_sent: dict[str, int] = {}  # host -> request count under the active profile


def get_profile() -> str:
    return _current_profile


def set_profile(name: str) -> str:
    """Set the active profile. Raises ValueError on an unknown name."""
    global _current_profile
    key = (name or "off").strip().lower()
    if key not in _PROFILES:
        raise ValueError(f"unknown noise profile {name!r}; choose from {sorted(_PROFILES)}")
    _current_profile = key
    return _current_profile


def stats() -> dict:
    """Per-host request counts paced so far under the active profile — for
    an operator to confirm the governor is actually doing something."""
    return {"profile": _current_profile, "hosts": dict(_sent)}


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


async def wait_for_host(host: str) -> float:
    """Pace one request to `host` under the current profile. Returns the
    seconds actually slept (0.0 when off or host is empty) — a caller/test
    can assert on this without needing a wall-clock measurement."""
    if not host or _current_profile == "off":
        return 0.0
    rate, capacity, jitter = _PROFILES[_current_profile]  # type: ignore[misc]
    async with _lock:
        bucket = _buckets.get(host)
        if bucket is None:
            bucket = _buckets[host] = _Bucket(rate, capacity)
        delay = bucket.reserve()
        _sent[host] = _sent.get(host, 0) + 1
    if jitter:
        delay += random.uniform(0, jitter)
    if delay > 0:
        await asyncio.sleep(delay)
    return delay


# Paths that dispatch a FRESH request carrying a target `url` in the JSON
# body. Anything else (proxy history reads, organizer, findings, annotate,
# scope, ...) never touches the target and is never paced.
_PACED_PATH_PREFIXES = (
    "/api/http/curl",
    "/api/http/concurrent",
    "/api/http/raw",
    "/api/http/raw-send",
    "/api/http/send",
    "/api/http/resend",
    "/api/http/repeater",
)


async def maybe_pace(path: str, json_body: dict | None) -> float:
    """Called from client.post() for every outbound call. No-op unless the
    path is a target-dispatching one AND the body carries a `url`."""
    if _current_profile == "off" or not json_body:
        return 0.0
    if not any(path.startswith(p) for p in _PACED_PATH_PREFIXES):
        return 0.0
    host = _host_of(json_body.get("url") or "")
    if not host:
        return 0.0
    return await wait_for_host(host)


def reset_for_test() -> None:
    """Test-only: drop all per-host state so cases don't leak into each
    other. Never called from product code."""
    _buckets.clear()
    _sent.clear()


__all__ = [
    "get_profile", "set_profile", "stats", "wait_for_host", "maybe_pace",
    "reset_for_test",
]
