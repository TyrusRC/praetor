"""probe_id_monotonic — UUIDv1 / ULID / Snowflake time-window enumeration.

Many systems use opaque-but-time-monotonic IDs (UUIDv1 contains the node MAC +
100ns-tick timestamp; ULID is 48-bit ms timestamp + 80 random bits; Snowflake
is 41-bit ms timestamp + worker + sequence). Sequential ID enumeration tools
miss these because the IDs look random, but the time window is predictable.

Given a known ID + a path with the ID interpolated, generate IDs in a ±N-unit
window around the seed and probe.

Strix-derived. Pure black-box.
"""

import re
import time
import uuid as _uuid

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from ._verdict import error_verdict, make_verdict, verdict_from_tally


# ULID alphabet — Crockford base32
_ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_ULID_REVERSE = {c: i for i, c in enumerate(_ULID_ALPHABET)}

_UUIDv1_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$", re.I)
_SNOWFLAKE_RE = re.compile(r"^[0-9]{15,20}$")
# Twitter epoch (2010-11-04) is the default — most apps use a similar epoch
_SNOWFLAKE_EPOCH_MS = 1288834974657


def _detect(id_str: str) -> str:
    if _UUIDv1_RE.match(id_str):
        return "uuidv1"
    if _ULID_RE.match(id_str.upper()):
        return "ulid"
    if _SNOWFLAKE_RE.match(id_str):
        return "snowflake"
    return "unknown"


def _uuidv1_timestamp(id_str: str) -> int:
    """Return 100-ns-tick timestamp embedded in a UUIDv1."""
    u = _uuid.UUID(id_str)
    return u.time  # 100-ns intervals since 1582-10-15


def _uuidv1_from_timestamp(seed_id: str, new_time: int) -> str:
    """Reconstruct a UUIDv1 with the given timestamp; reuse seed node + clock_seq."""
    u = _uuid.UUID(seed_id)
    # bytes layout per RFC 4122: time_low | time_mid | time_hi_version | clock_seq_hi_variant | clock_seq_low | node
    time_low = new_time & 0xFFFFFFFF
    time_mid = (new_time >> 32) & 0xFFFF
    time_hi = ((new_time >> 48) & 0x0FFF) | 0x1000  # version 1
    clock_seq = (u.clock_seq_hi_variant << 8) | u.clock_seq_low
    fields = (time_low, time_mid, time_hi, u.clock_seq_hi_variant, u.clock_seq_low, u.node)
    return str(_uuid.UUID(fields=fields))


def _ulid_decode_ts(ulid_str: str) -> int:
    """Decode the 48-bit timestamp (ms) component of a ULID."""
    s = ulid_str.upper()[:10]  # first 10 chars = timestamp
    n = 0
    for c in s:
        n = n * 32 + _ULID_REVERSE[c]
    return n


def _ulid_encode_ts(timestamp_ms: int) -> str:
    """Encode a ms timestamp to 10-char ULID time prefix."""
    chars = []
    for _ in range(10):
        chars.append(_ULID_ALPHABET[timestamp_ms & 0x1F])
        timestamp_ms >>= 5
    return "".join(reversed(chars))


def _ulid_with_new_ts(seed_ulid: str, new_ts_ms: int) -> str:
    """Replace ULID's time prefix; keep the random tail."""
    return _ulid_encode_ts(new_ts_ms) + seed_ulid.upper()[10:]


def _snowflake_timestamp(snowflake: str, epoch_ms: int = _SNOWFLAKE_EPOCH_MS) -> int:
    return (int(snowflake) >> 22) + epoch_ms


def _snowflake_with_new_ts(seed_snowflake: str, new_ts_ms: int, epoch_ms: int = _SNOWFLAKE_EPOCH_MS) -> str:
    seed = int(seed_snowflake)
    lower = seed & ((1 << 22) - 1)  # worker + sequence bits
    delta_ms = new_ts_ms - epoch_ms
    if delta_ms < 0:
        delta_ms = 0
    return str((delta_ms << 22) | lower)


def register(mcp: FastMCP):

    @mcp.tool()
    async def probe_id_monotonic(
        session: str,
        path_template: str,
        seed_id: str,
        window: int = 50,
        step: int = 1,
        id_type: str = "auto",
        method: str = "GET",
        snowflake_epoch_ms: int = _SNOWFLAKE_EPOCH_MS,
    ) -> dict:
        """Enumerate IDs in a time-window around a known UUIDv1 / ULID / Snowflake.

        Returns VerdictResult (W7 schema).

        Args:
            session: Auth session.
            path_template: Path with literal {ID} placeholder, e.g. /api/orders/{ID}.
            seed_id: A known valid ID to anchor the time window.
            window: Number of IDs to probe on each side of the seed (so 2*window+1 total).
            step: Time-unit step between probes (UUIDv1 = 100ns ticks, ULID = ms, Snowflake = ms).
            id_type: 'auto' | 'uuidv1' | 'ulid' | 'snowflake' (auto detects from seed_id).
            method: HTTP method.
            snowflake_epoch_ms: Custom epoch for Snowflake decoder (default Twitter 2010-11-04).
        """
        if "{ID}" not in path_template:
            return error_verdict("path_template must contain literal {ID}", vuln_type="idor")

        kind = id_type if id_type != "auto" else _detect(seed_id)
        if kind == "unknown":
            return error_verdict(
                f"cannot detect ID type from {seed_id!r}; pass id_type explicitly",
                vuln_type="idor",
            )

        # Generate candidate IDs
        candidates: list[tuple[int, str]] = []  # (time_delta, id)
        if kind == "uuidv1":
            base_t = _uuidv1_timestamp(seed_id)
            for i in range(-window, window + 1):
                if i == 0:
                    continue
                t = base_t + i * step
                if t <= 0:
                    continue
                candidates.append((i, _uuidv1_from_timestamp(seed_id, t)))
        elif kind == "ulid":
            base_t = _ulid_decode_ts(seed_id)
            for i in range(-window, window + 1):
                if i == 0:
                    continue
                t = base_t + i * step
                if t < 0:
                    continue
                candidates.append((i, _ulid_with_new_ts(seed_id, t)))
        elif kind == "snowflake":
            base_t = _snowflake_timestamp(seed_id, snowflake_epoch_ms)
            for i in range(-window, window + 1):
                if i == 0:
                    continue
                t = base_t + i * step
                if t < snowflake_epoch_ms:
                    continue
                candidates.append((i, _snowflake_with_new_ts(seed_id, t, snowflake_epoch_ms)))

        # Baseline: known-valid seed
        seed_path = path_template.replace("{ID}", seed_id)
        baseline = await client.post("/api/session/request", json={
            "session": session, "method": method, "path": seed_path,
        })
        if "error" in baseline:
            return error_verdict(f"seed probe failed: {baseline['error']}", vuln_type="idor")
        b_status = baseline.get("status", 0)
        b_len = len(baseline.get("response_body", ""))

        lines = [
            f"probe_id_monotonic [{kind}] window=±{window} step={step}",
            f"Seed: {seed_id} -> {seed_path} status={b_status} len={b_len}",
            "",
        ]
        if not (200 <= b_status < 300):
            lines.append("WARNING: seed ID itself does not return 2xx. Verify seed_id is currently valid.")
            lines.append("")

        hits = []
        for delta, candidate in candidates:
            cpath = path_template.replace("{ID}", candidate)
            r = await client.post("/api/session/request", json={
                "session": session, "method": method, "path": cpath,
            })
            if "error" in r:
                continue
            s = r.get("status", 0)
            ln = len(r.get("response_body", ""))
            # A hit is: 2xx AND length similar to baseline (so we know it's a real record, not an empty 200)
            if 200 <= s < 300 and (b_len == 0 or abs(ln - b_len) / max(b_len, 1) < 0.5):
                hits.append((delta, candidate, s, ln))

        if hits:
            lines.append(f"HITS: {len(hits)} / {len(candidates)} probed")
            for delta, candidate, s, ln in hits[:50]:
                lines.append(f"  Δ={delta:+d}  {candidate}  status={s} len={ln}")
            if len(hits) > 50:
                lines.append(f"  ... +{len(hits)-50} more hits ...")
            lines.append("\nRisk: monotonic-ID range yields foreign records — IDOR via time-window enumeration. Verify with PII content + cross-tenant data check.")
        else:
            lines.append("No additional valid IDs found in window.")

        human = "\n".join(lines)
        verdict, confidence = verdict_from_tally(len(hits))
        ev = (f"monotonic-ID IDOR: {len(hits)} foreign records reachable in window of {len(candidates)} "
              f"(kind={kind})" if hits else "no IDOR — monotonic-ID window probed clean")

        return make_verdict(
            verdict, confidence, ev,
            vuln_type="idor",
            details={
                "path_template": path_template,
                "id_type": kind,
                "hits": len(hits),
                "window_probed": len(candidates),
            },
            summary=human,
        )
