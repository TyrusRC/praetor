"""single-packet race + H3-detect helpers (extracted from race_singlepacket.py)"""


import asyncio
import re
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools._request_headers import apply_realistic_headers
from praetor.tools.testing import _h2_lowlevel
from praetor.tools.testing._verdict import error_verdict, make_verdict

# Alt-Svc h3 advertisement: `h3=":443"; ma=86400` or draft `h3-29="..."`.

_ALT_SVC_H3_RE = re.compile(r'h3(?:-\d+)?\s*=\s*"([^"]+)"')


async def _singlepacket_exchange(
    host: str, port: int, requests: list[dict], read_timeout: float = 15.0
) -> tuple[dict[int, dict], bytes, list[int], int]:
    """Open a Burp h2 tunnel, coalesce N stream frames into one TCP packet, flush, read.

    Shared transport for probe_race_singlepacket and probe_race_http3_datagram.
    Returns (results, buf, stream_ids, flush_ns). Raises on tunnel/exchange failure.
    """
    ssock, conn = await asyncio.to_thread(_h2_lowlevel.open_h2_tunnel, host, port)
    try:
        buf, stream_ids = await asyncio.to_thread(
            _h2_lowlevel.build_streams_buffer, conn, host, requests
        )
        flush_ns = await asyncio.to_thread(_h2_lowlevel.send_singlepacket, ssock, buf)
        results = await asyncio.to_thread(
            _h2_lowlevel.read_until_complete, ssock, conn, stream_ids, read_timeout
        )
    finally:
        try:
            conn.close_connection()
            ssock.sendall(conn.data_to_send())
        except Exception:
            pass
        try:
            ssock.close()
        except Exception:
            pass
    return results, buf, stream_ids, flush_ns


def _tally_race(
    stream_ids: list[int], results: dict[int, dict]
) -> tuple[dict[int, int], int, list[int], list[str]]:
    """Tally per-stream outcomes. Returns (statuses, success_count, time_samples, lines)."""
    statuses: dict[int, int] = {}
    success_count = 0
    time_samples: list[int] = []
    lines: list[str] = []
    for sid in stream_ids:
        r = results.get(sid, {})
        s = r.get("status", 0)
        statuses[s] = statuses.get(s, 0) + 1
        if 200 <= s < 300:
            success_count += 1
        tns = r.get("time_ns", -1)
        if tns >= 0:
            time_samples.append(tns)
        preview = r.get("body_preview", "")[:60].replace("\n", " ")
        time_str = f"{tns/1_000_000:.2f}ms" if tns >= 0 else "TIMEOUT"
        lines.append(f"  stream={sid}: status={s} len={r.get('length', 0)} t={time_str} preview={preview!r}")
    return statuses, success_count, time_samples, lines


async def _detect_h3_advertised(url: str) -> list[str]:
    """Return h3 host:port targets from the origin's Alt-Svc header (fetched via Burp)."""
    try:
        resp = await client.post("/api/http/curl", json={
            "method": "GET", "url": url,
            "headers": apply_realistic_headers(url, {}),
            "follow_redirects": False,
        })
    except Exception:
        return []
    if not isinstance(resp, dict) or "error" in resp:
        return []
    targets: list[str] = []
    for h in resp.get("response_headers", []) or []:
        name = h.get("name", "") if isinstance(h, dict) else ""
        if name.lower() != "alt-svc":
            continue
        val = h.get("value", "") if isinstance(h, dict) else ""
        for m in _ALT_SVC_H3_RE.finditer(val):
            targets.append(m.group(1).strip())
    return targets
