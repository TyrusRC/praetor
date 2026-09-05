"""gRPC frame + reflection helpers (extracted from grpc_probe.py)"""

from __future__ import annotations

import base64
import re
import struct
from typing import Any

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools.testing._verdict import error_verdict, make_verdict


# Reflection request — ListServices:
# message ServerReflectionRequest { string host=1; oneof message_request {
#   string list_services=3; ... } }
# Encoded: tag(0x1a, field 3 wire 2) + length(0) + empty string

_LIST_SERVICES_PROTOBUF = b"\x1a\x00"  # field 3 (list_services) = ""


def _gframe(body: bytes) -> bytes:
    """Wrap protobuf body in gRPC length-prefix framing.

    Format: [1 byte compression flag][4 byte big-endian length][body]
    """
    return b"\x00" + struct.pack(">I", len(body)) + body


def _gunframe(blob: bytes) -> list[bytes]:
    """Unwrap one or more gRPC frames from a response body."""
    frames = []
    off = 0
    while off + 5 <= len(blob):
        # byte[off] is the gRPC compression flag — not needed to unframe.
        length = struct.unpack(">I", blob[off + 1:off + 5])[0]
        if off + 5 + length > len(blob):
            break
        frames.append(blob[off + 5:off + 5 + length])
        off += 5 + length
    return frames


# Heuristic service-name extraction from a ServerReflectionResponse protobuf.
# Service names are FQNs like "grpc.health.v1.Health" — match anything that
# looks like a dotted package.Service path.
_SERVICE_RE = re.compile(rb"([a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*){1,8})")


def _extract_services(frames: list[bytes]) -> list[str]:
    found = set()
    for f in frames:
        for m in _SERVICE_RE.finditer(f):
            name = m.group(1).decode("ascii", errors="replace")
            # Filter: must have at least one dot, must look package-shaped
            if "." in name and not name.endswith(".") and len(name) >= 5:
                # Filter out HTTP header tokens that the regex might catch
                if any(name.lower().startswith(p) for p in (
                    "content.", "grpc-status", "x.grpc", "grpc.reflection")):
                    continue
                found.add(name)
    return sorted(found)


async def _send_grpc(url: str, body: bytes, headers: dict[str, str] | None = None,
                     timeout: int = 20) -> dict[str, Any]:
    """POST raw gRPC frame via Burp HTTP client.

    grpc-web compatibility: if base URL is HTTPS, send Content-Type
    application/grpc; transport handles H2 ALPN.
    """
    hdrs = {
        "Content-Type": "application/grpc",
        "TE": "trailers",
        "grpc-accept-encoding": "identity",
    }
    if headers:
        hdrs.update(headers)
    payload: dict[str, Any] = {
        "method": "POST",
        "url": url,
        "headers": hdrs,
        "body_b64": base64.b64encode(body).decode("ascii"),
        "follow_redirects": False,
        "timeout": timeout,
    }
    return await client.post("/api/http/curl", json=payload)


# IDOR-mutation heuristics — common gRPC numeric id field-tag patterns
# (varint encoding). Field 1 type 0 = tag 0x08 (request_id usually).
# Mutation: flip the varint to 1 or to N+1.
def _mutate_first_varint(frame: bytes) -> bytes | None:
    """Find first varint after a tag byte; bump it by 1.

    gRPC field tag for field N type 0 (varint) = (N << 3) | 0 = 0x08 (field 1)
    The varint value follows. Bump that value by 1 (cheap IDOR mutation).
    """
    if len(frame) < 2:
        return None
    # We're looking at the inner protobuf payload (already unframed)
    for i, b in enumerate(frame):
        # Tag byte for varint field, fields 1-5
        if b in (0x08, 0x10, 0x18, 0x20, 0x28):
            # Next byte is varint LSB
            if i + 1 < len(frame):
                old = frame[i + 1]
                if old < 0x7F:  # Simple single-byte varint
                    new = bytes(frame[: i + 1]) + bytes([old + 1]) + frame[i + 2:]
                    return new
    return None
