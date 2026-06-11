"""probe_grpc_reflection + probe_grpc_idor (W29-b).

gRPC active probing — the KB (`grpc_injection.json`) existed since W3 but no
active probe consumed it. Strix and Tenable WAS cover gRPC; Praetor didn't.

Two tools:

  - **probe_grpc_reflection(base_url)** — enumerate services + methods via
    the gRPC Server Reflection Protocol (grpc.reflection.v1alpha.ServerReflection).
    Sends a ListServices request as a length-prefixed gRPC frame over the
    HTTP/2 channel (Burp tunnel handles H2). Parses the response into a
    service/method inventory.

  - **probe_grpc_idor(method_url, replay_payload)** — given a captured gRPC
    request body (length-prefixed frame), replay it after mutating a numeric
    identifier (request_id / user_id / account_id heuristically). Standard
    IDOR pattern at the gRPC layer.

Notes:
  - Praetor uses Burp's HTTP-client transport which handles H2 ALPN.
    Manual gRPC frame format: 1 byte compression flag (0) + 4 byte big-endian
    length + protobuf bytes. Reflection responses come back the same way.
  - We don't ship a protobuf parser — for ListServices the response contains
    the service names as length-prefixed strings inside the protobuf message,
    which we extract heuristically. Full protobuf parsing is deferred to v2.
  - Status mapping: HTTP/2 status 200 + `grpc-status: 0` trailer = success.
    `grpc-status: 12` (UNIMPLEMENTED) = no reflection. `grpc-status: 7`
    (PERMISSION_DENIED) is the same idor signal as HTTP 403.
"""

from __future__ import annotations

import base64
import re
import struct
from typing import Any
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import error_verdict, make_verdict


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
        flag = blob[off]
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


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_grpc_reflection(  # cost: low (1-3 requests)
        base_url: str,
        reflection_method: str = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
        timeout: int = 20,
    ) -> dict:
        """Enumerate gRPC services + methods via the Server Reflection protocol.

        Sends a ListServices ServerReflectionRequest to the standard
        reflection endpoint. Vulnerable services expose their full RPC
        surface (auth-internal methods, debug RPCs, admin methods).

        Returns VerdictResult:
          - CONFIRMED — reflection enabled, services enumerated
          - SUSPECTED — server responds gRPC but reflection denied (12 UNIMPLEMENTED)
          - FAILED — non-gRPC response / no H2 / not reachable

        Args:
            base_url: gRPC server root (https://api.example.com)
            reflection_method: override if vendor uses non-standard path
            timeout: per-request timeout (s)
        """
        scope = await client.check_scope(base_url)
        if not scope.get("in_scope"):
            return error_verdict("grpc_reflection", "out_of_scope",
                                 f"{base_url} not in scope")

        url = base_url.rstrip("/") + reflection_method
        body = _gframe(_LIST_SERVICES_PROTOBUF)
        resp = await _send_grpc(url, body, timeout=timeout)
        if resp.get("error"):
            return error_verdict("grpc_reflection", "transport_error",
                                 resp.get("error", "send failed"))

        status = resp.get("status_code", 0)
        logger_indices = [resp["logger_index"]] if "logger_index" in resp else []

        # Try to read response body as bytes
        raw = resp.get("response_body_b64") or resp.get("response_body") or ""
        if resp.get("response_body_b64"):
            try:
                blob = base64.b64decode(raw)
            except Exception:
                blob = raw.encode("latin-1", errors="replace") if isinstance(raw, str) else b""
        else:
            blob = raw.encode("latin-1", errors="replace") if isinstance(raw, str) else b""

        # grpc-status trailer — Burp may surface in headers or body trailer
        hdrs = {k.lower(): v for k, v in (resp.get("response_headers") or {}).items()}
        grpc_status = hdrs.get("grpc-status") or hdrs.get("trailer-grpc-status") or ""

        frames = _gunframe(blob)
        services = _extract_services(frames)

        if services:
            return make_verdict(
                vuln_type="grpc_reflection",
                verdict="CONFIRMED",
                confidence=0.95,
                evidence_summary=f"gRPC reflection enabled — {len(services)} services enumerated",
                logger_indices=logger_indices,
                details={
                    "base_url": base_url,
                    "services": services,
                    "grpc_status": grpc_status,
                    "http_status": status,
                },
                human_summary=f"gRPC reflection enabled: {len(services)} services ({services[0] if services else ''}…)",
            )
        if grpc_status == "12":
            return make_verdict(
                vuln_type="grpc_reflection",
                verdict="SUSPECTED",
                confidence=0.4,
                evidence_summary="gRPC server reachable but reflection unimplemented",
                logger_indices=logger_indices,
                details={"base_url": base_url, "grpc_status": "12 UNIMPLEMENTED",
                         "http_status": status},
                human_summary="gRPC reachable; reflection disabled",
            )
        return make_verdict(
            vuln_type="grpc_reflection",
            verdict="FAILED",
            confidence=0.7,
            evidence_summary=f"No gRPC reflection response (http={status}, grpc-status={grpc_status})",
            logger_indices=logger_indices,
            details={"base_url": base_url, "http_status": status,
                     "grpc_status": grpc_status,
                     "frames_seen": len(frames)},
            human_summary="No gRPC reflection",
        )

    @mcp.tool()
    async def probe_grpc_idor(  # cost: low (3 requests)
        method_url: str,
        request_body_b64: str,
        timeout: int = 20,
        custom_mutations_b64: list[str] | None = None,
    ) -> dict:
        """IDOR-class probe at the gRPC layer — mutate first varint in body.

        Operator captures a legitimate gRPC request via Burp (the request_body
        is the base64-encoded request body, ALREADY length-prefixed gRPC
        frame). We strip the frame, mutate the first varint field by +1
        (heuristic for request_id / user_id / account_id), re-frame, replay.

        Compares response shape vs baseline:
          - 200 + same shape on mutation = vuln (data for another principal)
          - 200 + tombstone-like (zero fields) = ambiguous SUSPECTED
          - grpc-status 7 (PERMISSION_DENIED) or 5 (NOT_FOUND) = correctly enforced

        Args:
            method_url: full URL including /<service>/<Method>
            request_body_b64: base64 of the captured gRPC frame
            timeout: per-request timeout (s)
            custom_mutations_b64: additional pre-built mutation payloads
        """
        scope = await client.check_scope(method_url)
        if not scope.get("in_scope"):
            return error_verdict("grpc_idor", "out_of_scope",
                                 f"{method_url} not in scope")

        try:
            baseline_frame = base64.b64decode(request_body_b64)
        except Exception as e:
            return error_verdict("grpc_idor", "bad_payload", f"base64 decode: {e}")

        # Unframe baseline to get inner protobuf
        frames = _gunframe(baseline_frame)
        if not frames:
            return error_verdict("grpc_idor", "bad_payload",
                                 "no valid gRPC frame in request_body")
        inner = frames[0]
        mutated = _mutate_first_varint(inner)
        if not mutated and not custom_mutations_b64:
            return error_verdict("grpc_idor", "no_mutation",
                                 "no varint field 1-5 found and no custom_mutations provided")

        # Baseline
        baseline = await _send_grpc(method_url, baseline_frame, timeout=timeout)
        if baseline.get("error"):
            return error_verdict("grpc_idor", "baseline_failed",
                                 baseline.get("error", "baseline send failed"))
        b_status = baseline.get("status_code", 0)
        b_body = baseline.get("response_body") or ""
        b_len = len(b_body) if isinstance(b_body, str) else 0
        b_hdrs = {k.lower(): v for k, v in (baseline.get("response_headers") or {}).items()}
        b_grpc = b_hdrs.get("grpc-status", "0")

        logger_indices = []
        if "logger_index" in baseline:
            logger_indices.append(baseline["logger_index"])

        mutation_results = []
        candidates: list[bytes] = []
        if mutated:
            candidates.append(_gframe(mutated))
        for c in (custom_mutations_b64 or []):
            try:
                candidates.append(base64.b64decode(c))
            except Exception:
                continue

        for i, cand in enumerate(candidates):
            resp = await _send_grpc(method_url, cand, timeout=timeout)
            if resp.get("error"):
                continue
            if "logger_index" in resp:
                logger_indices.append(resp["logger_index"])
            m_status = resp.get("status_code", 0)
            m_body = resp.get("response_body") or ""
            m_len = len(m_body) if isinstance(m_body, str) else 0
            m_hdrs = {k.lower(): v for k, v in (resp.get("response_headers") or {}).items()}
            m_grpc = m_hdrs.get("grpc-status", "0")
            mutation_results.append({
                "mutation_index": i,
                "http_status": m_status,
                "grpc_status": m_grpc,
                "response_length": m_len,
                "len_delta": m_len - b_len,
            })

        # Verdict: any mutation that succeeded (grpc-status 0) with non-empty
        # body and length within ±25% of baseline = IDOR hit.
        hits = [r for r in mutation_results
                if r["grpc_status"] == "0" and r["response_length"] > 0
                and abs(r["len_delta"]) <= max(50, int(0.25 * b_len))]
        if hits:
            return make_verdict(
                vuln_type="grpc_idor",
                verdict="CONFIRMED",
                confidence=0.85,
                evidence_summary=f"{len(hits)}/{len(mutation_results)} mutations returned grpc-status 0 with similar response shape",
                logger_indices=logger_indices,
                details={
                    "method_url": method_url,
                    "baseline_grpc_status": b_grpc,
                    "baseline_length": b_len,
                    "mutations": mutation_results,
                },
                human_summary=f"gRPC IDOR: {len(hits)} mutations succeeded with similar response shape",
            )
        # Mixed signals — at least one 0 status but shape different
        suspect = [r for r in mutation_results if r["grpc_status"] == "0"]
        if suspect:
            return make_verdict(
                vuln_type="grpc_idor",
                verdict="SUSPECTED",
                confidence=0.55,
                evidence_summary=f"{len(suspect)} mutations succeeded but response shape diverged",
                logger_indices=logger_indices,
                details={"mutations": mutation_results, "baseline_length": b_len},
                human_summary=f"gRPC IDOR suspect: status 0 returned with different shape",
            )
        return make_verdict(
            vuln_type="grpc_idor",
            verdict="FAILED",
            confidence=0.9,
            evidence_summary=f"All {len(mutation_results)} mutations rejected (grpc-status non-zero)",
            logger_indices=logger_indices,
            details={"mutations": mutation_results, "baseline_grpc_status": b_grpc},
            human_summary="gRPC method correctly authorised — no IDOR",
        )
