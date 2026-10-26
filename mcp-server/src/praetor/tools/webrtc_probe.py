"""WebRTC security probes — TURN relay abuse and ICE candidate IP leak.

The signaling channel (HTTP/WebSocket) is already covered by Burp. These
tools test the STUN/TURN infrastructure and SDP metadata that sit outside
the HTTP path.

probe_turn_relay: test for open TURN relay (unauthenticated Allocate).
probe_webrtc_ip_leak: parse SDP for internal IPs in ICE candidates.
"""

from __future__ import annotations

import re
import struct

from mcp.server.fastmcp import FastMCP


# STUN magic cookie (RFC 5389)
_MAGIC = 0x2112A442

# STUN message types
_ALLOCATE_REQUEST = 0x0003  # TURN Allocate
_BINDING_REQUEST = 0x0001   # STUN Binding


def _build_stun_request(msg_type: int, transaction_id: bytes = b"",
                        attributes: bytes = b"") -> bytes:
    """Build a STUN message (RFC 5389 §6)."""
    import os
    if not transaction_id:
        transaction_id = os.urandom(12)
    header = struct.pack("!HHI", msg_type, len(attributes), _MAGIC) + transaction_id
    return header + attributes


def _parse_stun_response(data: bytes) -> dict:
    """Parse a STUN response into a dict of type, attrs."""
    if len(data) < 20:
        return {"error": "too short for STUN"}
    msg_type, msg_len, magic = struct.unpack("!HHI", data[:8])
    txn_id = data[8:20]
    attrs = {}
    offset = 20
    while offset + 4 <= len(data) and offset < 20 + msg_len:
        attr_type, attr_len = struct.unpack("!HH", data[offset:offset + 4])
        attr_val = data[offset + 4:offset + 4 + attr_len]
        attrs[attr_type] = attr_val
        offset += 4 + attr_len + (4 - attr_len % 4) % 4  # padding
    # Decode XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
    mapped = None
    for atype in (0x0020, 0x0001):
        if atype in attrs and len(attrs[atype]) >= 8:
            family = attrs[atype][1]
            if atype == 0x0020:  # XOR
                port = struct.unpack("!H", attrs[atype][2:4])[0] ^ (_MAGIC >> 16)
                ip_bytes = bytes(b ^ m for b, m in zip(
                    attrs[atype][4:8], struct.pack("!I", _MAGIC)))
            else:
                port = struct.unpack("!H", attrs[atype][2:4])[0]
                ip_bytes = attrs[atype][4:8]
            ip = ".".join(str(b) for b in ip_bytes)
            mapped = {"ip": ip, "port": port, "family": "IPv4" if family == 1 else "IPv6"}
            break
    is_success = (msg_type & 0x0110) == 0x0100
    is_error = (msg_type & 0x0110) == 0x0110
    # ERROR-CODE (0x0009)
    error_code = None
    if 0x0009 in attrs and len(attrs[0x0009]) >= 4:
        error_code = attrs[0x0009][2] * 100 + attrs[0x0009][3]
    return {
        "type": msg_type, "success": is_success, "error": is_error,
        "mapped_address": mapped, "error_code": error_code,
        "raw_attrs": {hex(k): v.hex() for k, v in attrs.items()},
    }


# Private IP patterns in ICE candidates
_PRIVATE_IP = re.compile(
    r"\b("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r"|fc[0-9a-f]{2}:[0-9a-f:]*"
    r"|fd[0-9a-f]{2}:[0-9a-f:]*"
    r")\b", re.IGNORECASE
)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_turn_relay(
        host: str,
        port: int = 3478,
        protocol: str = "udp",
        timeout_ms: int = 3000,
    ) -> str:
        """Test a TURN server for open relay (unauthenticated Allocate).

        An open TURN relay lets any client allocate a relay address and tunnel
        traffic through it — a network-boundary bypass. Sends an Allocate
        request without credentials and checks the response.

        Success response = open relay (finding). Error 401 = auth required
        (correct behavior). No response = not a TURN server or filtered.

        Args:
            host: TURN server host.
            port: TURN server port (default 3478).
            protocol: udp (default) or tcp.
            timeout_ms: Response timeout in ms.
        """
        from praetor.tools.expedition import _client
        allocate = _build_stun_request(_ALLOCATE_REQUEST)
        d = await _client.post("/repeat", json={
            "protocol": protocol, "host": host, "port": port,
            "hex": allocate.hex(), "timeout_ms": timeout_ms,
        })
        if "error" in d:
            return f"Error: {d['error']}"
        resp_hex = d.get("response_hex", "")
        if not resp_hex:
            return (f"No response from {host}:{port}/{protocol}. "
                    f"Not a TURN server or UDP filtered.")
        resp = bytes.fromhex(resp_hex)
        parsed = _parse_stun_response(resp)
        if parsed.get("success"):
            mapped = parsed.get("mapped_address", {})
            return (
                f"OPEN TURN RELAY on {host}:{port}\n"
                f"  Allocate succeeded without credentials.\n"
                f"  Relay address: {mapped.get('ip', '?')}:{mapped.get('port', '?')}\n"
                f"  Impact: any client can tunnel traffic through this server.\n"
                f"  Severity: HIGH (network boundary bypass)."
            )
        elif parsed.get("error_code") == 401:
            return (f"TURN server at {host}:{port} requires authentication (401). "
                    f"Correct behavior — not an open relay.")
        elif parsed.get("error_code"):
            return (f"TURN server at {host}:{port} returned error {parsed['error_code']}. "
                    f"Not an open relay but server is responsive.")
        else:
            return f"STUN response from {host}:{port} but not a clear Allocate response: {parsed}"

    @mcp.tool()
    async def probe_stun_binding(
        host: str,
        port: int = 3478,
        protocol: str = "udp",
        timeout_ms: int = 3000,
    ) -> str:
        """Send a STUN Binding request to discover the server's reflexive address.

        Useful for recon: confirms a STUN server is alive and reveals the
        client's public IP as seen by the server (NAT traversal info).

        Args:
            host: STUN server host.
            port: STUN server port (default 3478).
            protocol: udp (default) or tcp.
            timeout_ms: Response timeout in ms.
        """
        from praetor.tools.expedition import _client
        binding = _build_stun_request(_BINDING_REQUEST)
        d = await _client.post("/repeat", json={
            "protocol": protocol, "host": host, "port": port,
            "hex": binding.hex(), "timeout_ms": timeout_ms,
        })
        if "error" in d:
            return f"Error: {d['error']}"
        resp_hex = d.get("response_hex", "")
        if not resp_hex:
            return f"No response from {host}:{port}. Not a STUN server or filtered."
        resp = bytes.fromhex(resp_hex)
        parsed = _parse_stun_response(resp)
        if parsed.get("success") and parsed.get("mapped_address"):
            m = parsed["mapped_address"]
            return (f"STUN Binding success from {host}:{port}\n"
                    f"  Reflexive address: {m['ip']}:{m['port']} ({m['family']})")
        return f"STUN response but no mapped address: {parsed}"

    @mcp.tool()
    async def probe_webrtc_ip_leak(
        sdp: str,
    ) -> str:
        """Parse an SDP offer/answer for internal IP addresses in ICE candidates.

        WebRTC ICE candidates can leak private/internal IPs (10.x, 172.16-31.x,
        192.168.x, link-local, ULA IPv6). Extract the SDP from the signaling
        channel (WebSocket/HTTP — already in Burp proxy history) and pass it here.

        Args:
            sdp: Raw SDP text (from signaling channel capture).
        """
        if not sdp or not sdp.strip():
            return "Error: empty SDP."
        candidates = re.findall(r"a=candidate:.*", sdp)
        if not candidates:
            return "No ICE candidates found in SDP."
        leaks = []
        all_ips = []
        for line in candidates:
            ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)
            all_ips.extend(ips)
            for ip in ips:
                if _PRIVATE_IP.match(ip):
                    leaks.append({"ip": ip, "candidate": line.strip()})
        lines = [f"ICE candidates: {len(candidates)}, IPs found: {len(all_ips)}"]
        if leaks:
            lines.append(f"\nInternal IP leak: {len(leaks)} private address(es):\n")
            seen = set()
            for l in leaks:
                if l["ip"] not in seen:
                    lines.append(f"  {l['ip']}  — {l['candidate'][:100]}")
                    seen.add(l["ip"])
            lines.append(
                "\nImpact: exposes internal network topology. "
                "Useful for SSRF targeting and lateral movement planning."
            )
        else:
            lines.append("No private IPs found in ICE candidates.")
        return "\n".join(lines)
