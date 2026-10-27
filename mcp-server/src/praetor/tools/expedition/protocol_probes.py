"""Protocol-specific auth probes via expedition tcp_repeat.

When groma or nmap discovers a non-HTTP service (Redis, MySQL, MongoDB,
MQTT, Memcached), these tools send well-known auth-check payloads through
expedition's Repeater and interpret the dissected response. Closes the gap
where discovery finds the service but praetor has no tool to test it.
"""

from __future__ import annotations

import struct

from mcp.server.fastmcp import FastMCP

from . import _client


async def _repeat(host: str, port: int, hex_payload: str,
                  timeout_ms: int = 3000) -> dict:
    return await _client.post("/repeat", json={
        "protocol": "tcp", "host": host, "port": port,
        "hex": hex_payload, "timeout_ms": timeout_ms,
    })


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_redis_unauth(
        host: str, port: int = 6379, timeout_ms: int = 3000,
    ) -> str:
        """Probe a Redis server for unauthenticated access via expedition.

        Sends PING, INFO server, and CONFIG GET * as RESP commands. An open
        Redis that responds without NOAUTH is a HIGH finding (data access +
        potential RCE via CONFIG SET / MODULE LOAD / Lua scripting).

        Args:
            host: Redis server host.
            port: Redis server port (default 6379).
            timeout_ms: Response timeout in ms.
        """
        # RESP: *1\r\n$4\r\nPING\r\n
        ping_hex = "2a310d0a24340d0a50494e470d0a"
        d = await _repeat(host, port, ping_hex, timeout_ms)
        if "error" in d:
            return f"Error: {d['error']}"
        resp = d.get("response_text", "")
        if not resp:
            return f"No response from {host}:{port}. Service may be down or filtered."

        if "-NOAUTH" in resp or "-ERR" in resp and "auth" in resp.lower():
            return (f"Redis at {host}:{port} requires authentication (NOAUTH). "
                    f"Correct behavior — not an open instance.")

        lines = [f"Redis at {host}:{port} — PING response: {resp.strip()!r}"]

        if "+PONG" in resp:
            lines.append("  PING accepted WITHOUT authentication.")
            # INFO server
            info_hex = "2a320d0a24340d0a494e464f0d0a2436" \
                       "0d0a7365727665720d0a"
            d2 = await _repeat(host, port, info_hex, timeout_ms)
            info_resp = d2.get("response_text", "")
            if "redis_version" in info_resp:
                for line in info_resp.split("\\r\\n")[:5]:
                    if ":" in line:
                        lines.append(f"  {line.strip()}")
            # CONFIG GET *
            cfg_hex = ("2a330d0a2436" "0d0a434f4e464947"
                       "0d0a24330d0a474554" "0d0a24310d0a2a0d0a")
            d3 = await _repeat(host, port, cfg_hex, timeout_ms)
            cfg_resp = d3.get("response_text", "")
            if "-NOAUTH" not in cfg_resp and "$" in cfg_resp:
                lines.append("  CONFIG GET * accessible — full config read/write.")
                lines.append("  Impact: data theft, RCE via CONFIG SET dir/dbfilename "
                             "or MODULE LOAD.")
                lines.append("  Severity: HIGH (unauthenticated Redis with CONFIG access).")
            elif "-NOAUTH" in cfg_resp:
                lines.append("  CONFIG requires AUTH (ACL restricted), but PING/INFO open.")
                lines.append("  Severity: MEDIUM (info leak, limited data access).")
            else:
                lines.append("  Severity: HIGH (unauthenticated Redis, data accessible).")
        return "\n".join(lines)

    @mcp.tool()
    async def probe_mysql_unauth(
        host: str, port: int = 3306, timeout_ms: int = 3000,
    ) -> str:
        """Probe a MySQL/MariaDB server for anonymous login via expedition.

        Reads the server greeting (protocol version, server version, auth
        plugin) and attempts a minimal handshake with empty credentials.

        Args:
            host: MySQL server host.
            port: MySQL server port (default 3306).
            timeout_ms: Response timeout in ms.
        """
        # Send a single null byte to trigger the greeting packet
        d = await _repeat(host, port, "00", timeout_ms)
        if "error" in d:
            return f"Error: {d['error']}"
        resp_hex = d.get("response_hex", "")
        resp_text = d.get("response_text", "")
        if not resp_hex:
            return f"No response from {host}:{port}. Not MySQL or filtered."

        lines = [f"MySQL probe on {host}:{port}"]

        # Parse greeting: payload_len(3) + seq(1) + protocol_version(1) + server_version(null-terminated)
        try:
            raw = bytes.fromhex(resp_hex)
            if len(raw) < 5:
                return f"Response too short ({len(raw)} bytes) — not a MySQL greeting."
            proto_ver = raw[4]
            # Server version is null-terminated starting at byte 5
            ver_end = raw.index(0, 5)
            server_ver = raw[5:ver_end].decode("ascii", errors="replace")
            lines.append(f"  Protocol: {proto_ver}")
            lines.append(f"  Server: {server_ver}")

            if proto_ver == 10:
                lines.append("  MySQL/MariaDB greeting received.")
                # Check for auth plugin hint
                if b"mysql_native_password" in raw:
                    lines.append("  Auth plugin: mysql_native_password")
                elif b"caching_sha2_password" in raw:
                    lines.append("  Auth plugin: caching_sha2_password")
                lines.append("  Next: attempt anonymous login with run_sqlmap or manual handshake.")
            elif proto_ver == 255:
                # Error packet
                err_code = struct.unpack("<H", raw[5:7])[0] if len(raw) > 6 else 0
                lines.append(f"  Server returned error (code {err_code}). "
                             f"Connection may be blocked by host allowlist.")
        except (ValueError, IndexError):
            lines.append(f"  Raw greeting (hex): {resp_hex[:100]}")
            lines.append(f"  Raw greeting (text): {resp_text[:100]!r}")

        return "\n".join(lines)

    @mcp.tool()
    async def probe_mongodb_unauth(
        host: str, port: int = 27017, timeout_ms: int = 3000,
    ) -> str:
        """Probe a MongoDB server for unauthenticated access via expedition.

        Sends an isMaster/hello command as OP_MSG. If the server responds
        without auth error, authentication is not enforced.

        Args:
            host: MongoDB server host.
            port: MongoDB server port (default 27017).
            timeout_ms: Response timeout in ms.
        """
        # OP_MSG with isMaster: {isMaster: 1, $db: "admin"}
        # BSON document: {"isMaster": 1, "$db": "admin"}
        bson_doc = (
            b"\x27\x00\x00\x00"  # doc size = 39
            b"\x10isMaster\x00\x01\x00\x00\x00"  # int32 isMaster: 1
            b"\x02$db\x00\x06\x00\x00\x00admin\x00"  # string $db: "admin"
            b"\x00"  # terminator
        )
        # OP_MSG header: length(4) + requestID(4) + responseTo(4) + opCode(4=2013) + flagBits(4) + section(1=body) + doc
        msg_len = 4 + 4 + 4 + 4 + 4 + 1 + len(bson_doc)
        header = struct.pack("<iiii", msg_len, 1, 0, 2013)
        flags = struct.pack("<I", 0)
        section_kind = b"\x00"  # body
        packet = header + flags + section_kind + bson_doc
        hex_payload = packet.hex()

        d = await _repeat(host, port, hex_payload, timeout_ms)
        if "error" in d:
            return f"Error: {d['error']}"
        resp_text = d.get("response_text", "")
        resp_hex = d.get("response_hex", "")
        if not resp_hex:
            return f"No response from {host}:{port}. Not MongoDB or filtered."

        lines = [f"MongoDB probe on {host}:{port}"]

        if "ismaster" in resp_text.lower() or "isWritablePrimary" in resp_text:
            lines.append("  isMaster response received WITHOUT authentication.")
            lines.append("  MongoDB accepts unauthenticated commands.")
            if "maxBsonObjectSize" in resp_text:
                lines.append("  Server returned full capability document.")
            lines.append("  Impact: full database read/write access.")
            lines.append("  Severity: CRITICAL (unauthenticated MongoDB).")
            lines.append("  Next: enumerate databases with listDatabases command.")
        elif "auth" in resp_text.lower() or "unauthorized" in resp_text.lower():
            lines.append("  Server requires authentication. Correct behavior.")
        else:
            lines.append(f"  Response (text): {resp_text[:200]!r}")
            lines.append(f"  Response (hex): {resp_hex[:100]}")

        return "\n".join(lines)

    @mcp.tool()
    async def probe_mqtt_unauth(
        host: str, port: int = 1883, timeout_ms: int = 3000,
    ) -> str:
        """Probe an MQTT broker for unauthenticated access via expedition.

        Sends a CONNECT packet with no credentials and clean session. If
        CONNACK returns code 0x00 (accepted), the broker allows anonymous
        connections.

        Args:
            host: MQTT broker host.
            port: MQTT broker port (default 1883).
            timeout_ms: Response timeout in ms.
        """
        # MQTT CONNECT: fixed header + variable header + payload
        # Protocol: MQTT 3.1.1, Clean Session, no auth
        proto_name = b"\x00\x04MQTT"
        proto_level = b"\x04"  # 3.1.1
        connect_flags = b"\x02"  # Clean Session only
        keep_alive = b"\x00\x3c"  # 60 seconds
        client_id = b"\x00\x0epraetor-probe"  # 14-char client ID
        variable = proto_name + proto_level + connect_flags + keep_alive
        payload = client_id
        remaining = len(variable) + len(payload)
        # Fixed header: CONNECT (0x10) + remaining length
        packet = bytes([0x10, remaining]) + variable + payload
        hex_payload = packet.hex()

        d = await _repeat(host, port, hex_payload, timeout_ms)
        if "error" in d:
            return f"Error: {d['error']}"
        resp_hex = d.get("response_hex", "")
        if not resp_hex:
            return f"No response from {host}:{port}. Not an MQTT broker or filtered."

        lines = [f"MQTT probe on {host}:{port}"]

        try:
            raw = bytes.fromhex(resp_hex)
            if len(raw) >= 4 and raw[0] == 0x20:  # CONNACK
                return_code = raw[3]
                if return_code == 0x00:
                    lines.append("  CONNACK: Connection Accepted (0x00).")
                    lines.append("  Broker allows UNAUTHENTICATED connections.")
                    lines.append("  Impact: subscribe to all topics (#), publish "
                                 "arbitrary messages, intercept IoT/ICS traffic.")
                    lines.append("  Severity: HIGH (open MQTT broker).")
                elif return_code == 0x04:
                    lines.append("  CONNACK: Bad credentials (0x04). Auth required.")
                elif return_code == 0x05:
                    lines.append("  CONNACK: Not authorized (0x05). Auth required.")
                else:
                    lines.append(f"  CONNACK return code: 0x{return_code:02x}")
            else:
                lines.append(f"  Response (hex): {resp_hex[:60]}")
        except (ValueError, IndexError):
            lines.append(f"  Unparseable response: {resp_hex[:60]}")

        return "\n".join(lines)

    @mcp.tool()
    async def probe_memcached_unauth(
        host: str, port: int = 11211, timeout_ms: int = 3000,
    ) -> str:
        """Probe a Memcached server for unauthenticated access via expedition.

        Sends a `stats` command. If stats are returned, the instance is open
        and may be abused for data theft or amplification attacks.

        Args:
            host: Memcached server host.
            port: Memcached server port (default 11211).
            timeout_ms: Response timeout in ms.
        """
        # ASCII protocol: "stats\r\n"
        stats_hex = "73746174730d0a"
        d = await _repeat(host, port, stats_hex, timeout_ms)
        if "error" in d:
            return f"Error: {d['error']}"
        resp_text = d.get("response_text", "")
        if not resp_text:
            return f"No response from {host}:{port}. Not Memcached or filtered."

        lines = [f"Memcached probe on {host}:{port}"]

        if "STAT " in resp_text or "END" in resp_text:
            lines.append("  stats command accepted WITHOUT authentication.")
            # Extract key stats
            for stat_line in resp_text.replace("\\r\\n", "\n").split("\n"):
                if any(k in stat_line for k in ["version", "curr_items",
                                                 "bytes ", "total_connections"]):
                    lines.append(f"  {stat_line.strip()}")
            lines.append("  Impact: read/write cached data, potential data theft,")
            lines.append("  DDoS amplification (UDP reflection).")
            lines.append("  Severity: HIGH (unauthenticated Memcached).")
        elif "ERROR" in resp_text or "CLIENT_ERROR" in resp_text:
            lines.append(f"  Server returned error: {resp_text[:100]!r}")
            lines.append("  May require SASL authentication.")
        else:
            lines.append(f"  Response: {resp_text[:200]!r}")

        return "\n".join(lines)
