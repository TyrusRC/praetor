"""MCP tools for burp-expedition — the TCP/UDP proxy lane.

burp-expedition (a separate Burp extension) adds the non-HTTP proxy Burp lacks:
explicit-proxy TCP/UDP relays with TLS MITM, intercept, match-and-replace, and a
connection/message history. These tools drive its loopback control API (:8112)
so the agent can stand up a relay, read captured non-HTTP traffic as evidence,
replay/fuzz a raw message (the Repeater), and manage match-replace rules — for
targets Burp's HTTP proxy can't see (Redis, MySQL/PG, MongoDB, MQTT, gRPC, DNS,
game/IoT protocols, …).
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import _client


def _fmt_conns(rows: list) -> str:
    if not rows:
        return "No connections captured yet."
    out = [f"{len(rows)} connection(s):"]
    for c in rows[:60]:
        state = "closed" if c.get("closed_at") else "open"
        out.append(f"  #{c.get('id')} [{c.get('protocol')}] {c.get('client')} -> "
                   f"{c.get('upstream')} via {c.get('listener')} ({state})")
    return "\n".join(out)


def _fmt_msgs(rows: list) -> str:
    if not rows:
        return "No messages."
    out = [f"{len(rows)} message(s):"]
    for m in rows[:80]:
        arrow = "C->U" if m.get("direction") == "CLIENT_TO_UPSTREAM" else "U->C"
        out.append(f"  msg#{m.get('id')} conn#{m.get('connection_id')} {arrow} "
                   f"{m.get('length')}B  {str(m.get('text',''))[:80]!r}")
    return "\n".join(out)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def tcp_proxy_status() -> str:
        """Status of the burp-expedition TCP/UDP proxy (running listeners + counts).

        Confirms the extension is loaded and its control API is reachable before
        you drive it. Returns running listeners and connection/message totals.
        """
        d = await _client.get("/status")
        if "error" in d:
            return d["error"]
        return (f"expedition v{d.get('version')}: "
                f"{len(d.get('running_listeners', []))} listener(s) "
                f"{d.get('running_listeners')}, {d.get('connections')} connections, "
                f"{d.get('messages')} messages.")

    @mcp.tool()
    async def tcp_proxy_add_listener(
        name: str,
        upstream_host: str,
        upstream_port: int,
        bind_port: int,
        protocol: str = "tcp",
        bind_host: str = "127.0.0.1",
        tls: str = "none",
    ) -> str:
        """Start an explicit-proxy TCP/UDP listener (bind -> upstream) in Expedition.

        Point a client at bind_host:bind_port and it relays to
        upstream_host:upstream_port while capturing every message. Use for
        non-HTTP protocols Burp can't proxy (Redis 6379, MySQL 3306, PostgreSQL
        5432, MongoDB 27017, MQTT 1883, DNS 53, gRPC, …).

        Args:
            name: Unique listener name.
            upstream_host: Real service host to relay to.
            upstream_port: Real service port.
            bind_port: Local port the client connects to.
            protocol: tcp (default) or udp.
            bind_host: Local bind address (default 127.0.0.1).
            tls: 'mitm' to terminate client TLS with a Burp-CA leaf cert, else 'none'.
        """
        d = await _client.post("/listeners", json={
            "name": name, "protocol": protocol, "bind_host": bind_host,
            "bind_port": bind_port, "upstream_host": upstream_host,
            "upstream_port": upstream_port, "tls": tls,
        })
        if "error" in d:
            return f"Error: {d['error']}"
        return (f"Listener '{name}' [{protocol.upper()}] up on {bind_host}:{bind_port} "
                f"-> {upstream_host}:{upstream_port}"
                f"{' (TLS MITM)' if tls.lower() == 'mitm' else ''}.")

    @mcp.tool()
    async def tcp_proxy_listeners() -> str:
        """List the running Expedition listeners."""
        d = await _client.get("/listeners")
        if "error" in d:
            return d["error"]
        names = d.get("running", [])
        return "Running listeners: " + (", ".join(names) if names else "(none)")

    @mcp.tool()
    async def tcp_proxy_stop_listener(name: str) -> str:
        """Stop an Expedition listener by name."""
        d = await _client.delete(f"/listeners/{name}")
        return f"Stopped '{name}'." if d.get("ok") else f"Error: {d.get('error', d)}"

    @mcp.tool()
    async def tcp_proxy_connections() -> str:
        """List captured proxy connections (evidence source for non-HTTP findings)."""
        rows = await _client.get_list("/connections")
        if isinstance(rows, dict):
            return rows.get("error", str(rows))
        return _fmt_conns(rows)

    @mcp.tool()
    async def tcp_proxy_messages(connection_id: int = 0, limit: int = 200) -> str:
        """Read captured messages — for one connection, or the most recent overall.

        Each message carries direction, length, a hex dump and an ASCII preview —
        the raw non-HTTP evidence to cite in a finding.

        Args:
            connection_id: Restrict to one connection (0 = all recent).
            limit: Max messages when connection_id=0 (default 200).
        """
        path = (f"/connections/{connection_id}/messages" if connection_id
                else f"/messages?limit={limit}")
        rows = await _client.get_list(path)
        if isinstance(rows, dict):
            return rows.get("error", str(rows))
        return _fmt_msgs(rows)

    @mcp.tool()
    async def tcp_repeat(
        host: str,
        port: int,
        protocol: str = "tcp",
        hex: str = "",
        text: str = "",
        timeout_ms: int = 2000,
    ) -> str:
        """Repeater — send a raw TCP/UDP payload to a target and read the response.

        The non-HTTP equivalent of send_raw_request: craft or replay a captured
        message (edit it first), fire it, and inspect the reply. Ideal for
        confirming a protocol-level bug (e.g. a Redis command, a MySQL packet, an
        MQTT publish) benignly. Supply the payload as `hex` (from a captured
        message's hex) OR `text`.

        Args:
            host: Target host.
            port: Target port.
            protocol: tcp (default) or udp.
            hex: Payload as hex (e.g. from tcp_proxy_messages); wins over text.
            text: Payload as a text/latin-1 string.
            timeout_ms: Read timeout in ms (default 2000).
        """
        if not hex and not text:
            return "Error: supply a payload via hex= or text=."
        d = await _client.post("/repeat", json={
            "protocol": protocol, "host": host, "port": port,
            "hex": hex, "text": text, "timeout_ms": timeout_ms,
        })
        if "error" in d:
            return f"Error: {d['error']}"
        return (f"Sent {d.get('sent_len')}B, received {d.get('response_len')}B.\n"
                f"  response (text): {str(d.get('response_text',''))[:300]!r}\n"
                f"  response (hex):  {str(d.get('response_hex',''))[:200]}")

    @mcp.tool()
    async def tcp_match_replace_add(
        match: str, replace: str, match_type: str = "LITERAL_STRING",
    ) -> str:
        """Add an Expedition match-and-replace rule (rewrites relayed traffic).

        Args:
            match: The value to match.
            replace: The replacement.
            match_type: LITERAL_STRING (default), REGEX, or LITERAL_BYTES (hex).
        """
        d = await _client.post("/matchreplace", json={
            "match_type": match_type, "match": match, "replace": replace, "enabled": True,
        })
        return f"Rule #{d.get('id')} added." if d.get("ok") else f"Error: {d.get('error', d)}"

    @mcp.tool()
    async def tcp_match_replace_list() -> str:
        """List Expedition match-and-replace rules."""
        rows = await _client.get_list("/matchreplace")
        if isinstance(rows, dict):
            return rows.get("error", str(rows))
        if not rows:
            return "No match-replace rules."
        return "\n".join(f"  #{r['id']} [{r['match_type']}] {r['match']!r} -> "
                         f"{r['replace']!r} ({'on' if r['enabled'] else 'off'})" for r in rows)

    @mcp.tool()
    async def tcp_match_replace_remove(rule_id: int) -> str:
        """Remove an Expedition match-and-replace rule by id."""
        d = await _client.delete(f"/matchreplace/{rule_id}")
        return f"Removed rule #{rule_id}." if d.get("ok") else f"Error: {d.get('error', d)}"
