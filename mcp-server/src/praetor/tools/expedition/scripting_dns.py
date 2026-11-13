"""MCP tools for two burp-expedition capabilities with no prior wrapper:
the JSR-223 message-transform scripting hook (`/script`) and the DNS
redirector / spoofing resolver (`/dns`).

Closes a gap found reviewing the current burp-expedition Control API
(README "Control API" table): both endpoints existed in the extension with
no corresponding tcp_* tool, so the agent had no way to drive them short of
a raw curl against the loopback API.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import _client


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def tcp_script_status() -> str:
        """Show whether an expedition transform script is installed and healthy.

        Reports script-engine availability, whether a script is installed,
        and the last compile/runtime error (if any).
        """
        d = await _client.get("/script")
        if "error" in d:
            return f"Error: {d['error']}"
        if not d.get("available"):
            return "Scripting engine not available in this burp-expedition build."
        lines = [f"Script installed: {d.get('installed', False)}"]
        if d.get("source"):
            lines.append(f"  source ({len(d['source'])} chars): {d['source'][:200]}")
        if d.get("last_error"):
            lines.append(f"  last_error: {d['last_error']}")
        return "\n".join(lines)

    @mcp.tool()
    async def tcp_script_set(source: str) -> str:
        """Install a JSR-223 transform script on every captured TCP/UDP message.

        Args:
            source: script source (JavaScript via Nashorn/GraalVM, or another
                JSR-223 engine the extension ships). Runs against every
                captured message — use it for protocol-specific decode/
                re-encode logic a static match-replace rule can't express
                (checksum recompute, length-field fixups after an edit, a
                custom encoding). A compile error is returned as an Error
                here (the extension refuses to install it), not silently
                swallowed.

        Call tcp_script_status after installing to confirm no runtime error
        appeared on the first message it processed.
        """
        if not source.strip():
            return "Error: source required."
        d = await _client.post("/script", json={"source": source})
        if "error" in d:
            return f"Error: {d['error']}"
        return "Script installed." if d.get("installed") else "Script call returned without confirming install."

    @mcp.tool()
    async def tcp_script_clear() -> str:
        """Remove the installed expedition transform script, if any."""
        d = await _client.delete("/script")
        if "error" in d:
            return f"Error: {d['error']}"
        return "Script cleared." if not d.get("installed") else "Clear call returned but a script is still reported installed."

    @mcp.tool()
    async def tcp_dns_status() -> str:
        """Show the expedition DNS redirector's running state and rules."""
        d = await _client.get("/dns")
        if "error" in d:
            return f"Error: {d['error']}"
        if d.get("error") == "DNS not available":
            return "DNS redirector not available in this burp-expedition build."
        return "\n".join(f"  {k}: {v}" for k, v in d.items()) or "DNS redirector: no status returned."

    @mcp.tool()
    async def tcp_dns_start(
        rules: str = "",
        default_ip: str = "",
        host: str = "127.0.0.1",
        port: int = 53,
        allow_non_loopback: bool = False,
    ) -> str:
        """Start the DNS redirector — a spoofing resolver that pulls traffic
        for chosen hostnames into an expedition listener.

        Args:
            rules: comma list of 'hostname=ip' pairs (e.g.
                'api.target.com=127.0.0.1,db.target.com=127.0.0.1'). Point a
                client's resolver at this server and matching lookups answer
                with the mapped IP instead of the real one — the standard
                way to force a thick-client/mobile-app/IoT device with no
                proxy setting onto a local listener.
            default_ip: answer for any hostname NOT in rules (blank = NXDOMAIN
                passthrough-less; at least one of rules/default_ip is
                required).
            host: bind address (default 127.0.0.1 — loopback-only unless
                allow_non_loopback).
            port: UDP port (default 53 — binding it needs root/CAP_NET_BIND
                on Linux; the extension returns 409 if the bind fails).
            allow_non_loopback: required True to bind off-loopback (exposes
                the resolver to the network — only for a lab/VLAN where the
                operator controls what reaches it).
        """
        parsed = []
        for pair in rules.split(","):
            pair = pair.strip()
            if not pair:
                continue
            if "=" not in pair:
                return f"Error: rule {pair!r} must be 'hostname=ip'."
            h, ip = pair.split("=", 1)
            parsed.append({"host": h.strip(), "ip": ip.strip()})
        if not parsed and not default_ip:
            return "Error: at least one rule or default_ip is required."
        payload: dict = {"host": host, "port": port, "rules": parsed}
        if default_ip:
            payload["default_ip"] = default_ip
        if allow_non_loopback:
            payload["allow_non_loopback"] = True
        d = await _client.post("/dns/start", json=payload)
        if "error" in d:
            return f"Error: {d['error']}"
        return f"DNS redirector up on {d.get('host', host)}:{d.get('port', port)} ({len(parsed)} rule(s))."

    @mcp.tool()
    async def tcp_dns_stop() -> str:
        """Stop the expedition DNS redirector."""
        d = await _client.post("/dns/stop")
        if "error" in d:
            return f"Error: {d['error']}"
        return "DNS redirector stopped."


__all__ = ["register"]
