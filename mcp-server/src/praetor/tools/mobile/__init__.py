"""Mobile lane: active device control (adb/idb/Frida) + passive payload corpus.

Device-control commands bypass Burp (like the network lane) and cite an
operator-log id; unlocked app traffic still flows device-wifi-proxy -> Burp and
cites a proxy_history_index. HARD safety Rules 5-9 and the device allowlist apply.
"""

from mcp.server.fastmcp import FastMCP

from . import connect, control, frida, payloads, proxy


def register(mcp: FastMCP) -> None:
    payloads.register(mcp)
    control.register(mcp)
    connect.register(mcp)
    frida.register(mcp)
    proxy.register(mcp)


__all__ = ["register"]
