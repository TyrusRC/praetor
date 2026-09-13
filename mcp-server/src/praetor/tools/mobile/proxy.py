"""mobile_proxy_status — verify a device actually routes through Burp so app
traffic isn't silently lost. Config-status now; active canary in canary=True."""
from __future__ import annotations
import subprocess

from mcp.server.fastmcp import FastMCP
from praetor.config import BURP_PROXY_PORT
from ._device import DeviceError, backend_for, resolve_device
from ._store import log_action


def _run_text(cmd: list[str], timeout: int = 6) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def host_lan_ip() -> str:
    """Host's primary LAN IP (the address a device on the same network reaches
    it at), via `ip route get 1.1.1.1`. "" if it can't be determined."""
    out = _run_text(["ip", "route", "get", "1.1.1.1"])
    parts = out.split()
    if "src" in parts:
        i = parts.index("src")
        return parts[i + 1] if i + 1 < len(parts) else ""
    return ""


def burp_listener_scope() -> dict:
    """Whether Burp's proxy port has a listener, and if so whether it's bound
    to loopback only (unreachable from a LAN/USB device)."""
    out = _run_text(["ss", "-tlnH"]) or _run_text(["ss", "-tln"])
    port = str(BURP_PROXY_PORT)
    addrs = [ln.split()[3] for ln in out.splitlines()
             if len(ln.split()) >= 4 and ln.split()[3].endswith(":" + port)]
    listening = bool(addrs)
    loopback_only = listening and all(a.startswith("127.") or a.startswith("[::1]") for a in addrs)
    return {"listening": listening, "loopback_only": loopback_only, "addrs": addrs}


async def _run_canary(dev, domain):
    """Inert stub — active canary (fire one request from device, confirm it
    lands in Burp proxy history) is implemented in Task 3."""
    return {}


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def mobile_proxy_status(device: str = "", domain: str = "", canary: bool = False) -> dict:
        """Check whether the device routes through Burp (prevents lost packets).
        Config check always; set canary=True to also fire one request FROM the
        device and confirm it lands in Burp proxy history. Call after
        mobile_frida_run, before driving UI."""
        try:
            dev = await resolve_device(device)
        except DeviceError as e:
            return {"error": str(e)}
        warnings: list[str] = []
        device_proxy = ""
        try:
            device_proxy = await backend_for(dev).get_proxy(dev)
        except DeviceError as e:
            warnings.append(f"could not read device proxy: {e}")
        lan = host_lan_ip()
        expected = f"{lan}:{BURP_PROXY_PORT}" if lan else f"<host-lan-ip>:{BURP_PROXY_PORT}"
        scope = burp_listener_scope()
        if not device_proxy:
            warnings.append("device http_proxy is not set — app traffic will NOT reach Burp")
        elif lan and device_proxy != expected:
            warnings.append(f"device proxy {device_proxy!r} != expected {expected!r} (host LAN IP:Burp port)")
        if not scope["listening"]:
            warnings.append(f"no Burp proxy listener on port {BURP_PROXY_PORT}")
        elif scope["loopback_only"]:
            warnings.append("Burp proxy bound to loopback only — a LAN/USB device cannot reach it; add an all-interfaces (0.0.0.0) proxy listener")
        routing_ok = not warnings
        result = {"device": dev.id, "platform": dev.platform, "device_proxy": device_proxy,
                  "expected_proxy": expected, "burp_listener": scope, "routing_ok": routing_ok,
                  "canary_landed": None, "logger_index": None, "warnings": warnings}
        if canary:
            result.update(await _run_canary(dev, domain))  # Task 3
        result["oplog_id"] = log_action(domain, dev.id, "proxy_status", description="device->burp routing check",
                                        output=("ok" if routing_ok else "; ".join(warnings)))
        return result
