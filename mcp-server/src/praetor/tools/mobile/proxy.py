"""mobile_proxy_status — verify a device actually routes through Burp so app
traffic isn't silently lost. Config-status now; active canary in canary=True."""
from __future__ import annotations
import asyncio
import secrets
import subprocess

from mcp.server.fastmcp import FastMCP
from praetor import client
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


def host_tailscale_ip() -> str:
    """Host's tailnet IP (stable across DHCP renewals), via `ip -4 addr show
    tailscale0`. "" if no tailscale0 interface / not connected."""
    out = _run_text(["ip", "-4", "addr", "show", "tailscale0"])
    for ln in out.splitlines():
        ln = ln.strip()
        if ln.startswith("inet "):
            return ln.split()[1].split("/")[0]
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


async def _poll_history_for(token: str, seconds: float = 6.0) -> int | None:
    """Poll Burp proxy history for a request whose URL contains token; return its
    index, or None if it never lands within the window."""
    deadline = asyncio.get_running_loop().time() + seconds
    while True:
        data = await client.post("/api/search/history", json={"query": token, "in_url": True, "limit": 20})
        if "error" not in data:
            for r in data.get("results", []):
                if token in str(r.get("url", "")):
                    return r["index"]
        if asyncio.get_running_loop().time() >= deadline:
            return None
        await asyncio.sleep(1.0)


async def _run_canary(dev, domain) -> dict:
    """Fire one request FROM the device through its configured proxy and confirm
    it lands in Burp proxy history — proves packets actually flow, not just that
    the config looks right."""
    token = "praetor-canary-" + secrets.token_hex(4)
    # Not OOB exfil (Rule 9a) -- this request terminates at Burp itself; we only
    # check it lands in proxy history, nothing is exfiltrated to a remote host.
    # example.com is IANA-reserved (RFC 2606) purely as a syntactically-valid,
    # unroutable host, so Collaborator isn't required here.
    url = f"http://{token}.example.com/{token}"
    try:
        await backend_for(dev).open_url(dev, url)
    except DeviceError as e:
        return {"canary_landed": False, "logger_index": None, "canary_url": url,
                "warnings_extra": [f"could not fire canary: {e}"]}
    idx = await _poll_history_for(token)
    return {"canary_landed": idx is not None, "logger_index": idx, "canary_url": url}


CA_NOTE = "HTTPS capture also requires the Burp CA installed & trusted on the device"
DRIFT_REMEDIATION = "run mobile_set_proxy(mode='reverse' for USB, else 'tailscale'/'lan')"
DRIFT_NOTE = f"device proxy points at a stale IP (DHCP drift) — {DRIFT_REMEDIATION}"


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
        # A device proxy is valid wireless routing if its host part is ANY current
        # host IP, not just the LAN one — mode='tailscale' points at the tailnet IP,
        # which would otherwise always trip the LAN-IP mismatch/drift check below.
        host_ips = {ip for ip in (lan, host_tailscale_ip()) if ip}
        expected = f"{lan}:{BURP_PROXY_PORT}" if lan else f"<host-lan-ip>:{BURP_PROXY_PORT}"
        scope = burp_listener_scope()
        # adb-reverse routing: device 127.0.0.1:<port> tunnels to host 127.0.0.1:<port> —
        # a valid, DHCP-immune config, not a LAN-IP mismatch and not a loopback-listener problem.
        is_loopback_proxy = device_proxy in (f"127.0.0.1:{BURP_PROXY_PORT}", f"localhost:{BURP_PROXY_PORT}")
        device_proxy_ip = device_proxy.split(":")[0] if device_proxy else ""
        proxy_note = ""
        if not device_proxy:
            warnings.append("device http_proxy is not set — app traffic will NOT reach Burp")
        elif is_loopback_proxy:
            proxy_note = "device via adb reverse — loopback Burp is correct"
        elif device_proxy_ip in host_ips:
            proxy_note = "device proxy points at a current host IP (LAN or tailscale)"
        elif host_ips:
            warnings.append(DRIFT_NOTE)
        if not scope["listening"]:
            warnings.append(f"no Burp proxy listener on port {BURP_PROXY_PORT}")
        elif scope["loopback_only"] and not is_loopback_proxy:
            warnings.append("Burp proxy bound to loopback only — a LAN/USB device cannot reach it; add an all-interfaces (0.0.0.0) proxy listener")
        routing_ok = not warnings
        result = {"device": dev.id, "platform": dev.platform, "device_proxy": device_proxy,
                  "expected_proxy": expected, "burp_listener": scope, "routing_ok": routing_ok,
                  "canary_landed": None, "logger_index": None, "warnings": warnings,
                  "ca_note": CA_NOTE, "proxy_note": proxy_note}
        if canary:
            canary_result = await _run_canary(dev, domain)
            warnings.extend(canary_result.pop("warnings_extra", []))
            if canary_result.get("canary_landed") is False:
                warnings.append("canary request did NOT reach Burp — device traffic is being "
                                 "lost (check proxy + CA + all-interfaces listener); "
                                 f"if DHCP has changed the host IP, {DRIFT_REMEDIATION}")
            routing_ok = routing_ok and bool(canary_result.get("canary_landed"))
            result.update(canary_result)
            result["routing_ok"] = routing_ok
        result["oplog_id"] = log_action(domain, dev.id, "proxy_status", description="device->burp routing check",
                                        output=("ok" if routing_ok else "; ".join(warnings)))
        return result

    @mcp.tool()
    async def mobile_set_proxy(device: str = "", mode: str = "reverse", domain: str = "") -> dict:
        """Point the device at Burp in a DHCP-robust way. mode: 'reverse' (Android/USB,
        adb reverse + 127.0.0.1 — immune to IP changes; recommended), 'lan' (current host
        LAN IP), 'tailscale' (stable tailnet IP), 'off' (clear). iOS is unsupported (set the
        Wi-Fi proxy to a stable host address manually / via a .mobileconfig profile)."""
        try:
            dev = await resolve_device(device)
        except DeviceError as e:
            return {"error": str(e)}
        if dev.platform != "android":
            return {"error": "mobile_set_proxy supports Android only; for iOS set the Wi-Fi proxy "
                            "to a stable host address (Tailscale / DHCP reservation) or a .mobileconfig profile"}
        b = backend_for(dev); port = BURP_PROXY_PORT
        try:
            if mode == "reverse":
                await b.reverse_port(dev, port); value = f"127.0.0.1:{port}"; await b.set_proxy(dev, value)
            elif mode == "lan":
                ip = host_lan_ip()
                if not ip: return {"error": "could not determine host LAN IP"}
                value = f"{ip}:{port}"; await b.set_proxy(dev, value)
            elif mode == "tailscale":
                ip = host_tailscale_ip()
                if not ip: return {"error": "no tailscale0 address on host"}
                value = f"{ip}:{port}"; await b.set_proxy(dev, value)
            elif mode == "off":
                await b.clear_proxy(dev); value = ""
            else:
                return {"error": f"unknown mode {mode!r} (reverse|lan|tailscale|off)"}
        except DeviceError as e:
            return {"error": str(e)}
        oid = log_action(domain, dev.id, f"set_proxy {mode} {value}", description="device proxy config")
        return {"applied": mode, "device_proxy": value, "oplog_id": oid, "device": dev.id,
                "note": "run mobile_proxy_status(canary=True) to confirm traffic reaches Burp"}
