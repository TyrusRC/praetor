# tools/mobile/connect.py
"""Wireless adb: tcpip/connect/pair/disconnect/list. Wireless adb is the
reliable transport for driving a phone (USB/usbip resets on big transfers).
Every call bypasses Burp (adb, not target HTTP) and records an operator-log
entry."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _run_cmd

from ._device import DeviceError, list_devices, resolve_device
from ._store import log_action

_ACTIONS = ("tcpip", "connect", "pair", "disconnect", "list")


def _is_failure(output: str) -> bool:
    low = output.lower()
    return "failed" in low or "cannot" in low


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def mobile_connect(action: str = "", ip: str = "", port: int = 5555,
                             code: str = "", device: str = "", domain: str = "") -> dict:
        """Wireless adb connection management (Android). Actions:
        - tcpip: switch a USB-connected device into TCP/IP mode on `port`.
          Then reconnect over Wi-Fi with action='connect'.
        - connect: `adb connect <ip>:<port>`. Returns `serial` — pass it as
          `device=` to every other mobile_* tool.
        - pair: `adb pair <ip>:<port> <code>` (Android 11+ wireless
          debugging). `port` here is the pairing port shown on-device, not
          the connect port.
        - disconnect: `adb disconnect [<ip>:<port>]` (all devices if no ip).
        - list: connected Android + iOS devices and their state.
        """
        if action == "tcpip":
            try:
                dev = await resolve_device(device)
            except DeviceError as e:
                return {"error": str(e)}
            out, err, rc = await _run_cmd(["adb", "-s", dev.id, "tcpip", str(port)],
                                          bypass_proxy=True)
            if rc != 0 or _is_failure(out + err):
                return {"error": (out + err).strip() or "adb tcpip failed"}
            oid = log_action(domain, dev.id, f"tcpip {port}", description="wireless adb tcpip",
                             output=out.strip())
            return {"action": "tcpip", "port": port,
                    "note": "now call action='connect' with the phone's Wi-Fi ip",
                    "oplog_id": oid}

        if action == "connect":
            if not ip:
                return {"error": "connect requires ip=<phone Wi-Fi ip>"}
            serial = f"{ip}:{port}"
            out, err, rc = await _run_cmd(["adb", "connect", serial], bypass_proxy=True)
            combined = out + err
            if rc != 0 or _is_failure(combined) or not (
                    "connected" in combined.lower() or "already connected" in combined.lower()):
                return {"error": combined.strip() or "adb connect failed"}
            oid = log_action(domain, serial, "connect", description="wireless adb connect",
                             output=out.strip())
            return {"action": "connect", "serial": serial, "output": out.strip(),
                    "oplog_id": oid}

        if action == "pair":
            if not ip or not code:
                return {"error": "pair requires ip=<phone ip> and code=<pairing code>"}
            target = f"{ip}:{port}"
            out, err, rc = await _run_cmd(["adb", "pair", target, code], bypass_proxy=True)
            combined = out + err
            if rc != 0 or _is_failure(combined):
                return {"error": combined.strip() or "adb pair failed"}
            oid = log_action(domain, target, "pair", description="wireless adb pair",
                             output=out.strip())
            return {"action": "pair", "output": out.strip(), "oplog_id": oid}

        if action == "disconnect":
            cmd = ["adb", "disconnect"]
            target = f"{ip}:{port}" if ip else ""
            if target:
                cmd.append(target)
            out, err, rc = await _run_cmd(cmd, bypass_proxy=True)
            oid = log_action(domain, target or "all", "disconnect",
                             description="wireless adb disconnect", output=out.strip())
            return {"action": "disconnect", "output": out.strip(), "oplog_id": oid}

        if action == "list":
            devs = await list_devices()
            return {"count": len(devs),
                    "devices": [{"id": d.id, "platform": d.platform,
                                 "authorized": d.authorized} for d in devs]}

        return {"error": f"unknown action {action!r} ({'|'.join(_ACTIONS)})"}
