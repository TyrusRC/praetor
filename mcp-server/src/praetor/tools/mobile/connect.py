# tools/mobile/connect.py
"""Wireless adb: tcpip/connect/pair/disconnect/list. Wireless adb is the
reliable transport for driving a phone (USB/usbip resets on big transfers).
Every call bypasses Burp (adb, not target HTTP) and records an operator-log
entry."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _run_cmd

from ._device import DeviceError, backend_for, list_devices, resolve_device
from ._store import log_action

_ACTIONS = ("tcpip", "connect", "pair", "disconnect", "list", "auto")


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
        - auto: DHCP-proof wireless bootstrap (Android only). Derives the
          phone's current Wi-Fi IP over the USB channel (no manual `ip=`
          needed), then does tcpip + connect in one call. No-op if already on
          wireless adb. Errors on iOS (no IP-based transport — usbmuxd) or no
          device.
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
            return {"action": "tcpip", "port": port, "output": out.strip(),
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

        if action == "auto":
            devs = await list_devices()
            wireless_android = [d for d in devs if d.platform == "android" and ":" in d.id]
            usb_android = [d for d in devs if d.platform == "android" and ":" not in d.id]

            already = next((d for d in wireless_android if d.authorized), None)
            if already:
                oid = log_action(domain, already.id, "auto",
                                 description="already on wireless adb")
                return {"action": "auto", "serial": already.id,
                        "note": "already on wireless adb", "oplog_id": oid}

            if usb_android:
                dev = next((d for d in usb_android if d.id == device), usb_android[0]) \
                    if device else usb_android[0]
                ip = await backend_for(dev).wifi_ip(dev)
                if not ip:
                    return {"error": f"device {dev.id} is not on Wi‑Fi (no wlan0 IP) "
                                     "— connect it to Wi-Fi first"}
                out, err, rc = await _run_cmd(["adb", "-s", dev.id, "tcpip", str(port)],
                                              bypass_proxy=True)
                if rc != 0 or _is_failure(out + err):
                    return {"error": (out + err).strip() or "adb tcpip failed"}
                serial = f"{ip}:{port}"
                combined = ""
                for _attempt in range(2):
                    out, err, rc = await _run_cmd(["adb", "connect", serial], bypass_proxy=True)
                    combined = out + err
                    if rc == 0 and not _is_failure(combined) and (
                            "connected" in combined.lower()
                            or "already connected" in combined.lower()):
                        break
                else:
                    return {"error": combined.strip() or "adb connect failed"}
                oid = log_action(domain, serial, "auto",
                                 description="bootstrapped wireless adb from USB",
                                 output=out.strip())
                return {"action": "auto", "serial": serial, "ip": ip,
                        "note": "bootstrapped wireless adb from USB", "oplog_id": oid}

            if devs:
                return {"error": "auto is Android-only (wireless adb). iOS uses usbmuxd "
                                 "(no IP needed); for iOS-over-Wi-Fi use SSH to the device IP."}

            return {"error": "no Android device to bootstrap — attach one via USB once, "
                             "or use action='connect' with a known ip"}

        return {"error": f"unknown action {action!r} ({'|'.join(_ACTIONS)})"}
