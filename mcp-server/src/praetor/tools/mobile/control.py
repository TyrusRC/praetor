# tools/mobile/control.py
"""Active mobile device-control tools: perception (screenshot, ui_dump),
input (tap/swipe/text/key), apps, diagnostics, Frida. Every mutating call
guards the command and records an operator-log entry.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from ._device import DeviceError, backend_for, list_devices, resolve_device
from ._guards import check_command
from ._store import artifact_dir, log_action

_BOUNDS_RE = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


def parse_ui(raw: str, platform: str) -> list[dict]:
    """Flatten a UI hierarchy into indexed elements with tappable centers."""
    if platform == "ios":
        return _parse_ui_ios(raw)
    return _parse_ui_android(raw)


def _parse_ui_android(raw: str) -> list[dict]:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return []
    els: list[dict] = []
    for i, node in enumerate(root.iter("node")):
        b = _BOUNDS_RE.search(node.get("bounds", ""))
        bounds = [int(b.group(1)), int(b.group(2)), int(b.group(3)), int(b.group(4))] if b else []
        center = [(bounds[0] + bounds[2]) // 2, (bounds[1] + bounds[3]) // 2] if bounds else []
        els.append({
            "index": i,
            "text": node.get("text", ""),
            "resource_id": node.get("resource-id", ""),
            "class": node.get("class", ""),
            "bounds": bounds,
            "center": center,
            "clickable": node.get("clickable") == "true",
        })
    return els


def _parse_ui_ios(raw: str) -> list[dict]:
    try:
        rows = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    els: list[dict] = []
    for i, r in enumerate(rows):
        frame = r.get("frame", {})
        x, y = int(frame.get("x", 0)), int(frame.get("y", 0))
        w, h = int(frame.get("width", 0)), int(frame.get("height", 0))
        els.append({
            "index": i,
            "text": r.get("AXLabel") or r.get("AXValue") or "",
            "resource_id": r.get("AXUniqueId", ""),
            "class": r.get("type", ""),
            "bounds": [x, y, x + w, y + h],
            "center": [x + w // 2, y + h // 2],
            "clickable": bool(r.get("AXEnabled", True)),
        })
    return els


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def mobile_screenshot(device: str = "", domain: str = "", as_base64: bool = False) -> dict:
        """Capture the device screen -> PNG artifact. Returns the saved path;
        set as_base64=True to also receive the image inline (costs tokens).

        Args:
            device: adb serial / ios udid. Empty = the only connected device.
            domain: engagement domain for artifact + oplog storage.
            as_base64: include base64 PNG in the result.
        """
        try:
            dev = await resolve_device(device)
        except DeviceError as e:
            return {"error": str(e)}
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        out = artifact_dir(domain) / f"screen-{dev.id}-{ts}.png"
        try:
            await backend_for(dev).screenshot(dev, out)
        except DeviceError as e:
            return {"error": str(e)}
        oid = log_action(domain, dev.id, "screenshot", description="screen capture",
                         output=str(out))
        res = {"path": str(out), "oplog_id": oid, "device": dev.id}
        if as_base64:
            import base64
            res["png_base64"] = base64.b64encode(out.read_bytes()).decode()
        return res

    @mcp.tool()
    async def mobile_ui_dump(device: str = "", domain: str = "") -> dict:
        """Dump the on-screen UI hierarchy as indexed elements
        ({index, text, resource_id, class, bounds, center, clickable}).
        Use an element's `index` with mobile_tap(element_index=...).
        """
        try:
            dev = await resolve_device(device)
            raw = await backend_for(dev).ui_dump_raw(dev)
        except DeviceError as e:
            return {"error": str(e)}
        els = parse_ui(raw, dev.platform)
        oid = log_action(domain, dev.id, "ui_dump", description=f"{len(els)} elements")
        return {"elements": els, "count": len(els), "oplog_id": oid, "device": dev.id}

    async def _resolve_tap_target(dev, x, y, element_index):
        if element_index is not None:
            raw = await backend_for(dev).ui_dump_raw(dev)
            els = parse_ui(raw, dev.platform)
            match = next((e for e in els if e["index"] == element_index), None)
            if not match or not match["center"]:
                raise DeviceError(f"element_index {element_index} not found / has no bounds")
            return match["center"][0], match["center"][1]
        if x is None or y is None:
            raise DeviceError("pass either (x, y) or element_index")
        return x, y

    @mcp.tool()
    async def mobile_tap(device: str = "", x: int | None = None, y: int | None = None,
                         element_index: int | None = None, domain: str = "") -> dict:
        """Tap a coordinate, or the center of a mobile_ui_dump element by index."""
        try:
            dev = await resolve_device(device)
            tx, ty = await _resolve_tap_target(dev, x, y, element_index)
            await backend_for(dev).tap(dev, tx, ty)
        except DeviceError as e:
            return {"error": str(e)}
        oid = log_action(domain, dev.id, f"tap {tx} {ty}", description="tap")
        return {"tapped": [tx, ty], "oplog_id": oid, "device": dev.id}

    @mcp.tool()
    async def mobile_swipe(device: str = "", x1: int = 0, y1: int = 0, x2: int = 0, y2: int = 0,
                           duration_ms: int = 300, domain: str = "") -> dict:
        """Swipe/scroll from (x1,y1) to (x2,y2)."""
        try:
            dev = await resolve_device(device)
            await backend_for(dev).swipe(dev, x1, y1, x2, y2, duration_ms)
        except DeviceError as e:
            return {"error": str(e)}
        oid = log_action(domain, dev.id, f"swipe {x1} {y1} {x2} {y2}", description="swipe")
        return {"swiped": [x1, y1, x2, y2], "oplog_id": oid, "device": dev.id}

    @mcp.tool()
    async def mobile_input_text(device: str = "", text: str = "", domain: str = "") -> dict:
        """Type text into the focused field."""
        ok, why = check_command(f"input text {text}")
        if not ok:
            return {"error": why}
        try:
            dev = await resolve_device(device)
            await backend_for(dev).input_text(dev, text)
        except DeviceError as e:
            return {"error": str(e)}
        oid = log_action(domain, dev.id, "input text <redacted>", description="type text")
        return {"typed": True, "oplog_id": oid, "device": dev.id}

    @mcp.tool()
    async def mobile_key(device: str = "", key: str = "", domain: str = "") -> dict:
        """Send a key event. Android: keycode name/number (e.g. KEYCODE_BACK, 4).
        iOS (idb): a supported button code."""
        try:
            dev = await resolve_device(device)
            await backend_for(dev).key(dev, key)
        except DeviceError as e:
            return {"error": str(e)}
        oid = log_action(domain, dev.id, f"key {key}", description="key event")
        return {"key": key, "oplog_id": oid, "device": dev.id}

    @mcp.tool()
    async def mobile_devices() -> dict:
        """List connected Android (adb) + iOS (idb) devices and their state."""
        devs = await list_devices()
        return {"count": len(devs),
                "devices": [{"id": d.id, "platform": d.platform, "model": d.model,
                             "os_version": d.os_version, "authorized": d.authorized}
                            for d in devs]}

    @mcp.tool()
    async def mobile_device_info(device: str = "", domain: str = "") -> dict:
        """Model, OS version, and a root/jailbreak hint for the target device."""
        try:
            dev = await resolve_device(device)
            info = await backend_for(dev).device_info(dev)
        except DeviceError as e:
            return {"error": str(e)}
        return {"device": dev.id, "platform": dev.platform, **info}

    @mcp.tool()
    async def mobile_app_list(device: str = "", third_party_only: bool = True,
                              domain: str = "") -> dict:
        """List installed packages (third-party by default)."""
        try:
            dev = await resolve_device(device)
            pkgs = await backend_for(dev).app_list(dev, third_party_only)
        except DeviceError as e:
            return {"error": str(e)}
        oid = log_action(domain, dev.id, "app_list", description=f"{len(pkgs)} packages")
        return {"packages": pkgs, "count": len(pkgs), "oplog_id": oid, "device": dev.id}

    @mcp.tool()
    async def mobile_app_control(action: str = "", package: str = "", device: str = "",
                                 domain: str = "") -> dict:
        """Control an app: start | stop | clear | info. `info` returns the
        manifest / permissions / exported components dump. `clear` (data wipe)
        is refused by the guard — mobile pentest proves impact by READ."""
        ok, why = check_command(f"pm {action} {package}")
        if not ok:
            return {"error": why}
        try:
            dev = await resolve_device(device)
            out = await backend_for(dev).app_control(dev, action, package)
        except DeviceError as e:
            return {"error": str(e)}
        oid = log_action(domain, dev.id, f"app {action} {package}", description=action,
                         output=out[:2000])
        return {"action": action, "package": package, "output": out,
                "oplog_id": oid, "device": dev.id}

    @mcp.tool()
    async def mobile_deeplink(uri: str = "", package: str = "", device: str = "",
                              domain: str = "") -> dict:
        """Fire a deep link / URL scheme at the app. Traffic the app makes in
        response is captured in Burp (route the device through the Burp proxy);
        the mobile_deeplink / webview_injection KBs match on it."""
        try:
            dev = await resolve_device(device)
            out = await backend_for(dev).deeplink(dev, uri, package)
        except DeviceError as e:
            return {"error": str(e)}
        oid = log_action(domain, dev.id, f"deeplink {uri}", description="deep link")
        return {"uri": uri, "output": out, "oplog_id": oid, "device": dev.id,
                "note": "check Burp Proxy history for the app's resulting requests"}
