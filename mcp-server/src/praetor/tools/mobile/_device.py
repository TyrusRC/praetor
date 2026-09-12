"""Device model, discovery, resolution, and per-platform command backends.

Android -> adb; iOS -> Facebook idb (UI) + Frida (hooks). Control commands run
with bypass_proxy=True (not target HTTP). Higher-level ops (tap, ui_dump, ...)
are added to the backend classes by the control-tool tasks.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass

from praetor.tools.recon._common import _check_tool, _run_cmd, _find_tool

from . import _guards


class DeviceError(Exception):
    """Unknown / ambiguous / unauthorized device, or missing platform tool."""


@dataclass
class Device:
    id: str
    platform: str  # "android" | "ios"
    model: str = ""
    os_version: str = ""
    authorized: bool = True


def _parse_adb_devices(text: str) -> list[Device]:
    out: list[Device] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        model = ""
        for tok in parts[2:]:
            if tok.startswith("model:"):
                model = tok.split(":", 1)[1]
        out.append(Device(id=serial, platform="android", model=model,
                          authorized=(state == "device")))
    return out


def _parse_idb_targets(text: str) -> list[Device]:
    try:
        rows = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    if isinstance(rows, dict):
        rows = [rows]
    out: list[Device] = []
    for r in rows:
        out.append(Device(id=r.get("udid", ""), platform="ios",
                          model=r.get("name", ""), os_version=r.get("os_version", ""),
                          authorized=(r.get("state", "").lower() in ("booted", "connected", ""))))
    return [d for d in out if d.id]


async def list_devices() -> list[Device]:
    """All connected Android (adb) + iOS (idb) devices. Missing tool -> that
    platform contributes nothing (graceful degradation)."""
    devices: list[Device] = []
    if _check_tool("adb"):
        out, _, rc = await _run_cmd(["adb", "devices", "-l"], timeout=15, bypass_proxy=True)
        if rc == 0:
            devices.extend(_parse_adb_devices(out))
    if _check_tool("idb"):
        out, _, rc = await _run_cmd(["idb", "list-targets", "--json"], timeout=15, bypass_proxy=True)
        if rc == 0:
            devices.extend(_parse_idb_targets(out))
    return devices


async def resolve_device(device: str = "", platform: str = "") -> Device:
    """Pick the target device and enforce the allowlist. Raises DeviceError."""
    devs = await list_devices()
    if platform:
        devs = [d for d in devs if d.platform == platform]
    if not devs:
        raise DeviceError("no connected device found (check adb/idb, USB, authorization)")

    if device:
        match = next((d for d in devs if d.id == device), None)
        if not match:
            raise DeviceError(f"device {device!r} not connected. Connected: "
                              f"{', '.join(d.id for d in devs)}")
    elif len(devs) == 1:
        match = devs[0]
    else:
        raise DeviceError("multiple devices connected — pass device=<serial/udid>. "
                          f"Connected: {', '.join(d.id for d in devs)}")

    ok, why = _guards.check_device(match.id, connected_count=len(devs))
    if not ok:
        raise DeviceError(why)
    if not match.authorized:
        raise DeviceError(f"device {match.id!r} is not authorized/booted "
                          "(adb: accept the RSA prompt; idb: boot the target)")
    return match


class _Backend:
    platform = ""
    tool = ""

    async def run(self, dev: Device, args: list[str], timeout: int = 60) -> tuple[str, str, int]:
        if not _check_tool(self.tool):
            raise DeviceError(f"{self.tool} not installed — required for {self.platform} control")
        cmd = [self.tool, *self._target_flag(dev), *args]
        return await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)

    async def run_binary(self, dev: Device, args: list[str], timeout: int = 60) -> tuple[bytes, str, int]:
        """Like run() but returns raw stdout bytes (for screencap PNG)."""
        if not _check_tool(self.tool):
            raise DeviceError(f"{self.tool} not installed — required for {self.platform} control")
        resolved = _find_tool(self.tool) or self.tool
        cmd = [resolved, *self._target_flag(dev), *args]
        env = os.environ.copy()
        env.pop("HTTPS_PROXY", None)
        env.pop("HTTP_PROXY", None)
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL, env=env)
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            raise DeviceError(f"{self.tool} timed out after {timeout}s")
        return stdout, stderr.decode("utf-8", "replace"), proc.returncode

    def _target_flag(self, dev: Device) -> list[str]:
        raise NotImplementedError


class AndroidBackend(_Backend):
    platform = "android"
    tool = "adb"

    def _target_flag(self, dev: Device) -> list[str]:
        return ["-s", dev.id] if dev.id else []


class IOSBackend(_Backend):
    platform = "ios"
    tool = "idb"

    def _target_flag(self, dev: Device) -> list[str]:
        return ["--udid", dev.id] if dev.id else []


def backend_for(dev: Device) -> AndroidBackend | IOSBackend:
    return IOSBackend() if dev.platform == "ios" else AndroidBackend()
