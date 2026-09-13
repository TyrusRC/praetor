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

    strict = os.environ.get("PRAETOR_MOBILE_STRICT", "").strip().lower() in ("1", "true", "yes", "on")
    ok, why = _guards.check_device(match.id, connected_count=len(devs), strict=strict)
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

    async def screenshot(self, dev, out_path):
        data, err, rc = await self.run_binary(dev, ["exec-out", "screencap", "-p"])
        if rc != 0:
            raise DeviceError(f"screencap failed: {err.strip()}")
        out_path.write_bytes(data)

    async def ui_dump_raw(self, dev):
        _o, err, rc = await self.run(dev, ["shell", "uiautomator", "dump", "/sdcard/praetor_ui.xml"])
        if rc != 0:
            raise DeviceError(f"uiautomator dump failed: {err.strip()}")
        out, err2, rc2 = await self.run(dev, ["shell", "cat", "/sdcard/praetor_ui.xml"])
        if rc2 != 0:
            raise DeviceError(f"reading ui dump failed: {err2.strip()}")
        return out

    async def tap(self, dev, x, y):
        await self.run(dev, ["shell", "input", "tap", str(x), str(y)])

    async def swipe(self, dev, x1, y1, x2, y2, duration_ms):
        await self.run(dev, ["shell", "input", "swipe", str(x1), str(y1),
                             str(x2), str(y2), str(duration_ms)])

    async def input_text(self, dev, text):
        # NOTE: only spaces are escaped (space -> %s); shell metacharacters (;&`$) in
        # text reach 'adb shell input text' unescaped. Safe (check_command guards
        # destruction; argv exec, no shell=True) but a field value containing them is
        # mangled. Upgrade path: base64-encode + broadcast, or per-char keyevent, for
        # exact text.
        await self.run(dev, ["shell", "input", "text", text.replace(" ", "%s")])

    async def key(self, dev, key):
        await self.run(dev, ["shell", "input", "keyevent", key])

    async def device_info(self, dev):
        model, _, _ = await self.run(dev, ["shell", "getprop", "ro.product.model"])
        ver, _, _ = await self.run(dev, ["shell", "getprop", "ro.build.version.release"])
        su, _, rc = await self.run(dev, ["shell", "which", "su"])
        return {"model": model.strip(), "os_version": ver.strip(),
                "rooted_hint": bool(su.strip())}

    async def app_list(self, dev, third_party_only):
        args = ["shell", "pm", "list", "packages"] + (["-3"] if third_party_only else [])
        out, _, _ = await self.run(dev, args)
        return sorted(l.split(":", 1)[1].strip() for l in out.splitlines()
                      if l.startswith("package:"))

    async def app_control(self, dev, action, package):
        if action == "start":
            out, _, _ = await self.run(dev, ["shell", "monkey", "-p", package,
                                             "-c", "android.intent.category.LAUNCHER", "1"])
        elif action == "stop":
            out, _, _ = await self.run(dev, ["shell", "am", "force-stop", package])
        elif action == "clear":
            out, _, _ = await self.run(dev, ["shell", "pm", "clear", package])
        elif action == "info":
            out, _, _ = await self.run(dev, ["shell", "dumpsys", "package", package], timeout=30)
        else:
            raise DeviceError(f"unknown action {action!r} (start|stop|clear|info)")
        return out

    async def deeplink(self, dev, uri, package):
        args = ["shell", "am", "start", "-a", "android.intent.action.VIEW", "-d", uri]
        if package:
            args += [package]
        out, err, rc = await self.run(dev, args)
        if rc != 0:
            raise DeviceError(f"deeplink failed: {err.strip()}")
        return out

    async def logs(self, dev, filter_expr, lines):
        args = ["logcat", "-d", "-t", str(lines)]
        if filter_expr:
            args += filter_expr.split()
        out, _, _ = await self.run(dev, args, timeout=30)
        return out

    async def pull(self, dev, remote, out_path, package=""):
        _o, err, rc = await self.run(dev, ["pull", remote, str(out_path)], timeout=120)
        if rc != 0:
            raise DeviceError(f"adb pull failed: {err.strip()}")

    async def shell(self, dev, command):
        # NOTE: naive command.split() — pipes/quotes/globs are not honored (adb
        # reassembles argv on-device). check_command guards destruction. Upgrade path:
        # wrap complex commands in ["shell","sh","-c", command].
        return await self.run(dev, ["shell", *command.split()])


class IOSBackend(_Backend):
    platform = "ios"
    tool = "idb"

    def _target_flag(self, dev: Device) -> list[str]:
        return ["--udid", dev.id] if dev.id else []

    async def screenshot(self, dev, out_path):
        _o, err, rc = await self.run(dev, ["screenshot", str(out_path)])
        if rc != 0:
            raise DeviceError(f"idb screenshot failed: {err.strip()}")

    async def ui_dump_raw(self, dev):
        out, err, rc = await self.run(dev, ["ui", "describe-all", "--json"])
        if rc != 0:
            raise DeviceError(f"idb ui describe-all failed: {err.strip()}")
        return out

    async def tap(self, dev, x, y):
        await self.run(dev, ["ui", "tap", str(x), str(y)])

    async def swipe(self, dev, x1, y1, x2, y2, duration_ms):
        await self.run(dev, ["ui", "swipe", str(x1), str(y1), str(x2), str(y2)])

    async def input_text(self, dev, text):
        await self.run(dev, ["ui", "text", text])

    async def key(self, dev, key):
        await self.run(dev, ["ui", "key", key])

    async def device_info(self, dev):
        return {"model": dev.model, "os_version": dev.os_version, "rooted_hint": None}

    async def app_list(self, dev, third_party_only):
        out, _, _ = await self.run(dev, ["list-apps", "--json"])
        pkgs = []
        for line in out.splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not third_party_only or row.get("install_type") == "user":
                pkgs.append(row.get("bundle_id", ""))
        return sorted(p for p in pkgs if p)

    async def app_control(self, dev, action, package):
        if action == "start":
            out, _, _ = await self.run(dev, ["launch", package])
        elif action == "stop":
            out, _, _ = await self.run(dev, ["terminate", package])
        elif action == "info":
            out, _, _ = await self.run(dev, ["list-apps", "--json"])
        else:
            raise DeviceError(f"action {action!r} unsupported on iOS (start|stop|info)")
        return out

    async def deeplink(self, dev, uri, package):
        out, err, rc = await self.run(dev, ["open", uri])
        if rc != 0:
            raise DeviceError(f"idb open failed: {err.strip()}")
        return out

    async def logs(self, dev, filter_expr, lines):
        out, _, _ = await self.run(dev, ["log", "--", "show", "--last", "5m"], timeout=30)
        tail = out.splitlines()[-lines:] if lines else out.splitlines()
        return "\n".join(tail)

    async def pull(self, dev, remote, out_path, package=""):
        if not package:
            raise DeviceError("iOS pull needs package=<bundle_id> (idb file pull --bundle-id)")
        _o, err, rc = await self.run(dev, ["file", "pull", "--bundle-id", package,
                                           remote, str(out_path)], timeout=120)
        if rc != 0:
            raise DeviceError(f"idb file pull failed: {err.strip()}")

    async def shell(self, dev, command):
        raise DeviceError("iOS has no adb-style shell — use mobile_frida_run for "
                          "on-device runtime ops")


def backend_for(dev: Device) -> AndroidBackend | IOSBackend:
    return IOSBackend() if dev.platform == "ios" else AndroidBackend()
