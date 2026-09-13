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
    """Fallback discovery parser for Facebook idb (`idb list-targets --json`),
    used only when go-ios (`ios`) is not installed."""
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


def _parse_ios_list(text: str) -> list[Device]:
    """Parse go-ios `ios list --json` output into iOS Devices. go-ios only
    lists trusted/connected udids -> treated as authorized. Handles the
    documented `{"deviceList": [...]}` shape, a bare JSON array, richer dict
    entries (a future `--details` output), and a plain udid-per-line fallback
    for non-JSON output, since real go-ios CLI output isn't available here to
    pin exactly (needs real-device calibration)."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return [Device(id=ln.strip(), platform="ios") for ln in text.splitlines() if ln.strip()]
    if isinstance(data, dict):
        # Go marshals a nil slice as JSON null (the common no-device-attached
        # case) -> `.get(...)` returns None here, not [] -- `or []` catches it.
        udids = data.get("deviceList") or []
    elif isinstance(data, list):
        udids = data
    else:
        udids = []
    out: list[Device] = []
    for u in udids:
        if isinstance(u, str) and u.strip():
            out.append(Device(id=u.strip(), platform="ios"))
        elif isinstance(u, dict):
            udid = u.get("udid") or u.get("Udid") or u.get("UDID") or ""
            if udid:
                out.append(Device(id=udid, platform="ios",
                                  model=u.get("name", ""), os_version=u.get("os_version", "")))
    return out


def _parse_ios_info(text: str) -> dict:
    """Parse `ios info` output. Defensive to either a JSON object or
    ideviceinfo-style `Key: Value` lines — the exact go-ios format needs
    real-device calibration (not available in this environment)."""
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, TypeError):
        pass
    return _parse_ideviceinfo(text)


def _parse_ideviceinfo(text: str) -> dict:
    """Parse libimobiledevice `ideviceinfo`'s `Key: Value` line output."""
    out: dict = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        out[key.strip()] = val.strip()
    return out


def _parse_ios_apps(text: str, third_party_only: bool) -> list[str]:
    """Parse go-ios `ios apps` output (a JSON array of app dicts)."""
    try:
        rows = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    # Go marshals a nil slice as JSON null -> json.loads gives None, not [].
    rows = rows or []
    if isinstance(rows, dict):
        rows = [rows]
    pkgs = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if third_party_only and row.get("ApplicationType", "User") != "User":
            continue
        bid = row.get("CFBundleIdentifier", "")
        if bid:
            pkgs.append(bid)
    return sorted(set(pkgs))


def _parse_ideviceinstaller_list(text: str) -> list[str]:
    """Parse libimobiledevice `ideviceinstaller -l` line output
    (`<bundle_id> - "<Name>" <Version>` per line, header lines ignored)."""
    pkgs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or " - " not in line:
            continue
        bid = line.split(" - ", 1)[0].strip()
        if bid and "." in bid:
            pkgs.append(bid)
    return sorted(set(pkgs))


def _parse_idb_apps(text: str, third_party_only: bool) -> list[str]:
    """Parse idb `list-apps --json` output (newline-delimited JSON objects)."""
    pkgs = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not third_party_only or row.get("install_type") == "user":
            pkgs.append(row.get("bundle_id", ""))
    return sorted(p for p in pkgs if p)


async def list_devices() -> list[Device]:
    """All connected Android (adb) + iOS (go-ios, idb fallback) devices.
    Missing tool -> that platform contributes nothing (graceful degradation)."""
    devices: list[Device] = []
    if _check_tool("adb"):
        out, _, rc = await _run_cmd(["adb", "devices", "-l"], timeout=15, bypass_proxy=True)
        if rc == 0:
            devices.extend(_parse_adb_devices(out))
    if _check_tool("ios"):
        out, _, rc = await _run_cmd(["ios", "list", "--json"], timeout=15, bypass_proxy=True)
        if rc == 0:
            devices.extend(_parse_ios_list(out))
    elif _check_tool("idb"):
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

    async def get_proxy(self, dev) -> str:
        """Base fallback: iOS has no CLI-readable device-wide proxy setting
        (AndroidBackend overrides this with a real `settings get` read). Without
        this, mobile_proxy_status's `except DeviceError` around get_proxy() would
        never fire for iOS and the tool would crash with a raw AttributeError."""
        raise DeviceError("iOS device proxy is not readable via CLI — set/verify the Wi-Fi "
                          "proxy manually (stable host address: Tailscale / DHCP reservation)")

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

    async def get_proxy(self, dev) -> str:
        """Device-wide HTTP proxy setting, or "" if unset/disabled (":0")."""
        out, _, _ = await self.run(dev, ["shell", "settings", "get", "global", "http_proxy"])
        v = out.strip()
        return "" if v in ("", "null", ":0", "0") else v

    async def open_url(self, dev, url) -> None:
        """Fire the URL via an Android VIEW intent — routes through the device's
        configured proxy, unlike our own control commands (which bypass it)."""
        await self.run(dev, ["shell", "am", "start", "-a", "android.intent.action.VIEW", "-d", url])

    async def reverse_port(self, dev, port) -> None:
        """adb reverse tcp:<port> tcp:<port> — the device's 127.0.0.1:<port> tunnels
        to the host's, immune to DHCP lease changes (USB only)."""
        _o, err, rc = await self.run(dev, ["reverse", f"tcp:{port}", f"tcp:{port}"])
        if rc != 0:
            raise DeviceError(f"adb reverse failed: {err.strip()}")

    async def set_proxy(self, dev, value) -> None:
        """Set the device-wide HTTP proxy to host:port (or 127.0.0.1:port with reverse_port)."""
        await self.run(dev, ["shell", "settings", "put", "global", "http_proxy", value])

    async def clear_proxy(self, dev) -> None:
        """Unset the device-wide HTTP proxy and drop any adb reverse tunnels."""
        await self.run(dev, ["shell", "settings", "put", "global", "http_proxy", ":0"])
        await self.run(dev, ["reverse", "--remove-all"])


class IOSBackend(_Backend):
    """iOS control over go-ios (`ios` CLI, cross-platform, Rust/Go — installs
    as `ios` per setup Task 1's symlink) + libimobiledevice, so iOS works on
    Linux (no Mac / idb required). Falls back to Facebook idb only when
    go-ios is absent and idb happens to be installed. UI methods
    (tap/swipe/input_text/key/ui_dump_raw) are WebDriverAgent's job — Task 5,
    not reimplemented here.

    UI methods (tap/swipe/input_text/key/ui_dump_raw) drive the device via
    WebDriverAgent, started + port-forwarded by go-ios (see `_wda.py`).

    NOTE: exact go-ios subcommand flags/output shapes (`ios info`, `ios apps`,
    `ios afc`, `ios runwda`, `ios forward`) are reasoned from go-ios's
    documented CLI surface, not captured from a real device in this
    environment — calibrate against a live device before relying on parsed
    fields beyond bundle id / udid, and before trusting exact WDA startup
    flags.
    """

    platform = "ios"
    tool = "ios"

    def _target_flag(self, dev: Device) -> list[str]:
        return ["--udid", dev.id] if dev.id else []

    async def _ios(self, dev, args, timeout=60):
        cmd = ["ios", *args, *self._target_flag(dev)]
        return await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)

    async def _idb(self, dev, args, timeout=60):
        cmd = ["idb", *args, *self._target_flag(dev)]
        return await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)

    async def _libimd(self, binary, dev, args, timeout=60):
        """Run a libimobiledevice CLI tool (`-u <udid>`, not go-ios's `--udid`)."""
        cmd = [binary, *(["-u", dev.id] if dev.id else []), *args]
        return await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)

    _WDA_KEY_MAP = {"HOME": "home"}  # WDA exposes no generic keycode injection (unlike adb's
    # `input keyevent`) -- only a handful of hardware actions. See WdaClient.home() NOTE.

    async def ui_dump_raw(self, dev):
        client = await _wda_ensure(dev)
        return await asyncio.to_thread(client.source)

    async def tap(self, dev, x, y):
        client = await _wda_ensure(dev)
        await asyncio.to_thread(client.tap, x, y)

    async def swipe(self, dev, x1, y1, x2, y2, duration_ms):
        client = await _wda_ensure(dev)
        await asyncio.to_thread(client.swipe, x1, y1, x2, y2, duration_ms / 1000)

    async def input_text(self, dev, text):
        client = await _wda_ensure(dev)
        await asyncio.to_thread(client.type_text, text)

    async def key(self, dev, key):
        action = self._WDA_KEY_MAP.get(key.strip().upper())
        if not action:
            raise DeviceError(f"iOS key {key!r} not mapped to a WDA action "
                              f"(supported: {', '.join(self._WDA_KEY_MAP)})")
        client = await _wda_ensure(dev)
        await asyncio.to_thread(getattr(client, action))

    async def screenshot(self, dev, out_path):
        if _check_tool("ios"):
            _o, err, rc = await self._ios(dev, ["screenshot", "--output", str(out_path)])
            if rc != 0:
                raise DeviceError(f"ios screenshot failed: {err.strip()}")
            return
        if _check_tool("idevicescreenshot"):
            _o, err, rc = await self._libimd("idevicescreenshot", dev, [str(out_path)])
            if rc != 0:
                raise DeviceError(f"idevicescreenshot failed: {err.strip()}")
            return
        if _check_tool("idb"):
            _o, err, rc = await self._idb(dev, ["screenshot", str(out_path)])
            if rc != 0:
                raise DeviceError(f"idb screenshot failed: {err.strip()}")
            return
        raise DeviceError("no iOS screenshot tool found — install go-ios (`ios`) "
                          "or libimobiledevice's idevicescreenshot")

    async def device_info(self, dev):
        # Never raises: discovery already gave us dev.model/dev.os_version,
        # so a missing/failing tool just skips enrichment rather than failing.
        if _check_tool("ios"):
            out, _err, rc = await self._ios(dev, ["info"])
            if rc == 0:
                info = _parse_ios_info(out)
                if info:
                    return {"model": info.get("DeviceName") or info.get("ProductType") or dev.model,
                            "os_version": info.get("ProductVersion") or dev.os_version,
                            "rooted_hint": None}
        if _check_tool("ideviceinfo"):
            out, _err, rc = await self._libimd("ideviceinfo", dev, [])
            if rc == 0:
                info = _parse_ideviceinfo(out)
                if info:
                    return {"model": info.get("DeviceName") or info.get("ProductType") or dev.model,
                            "os_version": info.get("ProductVersion") or dev.os_version,
                            "rooted_hint": None}
        return {"model": dev.model, "os_version": dev.os_version, "rooted_hint": None}

    async def app_list(self, dev, third_party_only):
        if _check_tool("ios"):
            out, err, rc = await self._ios(dev, ["apps"])
            if rc != 0:
                raise DeviceError(f"ios apps failed: {err.strip()}")
            return _parse_ios_apps(out, third_party_only)
        if _check_tool("ideviceinstaller"):
            args = ["-l"] + (["-o", "list_user"] if third_party_only else [])
            out, err, rc = await self._libimd("ideviceinstaller", dev, args)
            if rc != 0:
                raise DeviceError(f"ideviceinstaller failed: {err.strip()}")
            return _parse_ideviceinstaller_list(out)
        if _check_tool("idb"):
            out, _err, rc = await self._idb(dev, ["list-apps", "--json"])
            return _parse_idb_apps(out, third_party_only)
        raise DeviceError("no iOS app-list tool found — install go-ios (`ios`) "
                          "or libimobiledevice's ideviceinstaller")

    async def app_control(self, dev, action, package):
        if action not in ("start", "stop", "info"):
            raise DeviceError(f"action {action!r} unsupported on iOS (start|stop|info)")
        if _check_tool("ios"):
            if action == "start":
                out, err, rc = await self._ios(dev, ["launch", package])
            elif action == "stop":
                out, err, rc = await self._ios(dev, ["kill", package])
            else:
                out, err, rc = await self._ios(dev, ["apps"])
            if rc != 0:
                raise DeviceError(f"ios {action} failed: {err.strip()}")
            return out
        if _check_tool("idb"):
            if action == "start":
                out, err, rc = await self._idb(dev, ["launch", package])
            elif action == "stop":
                out, err, rc = await self._idb(dev, ["terminate", package])
            else:
                out, err, rc = await self._idb(dev, ["list-apps", "--json"])
            if rc != 0:
                raise DeviceError(f"idb {action} failed: {err.strip()}")
            return out
        raise DeviceError("no iOS app-control tool found — install go-ios (`ios`) or idb")

    async def deeplink(self, dev, uri, package):
        # go-ios has no "open arbitrary URL" primitive; idb (SpringBoard-backed)
        # does. Prefer idb for a real deep-link open, else launch the owning
        # app by bundle id via go-ios (not a true URI open), else point at WDA.
        if _check_tool("idb"):
            out, err, rc = await self._idb(dev, ["open", uri])
            if rc != 0:
                raise DeviceError(f"idb open failed: {err.strip()}")
            return out
        if _check_tool("ios"):
            if not package:
                raise DeviceError("go-ios cannot open an arbitrary URI without a bundle id — "
                                  "pass package=<bundle_id> to launch the app, or install idb "
                                  "for a real deep-link open")
            out, err, rc = await self._ios(dev, ["launch", package])
            if rc != 0:
                raise DeviceError(f"ios launch failed: {err.strip()}")
            return out
        raise DeviceError("no iOS deep-link tool found — install go-ios (`ios`) or idb")

    _LOG_CAPTURE_SECS = 8  # NOTE: go-ios/idevicesyslog stream forever; `timeout`
    # (coreutils) bounds the capture window. Ceiling: fixed window, not a
    # line-count tail like adb logcat -t. Upgrade path: stream + stop at N lines.

    async def logs(self, dev, filter_expr, lines):
        if _check_tool("ios"):
            cmd = ["timeout", str(self._LOG_CAPTURE_SECS), "ios", "syslog", *self._target_flag(dev)]
            out, err, rc = await _run_cmd(cmd, timeout=self._LOG_CAPTURE_SECS + 10, bypass_proxy=True)
            if rc not in (0, 124):
                raise DeviceError(f"ios syslog failed: {err.strip()}")
        elif _check_tool("idevicesyslog"):
            cmd = ["timeout", str(self._LOG_CAPTURE_SECS), "idevicesyslog",
                  *(["-u", dev.id] if dev.id else [])]
            out, err, rc = await _run_cmd(cmd, timeout=self._LOG_CAPTURE_SECS + 10, bypass_proxy=True)
            if rc not in (0, 124):
                raise DeviceError(f"idevicesyslog failed: {err.strip()}")
        elif _check_tool("idb"):
            out, _err, _rc = await self._idb(dev, ["log", "--", "show", "--last", "5m"], timeout=30)
        else:
            raise DeviceError("no iOS log tool found — install go-ios (`ios`) "
                              "or libimobiledevice's idevicesyslog")
        rows = out.splitlines()
        if filter_expr:
            rows = [l for l in rows if filter_expr in l]
        tail = rows[-lines:] if lines else rows
        return "\n".join(tail)

    async def pull(self, dev, remote, out_path, package=""):
        if not package:
            raise DeviceError("iOS pull needs package=<bundle_id> (app-sandbox file access)")
        if _check_tool("ios"):
            _o, err, rc = await self._ios(dev, ["afc", "pull", "--container", package,
                                                remote, str(out_path)], timeout=120)
            if rc != 0:
                raise DeviceError(f"ios afc pull failed: {err.strip()}")
            return
        if _check_tool("idb"):
            _o, err, rc = await self._idb(dev, ["file", "pull", "--bundle-id", package,
                                                remote, str(out_path)], timeout=120)
            if rc != 0:
                raise DeviceError(f"idb file pull failed: {err.strip()}")
            return
        raise DeviceError("no iOS file-pull tool found — install go-ios (`ios`) or idb")

    async def shell(self, dev, command):
        raise DeviceError("iOS has no adb-style shell — use mobile_frida_run for "
                          "on-device runtime ops")


async def _wda_ensure(dev) -> "object":
    """Lazily import _wda (avoids a module-load cycle: _wda imports DeviceError
    from this module) and return a live WdaClient for `dev`."""
    from . import _wda
    return await _wda.ensure_session(dev)


def backend_for(dev: Device) -> AndroidBackend | IOSBackend:
    return IOSBackend() if dev.platform == "ios" else AndroidBackend()
