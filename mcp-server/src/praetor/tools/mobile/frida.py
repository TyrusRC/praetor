"""Execute bundled Frida snippets against a device and keep them attached.

Frida stays running (in the background) so a pinning-bypass hook remains live
while you drive the UI and the app's traffic flows through Burp. A session id
addresses the running process; mobile_frida_stop detaches it.
"""

from __future__ import annotations

import asyncio
import os
import secrets
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _check_tool, _find_tool

from ._device import DeviceError, backend_for, resolve_device
from ._store import log_action

_FRIDA_DIR = Path(__file__).parent.parent.parent / "payloads" / "frida"
_SESSIONS: dict[str, "asyncio.subprocess.Process"] = {}


def _snippet_path(name: str) -> str | None:
    """Resolve a bundled snippet name to its on-disk path, or None if missing."""
    p = _FRIDA_DIR / f"{name}.js"
    return str(p) if p.exists() else None


async def _drain(proc, seconds: float) -> str:
    """Read available stdout lines for up to `seconds`; return what we got."""
    lines: list[str] = []
    end = asyncio.get_event_loop().time() + seconds
    while True:
        remaining = end - asyncio.get_event_loop().time()
        if remaining <= 0:
            break
        try:
            raw = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
        except asyncio.TimeoutError:
            break
        if not raw:
            break
        lines.append(raw.decode("utf-8", "replace").rstrip())
    return "\n".join(lines)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def mobile_frida_run(script: str = "", package: str = "", device: str = "",
                               spawn: bool = True, capture_secs: float = 3.0,
                               domain: str = "") -> dict:
        """Run a bundled Frida snippet (mobile_frida_snippet lists them) and keep
        it attached. Returns a session_id + the first console lines. Typical use:
        run ssl_pin_universal_android, then drive the UI while traffic flows to Burp.

        Args:
            script: snippet name (e.g. ssl_pin_universal_android).
            package: target package / bundle id.
            spawn: True = spawn the app (frida -f); False = attach to running.
            capture_secs: seconds to collect initial console output.
        """
        path = _snippet_path(script)
        if not path:
            return {"error": f"frida snippet {script!r} not found (mobile_frida_snippet lists them)"}
        if not package:
            return {"error": "package (app id) required"}
        if not _check_tool("frida"):
            return {"error": "frida not installed — pip install frida-tools; ensure frida-server "
                            "runs on the device / frida gadget on iOS"}
        try:
            dev = await resolve_device(device)
        except DeviceError as e:
            return {"error": str(e)}

        frida_bin = _find_tool("frida") or "frida"
        cmd = [frida_bin, "-U", "-l", path]
        cmd += (["-f", package] if spawn else [package])
        env = os.environ.copy()
        env.pop("HTTPS_PROXY", None)
        env.pop("HTTP_PROXY", None)
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.DEVNULL, env=env)
        head = await _drain(proc, capture_secs) if capture_secs else await _drain(proc, 0.5)

        sid = "fr" + secrets.token_hex(4)
        _SESSIONS[sid] = proc
        oid = log_action(domain, dev.id, f"frida -U -l {script} {'-f ' if spawn else ''}{package}",
                         description=f"frida {script}", output=head,
                         tags=["ttp:T1562"])  # impair defenses (pinning bypass)
        return {"session_id": sid, "pid": proc.pid, "running": proc.returncode is None,
                "console_head": head, "oplog_id": oid, "device": dev.id,
                "note": "hook stays attached; route the device through Burp and drive the UI. "
                        "mobile_frida_stop(session_id) to detach."}

    @mcp.tool()
    async def mobile_frida_stop(session_id: str = "", device: str = "", domain: str = "") -> dict:
        """Detach a running Frida session started by mobile_frida_run."""
        proc = _SESSIONS.pop(session_id, None)
        if not proc:
            return {"error": f"no such frida session {session_id!r}"}
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        log_action(domain, device, f"frida stop {session_id}", description="detach frida")
        return {"stopped": True, "session_id": session_id}

    @mcp.tool()
    async def mobile_portal(action: str = "info", device: str = "", apk_path: str = "",
                            domain: str = "") -> dict:
        """Optional on-device helper for richer UI data (Android a11y APK / iOS
        WDA). Default footprint is ZERO — pure adb/idb needs no helper. Installing
        one MODIFIES the device under test; the install is recorded to the oplog.

        Args:
            action: info | install | status. install needs apk_path (Android).
        """
        try:
            dev = await resolve_device(device)
        except DeviceError as e:
            return {"error": str(e)}
        if action == "info":
            return {"portal": "optional", "installed": False, "device": dev.id,
                    "note": "pure adb/idb control needs no helper; install only for "
                            "Canvas/Compose/Flutter UIs where uiautomator/idb trees are thin"}
        if action == "install":
            if dev.platform != "android" or not apk_path:
                return {"error": "install needs an Android device and apk_path "
                                "(iOS uses WDA, provisioned out-of-band)"}
            _out, err, rc = await backend_for(dev).run(dev, ["install", "-r", apk_path], timeout=120)
            if rc != 0:
                return {"error": f"adb install failed: {err.strip()}"}
            oid = log_action(domain, dev.id, f"install portal {apk_path}",
                             description="on-device helper install (footprint)",
                             tags=["footprint"])
            return {"action": "install", "apk_path": apk_path, "oplog_id": oid,
                    "note": "helper installed — remember to uninstall at engagement end"}
        return {"error": f"unknown action {action!r} (info|install|status)"}
