"""WebDriverAgent (WDA) HTTP client + go-ios session management.

iOS UI driving (tap/swipe/type/dump/screenshot) on Linux has no idb/Mac to lean
on, so it goes through WebDriverAgent instead: go-ios installs+launches WDA on
the device (`ios runwda`) and forwards its port to localhost (`ios forward`),
then this module speaks WDA's plain HTTP/JSON protocol directly (stdlib
`http.client` only -- no new dependency).

NOTE: go-ios's `runwda`/`forward` subcommand flags and WDA's exact JSON field
names (`rect` vs `frame`, `label` vs `name`) are reasoned from documented CLI
surfaces / the Appium-WDA protocol, not captured from a real device in this
environment. Calibrate against a live device before trusting anything beyond
"it either connects or raises a clear DeviceError". A signed WebDriverAgent
build must already be installed/trusted on the device -- go-ios does not sign
one for you.
"""

from __future__ import annotations

import asyncio
import base64
import http.client
import json
import os
import socket

from praetor.tools.recon._common import _check_tool, _find_tool

from ._device import DeviceError

_WDA_DEVICE_PORT = 8100  # WDA's fixed on-device listen port
_WDA_START_TIMEOUT = 15.0  # seconds to wait for WDA to answer after go-ios launches it
_WDA_POLL_INTERVAL = 0.5

# udid -> {"port": int, "client": WdaClient, "runwda_proc": Process, "forward_proc": Process}
_WDA_SESSIONS: dict[str, dict] = {}


class WdaClient:
    """Minimal WebDriverAgent HTTP client (stdlib `http.client`, no deps)."""

    def __init__(self, host: str = "127.0.0.1", port: int = _WDA_DEVICE_PORT, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.session_id: str | None = None

    def _request(self, method: str, path: str, body: dict | None = None) -> bytes:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            payload = json.dumps(body).encode() if body is not None else None
            headers = {"Content-Type": "application/json"} if payload is not None else {}
            conn.request(method, path, body=payload, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            if resp.status >= 400:
                raise DeviceError(f"WDA {method} {path} -> HTTP {resp.status}: "
                                  f"{data[:300].decode('utf-8', 'replace')}")
            return data
        finally:
            conn.close()

    def _request_json(self, method: str, path: str, body: dict | None = None) -> dict:
        data = self._request(method, path, body)
        if not data:
            return {}
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return {}

    def session(self, bundle_id: str = "") -> str:
        """POST /session -- create a WDA session. Returns the sessionId."""
        caps = {"capabilities": {"alwaysMatch": ({"bundleId": bundle_id} if bundle_id else {})}}
        out = self._request_json("POST", "/session", caps)
        sid = out.get("sessionId") or out.get("value", {}).get("sessionId", "")
        if not sid:
            raise DeviceError(f"WDA /session returned no sessionId: {out!r}")
        self.session_id = sid
        return sid

    def _sid(self) -> str:
        if not self.session_id:
            raise DeviceError("no active WDA session -- call session() first")
        return self.session_id

    def source(self) -> str:
        """GET the current session's accessibility tree as raw JSON text.
        Feed the result to parse_wda_source() for the flattened element list."""
        data = self._request("GET", f"/session/{self._sid()}/wda/accessibleSource")
        return data.decode("utf-8", "replace")

    def tap(self, x: int, y: int) -> None:
        self._request_json("POST", f"/session/{self._sid()}/wda/tap/0", {"x": x, "y": y})

    def swipe(self, x1: int, y1: int, x2: int, y2: int, duration: float = 0.3) -> None:
        self._request_json("POST", f"/session/{self._sid()}/wda/dragfromtoforduration",
                           {"fromX": x1, "fromY": y1, "toX": x2, "toY": y2, "duration": duration})

    def type_text(self, t: str) -> None:
        self._request_json("POST", f"/session/{self._sid()}/wda/keys", {"value": list(t)})

    def screenshot(self) -> bytes:
        """GET /screenshot (session-independent) -> decoded PNG bytes."""
        out = self._request_json("GET", "/screenshot")
        b64 = out.get("value", "")
        if not b64:
            raise DeviceError("WDA /screenshot returned no image data")
        return base64.b64decode(b64)

    def open_url(self, u: str) -> None:
        self._request_json("POST", f"/session/{self._sid()}/url", {"url": u})

    def home(self) -> None:
        """POST /wda/homescreen -- press the Home button/gesture (session-independent).
        NOTE: WDA has no generic keycode endpoint like adb's `input keyevent`; only a
        handful of hardware actions are exposed this way. Upgrade path: map more
        buttons (volume up/down) via /wda/pressButton once calibrated on a device."""
        self._request_json("POST", "/wda/homescreen")


def parse_wda_source(raw_json) -> list[dict]:
    """Flatten a WebDriverAgent accessibility-tree response into the SAME
    element shape as control.parse_ui: {index, text, resource_id, class,
    bounds, center, clickable}.

    Accepts either the raw JSON text (as returned by WdaClient.source()) or an
    already-parsed dict/list. WDA nests children under each node and wraps the
    tree as {"value": {...}}; geometry may be reported as `rect` or `frame`
    (both are read defensively -- the exact field set isn't calibrated against
    a live device in this environment).
    """
    if isinstance(raw_json, (str, bytes)):
        try:
            data = json.loads(raw_json)
        except (json.JSONDecodeError, TypeError):
            return []
    else:
        data = raw_json
    value = data.get("value", data) if isinstance(data, dict) else data
    roots = value if isinstance(value, list) else [value]

    els: list[dict] = []

    def walk(node) -> None:
        if not isinstance(node, dict):
            return
        geo = node.get("rect") or node.get("frame") or {}
        x, y = int(geo.get("x", 0)), int(geo.get("y", 0))
        w, h = int(geo.get("width", 0)), int(geo.get("height", 0))
        has_geo = bool(geo)
        bounds = [x, y, x + w, y + h] if has_geo else []
        center = [x + w // 2, y + h // 2] if has_geo else []
        els.append({
            "index": len(els),
            "text": node.get("label") or node.get("value") or node.get("name") or "",
            "resource_id": node.get("name") or node.get("rawIdentifier", ""),
            "class": node.get("type", ""),
            "bounds": bounds,
            "center": center,
            "clickable": bool(node.get("enabled", True)),
        })
        for child in node.get("children") or []:
            walk(child)

    for r in roots:
        walk(r)
    return els


def _free_port() -> int:
    """Ask the OS for an unused local TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _kill(proc) -> None:
    try:
        proc.kill()
    except ProcessLookupError:
        pass


async def _spawn(cmd: list[str]) -> "asyncio.subprocess.Process":
    env = os.environ.copy()
    env.pop("HTTPS_PROXY", None)
    env.pop("HTTP_PROXY", None)
    return await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        stdin=asyncio.subprocess.DEVNULL, env=env)


async def _wait_for_wda(client: WdaClient) -> None:
    """Poll WDA's /session until it answers, or raise. go-ios's runwda needs a
    few seconds to install+launch WDA on-device before it's reachable."""
    loop = asyncio.get_event_loop()
    deadline = loop.time() + _WDA_START_TIMEOUT
    last_err: Exception | None = None
    while loop.time() < deadline:
        try:
            await asyncio.to_thread(client.session)
            return
        except (OSError, DeviceError, http.client.HTTPException) as e:
            last_err = e
            await asyncio.sleep(_WDA_POLL_INTERVAL)
    raise DeviceError(
        "WebDriverAgent did not respond after go-ios runwda+forward -- a signed "
        f"WebDriverAgent build must be installed/trusted on the device (last error: {last_err})")


async def ensure_session(dev) -> WdaClient:
    """Return a live WdaClient for `dev`, lazily starting go-ios `runwda` +
    `forward` and opening a WDA session on first use. Cached per-udid."""
    entry = _WDA_SESSIONS.get(dev.id)
    if entry:
        return entry["client"]
    if not _check_tool("ios"):
        raise DeviceError("go-ios (`ios`) not installed -- required to start/forward "
                          "WebDriverAgent for iOS UI driving")

    ios_bin = _find_tool("ios") or "ios"
    port = _free_port()
    runwda_cmd = [ios_bin, "runwda", "--udid", dev.id]
    forward_cmd = [ios_bin, "forward", str(port), str(_WDA_DEVICE_PORT), "--udid", dev.id]

    runwda_proc = await _spawn(runwda_cmd)
    forward_proc = await _spawn(forward_cmd)

    client = WdaClient(port=port)
    try:
        await _wait_for_wda(client)
    except DeviceError:
        _kill(runwda_proc)
        _kill(forward_proc)
        raise

    _WDA_SESSIONS[dev.id] = {"port": port, "client": client,
                             "runwda_proc": runwda_proc, "forward_proc": forward_proc}
    return client


async def stop_session(udid: str) -> bool:
    """Tear down a cached WDA session: kill the runwda/forward processes and
    drop it from the registry. Returns False if no session was cached."""
    entry = _WDA_SESSIONS.pop(udid, None)
    if not entry:
        return False
    _kill(entry["runwda_proc"])
    _kill(entry["forward_proc"])
    return True
