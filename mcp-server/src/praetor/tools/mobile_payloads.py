"""Mobile payload delivery — Frida snippets + adb command pack (W8, T6).

Pure string-return wrappers. Praetor does NOT execute adb or Frida; the
operator runs these on their authorized device. The MCP tools surface
ready-to-paste payloads from the bundled corpus.

Snippets live in `payloads/frida/*.js`; adb pattern table in
`payloads/adb_commands.json`. Both are operator-curated (no LLM synthesis).
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

_PAYLOADS = Path(__file__).parent.parent / "payloads"
_FRIDA_DIR = _PAYLOADS / "frida"
_ADB_PATH = _PAYLOADS / "adb_commands.json"


def _list_frida_snippets() -> list[str]:
    if not _FRIDA_DIR.exists():
        return []
    return sorted(f.stem for f in _FRIDA_DIR.glob("*.js"))


def _list_adb_commands() -> list[dict]:
    if not _ADB_PATH.exists():
        return []
    try:
        return json.loads(_ADB_PATH.read_text(encoding="utf-8")).get("commands", [])
    except (json.JSONDecodeError, OSError):
        return []


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def mobile_frida_snippet(name: str = "") -> dict:
        """Return a Frida hook script by name. Empty name = list available.

        Available snippets (Android+iOS): ssl_pin_universal_android,
        ssl_pin_okhttp_specific, ssl_pin_universal_ios, root_jailbreak_bypass,
        webview_debug_enable, intent_url_enumerator, crypto_dump,
        keystore_hook, biometric_bypass, logcat_sensitive_tap, clipboard_hook.

        Operator runs:  frida -U -l <saved-path>.js -f <pkg>

        Args:
            name: snippet name (without .js). Empty returns the catalogue.
        """
        available = _list_frida_snippets()
        if not name:
            return {"available": available, "count": len(available),
                    "note": "Call with name=<snippet_id> to fetch the script source."}
        path = _FRIDA_DIR / f"{name}.js"
        if not path.exists():
            return {"error": f"snippet {name!r} not found",
                    "available": available}
        return {
            "name": name,
            "path": str(path),
            "script": path.read_text(encoding="utf-8"),
            "run_cmd": f"frida -U -l {path} -f <pkg>",
        }

    @mcp.tool()
    async def mobile_adb_pack(
        command_id: str = "",
        pkg: str = "",
        target: str = "",
        auth: str = "",
        scheme: str = "",
        host: str = "",
        path: str = "",
        db_file: str = "",
    ) -> dict:
        """Return an adb command string from the corpus, with parameters filled.

        Empty command_id returns the catalogue. Praetor does NOT execute adb —
        operator runs the returned command on their authorized device.

        Args:
            command_id: one of list_packages / pull_apk / dumpsys_package /
                dumpsys_activities / dumpsys_content / exported_activities /
                dangerous_permissions / deep_link_probe / logcat_app_only /
                sandbox_enum / sqlite_dump / service_list.
            pkg: package name to substitute for {pkg}.
            target: substring filter for {target}.
            auth: content authority for {auth}.
            scheme, host, path: deep link parts for {scheme}://{host}{path}.
            db_file: sqlite db file name (without .db).
        """
        commands = _list_adb_commands()
        if not command_id:
            return {"available": [c["id"] for c in commands], "count": len(commands)}
        cmd = next((c for c in commands if c["id"] == command_id), None)
        if not cmd:
            return {"error": f"command {command_id!r} unknown",
                    "available": [c["id"] for c in commands]}

        filled = cmd["command"]
        for key, value in {"pkg": pkg, "target": target, "auth": auth,
                            "scheme": scheme, "host": host, "path": path,
                            "db_file": db_file}.items():
            filled = filled.replace("{" + key + "}", value)

        out: dict = {
            "id": cmd["id"],
            "purpose": cmd["purpose"],
            "command": filled,
        }
        if cmd.get("follow_up"):
            out["follow_up"] = cmd["follow_up"]
        if cmd.get("filter") and target:
            out["filter_suggestion"] = cmd["filter"].replace("{target}", target)
        return out
