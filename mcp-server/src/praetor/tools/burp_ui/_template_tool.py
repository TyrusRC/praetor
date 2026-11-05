"""screenshot_template — list / get / save reusable screenshot presets.

A template bundles the redaction + appearance knobs of screenshot_message so a
report-ready, safely-redacted shot is one argument (`template="clean"`). Built-in
presets ship with the tool; user presets save as shareable JSON under
`.burp-intel/_templates/screenshot/`.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import _templates


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def screenshot_template(action: str = "list", name: str = "",
                                  config: dict | None = None) -> dict:
        """Manage screenshot presets (redaction + appearance) for screenshot_message.

        A preset holds any of: redact, redact_headers, hide_headers, hide_groups,
        redact_query, redact_body_fields, redact_glyph, view, theme, size. Pass its
        name to `screenshot_message(template=...)`; explicit args override it.

        Built-ins: 'defaults' (safe secret redaction), 'clean' (defaults + hide
        noise headers + pretty view), 'report-a4' (clean + A4 size), 'empty'
        (no redaction — for a PoC that must show a token value).

        Args:
            action: 'list' (names + built-in configs), 'get' (one template's
                config), or 'save' (persist a user template as JSON).
            name: the template name (for 'get' / 'save').
            config: the preset dict (for 'save'). Unknown keys are dropped.
        """
        act = (action or "list").strip().lower()
        if act == "get":
            if not name.strip():
                return {"error": "pass name for action='get'"}
            cfg = _templates.resolve(name)
            if not cfg:
                return {"error": f"no template '{name}'", "available": _templates.names()}
            return {"name": name, "config": cfg}
        if act == "save":
            if not name.strip():
                return {"error": "pass name for action='save'"}
            return _templates.save(name, config or {})
        # list
        out = _templates.names()
        out["builtin_configs"] = dict(_templates.BUILTIN)
        return out
