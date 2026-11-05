"""Screenshot templates — reusable redaction + appearance presets the AI picks by
name, so a report-ready, safely-redacted shot is one argument (`template="clean"`)
instead of a dozen. Built-in presets live here; user presets are shareable JSON
under `.burp-intel/_templates/screenshot/<name>.json`.

A template is a flat dict of the `screenshot_message` knobs. `expand()` merges a
template under explicit call arguments (the call always wins), so a template sets
the baseline and the agent overrides per shot.
"""

from __future__ import annotations

import json
from pathlib import Path

# Keys a template may set. Anything else in a loaded file is ignored, so a bad or
# hostile template file cannot inject behaviour — it can only set known knobs.
TEMPLATE_KEYS = frozenset({
    "redact", "redact_headers", "hide_headers", "hide_groups",
    "redact_query", "redact_body_fields", "redact_glyph",
    "view", "theme", "size",
})

# Built-in presets. "defaults" = the safe secret set (render-time). "clean" also
# hides report-noise headers and uses the Pretty view. "empty" opts out entirely
# (for a PoC that must SHOW a token value).
BUILTIN: dict[str, dict] = {
    "defaults": {"redact": "defaults"},
    "clean": {
        "redact": "defaults",
        "hide_groups": ["browser", "caching", "tracing"],
        "view": "pretty",
    },
    "report-a4": {
        "redact": "defaults",
        "hide_groups": ["browser", "caching", "tracing"],
        "view": "pretty",
        "size": "a4",
    },
    "empty": {},
}


def _user_dir() -> Path:
    return Path.cwd() / ".burp-intel" / "_templates" / "screenshot"


def _safe_name(name: str) -> str:
    """A template name is a bare slug — no path separators, so a name can never
    escape the templates dir."""
    return "".join(c for c in (name or "").strip().lower()
                   if c.isalnum() or c in ("-", "_"))[:60]


def resolve(name: str) -> dict:
    """The template dict for `name` — a built-in, or a user JSON file, or {} when
    unknown. Only recognised keys are kept."""
    key = _safe_name(name)
    if not key:
        return {}
    if key in BUILTIN:
        return dict(BUILTIN[key])
    f = _user_dir() / f"{key}.json"
    if f.exists():
        try:
            data = json.loads(f.read_text())
        except (OSError, ValueError):
            return {}
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if k in TEMPLATE_KEYS}
    return {}


def expand(template_name: str, overrides: dict) -> dict:
    """Merge a template under explicit call arguments. The call wins: an override
    with a non-empty / non-None value replaces the template's value for that key.
    """
    base = resolve(template_name) if template_name else {}
    out = dict(base)
    for k, v in (overrides or {}).items():
        if k not in TEMPLATE_KEYS:
            continue
        if v in (None, "", [], {}):
            continue  # unset override — keep the template's value
        out[k] = v
    return out


def save(name: str, config: dict) -> dict:
    """Persist a user template as shareable JSON. Returns the path or an error."""
    key = _safe_name(name)
    if not key:
        return {"error": "template name must be alphanumeric (plus - or _)"}
    if key in BUILTIN:
        return {"error": f"'{key}' is a built-in template — pick another name"}
    clean = {k: v for k, v in (config or {}).items() if k in TEMPLATE_KEYS}
    if not clean:
        return {"error": f"no recognised keys — allowed: {sorted(TEMPLATE_KEYS)}"}
    d = _user_dir()
    try:
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{key}.json").write_text(json.dumps(clean, indent=2))
    except OSError as exc:
        return {"error": f"save failed: {exc}"}
    return {"saved": str(d / f"{key}.json"), "name": key, "config": clean}


def names() -> dict:
    """Built-in and user template names, for discovery."""
    user = []
    d = _user_dir()
    if d.exists():
        user = sorted(p.stem for p in d.glob("*.json"))
    return {"builtin": sorted(BUILTIN), "user": user}
