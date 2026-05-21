"""Scope-mode persistence: operator (default, warn+log) | strict (hard-block).

State lives at .burp-intel/_scope_mode.json so it survives sessions.
"""
import json
from pathlib import Path

_VALID = {"operator", "strict"}
_DEFAULT = "operator"


def _intel_dir() -> Path:
    p = Path.cwd() / ".burp-intel"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _state_file() -> Path:
    return _intel_dir() / "_scope_mode.json"


def get_mode() -> str:
    f = _state_file()
    if not f.exists():
        return _DEFAULT
    try:
        return json.loads(f.read_text()).get("mode", _DEFAULT)
    except (json.JSONDecodeError, OSError):
        return _DEFAULT


def set_mode(mode: str) -> None:
    if mode not in _VALID:
        raise ValueError(f"mode must be one of {sorted(_VALID)}, got {mode!r}")
    _state_file().write_text(json.dumps({"mode": mode}))
