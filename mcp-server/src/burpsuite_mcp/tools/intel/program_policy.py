"""set_program_policy + get_program_policy + load_active_program_policy.

Per-program override that lets the operator strip / extend the hardcoded
NEVER-SUBMIT list, set a confidence floor, and tag engagement scope text.
Persisted to .burp-intel/programs/<slug>.json with an active.json marker.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from ._internals import _atomic_write_json, _intel_root


def _programs_dir() -> Path:
    return _intel_root() / "programs"


def register(mcp: FastMCP):

    @mcp.tool()
    async def set_program_policy(
        name: str,
        scope_text: str = "",
        never_submit_remove: list[str] | None = None,
        never_submit_add: list[str] | None = None,
        confidence_floor: float = 0.0,
        notes: str = "",
    ) -> str:
        """Persist per-program policy that overrides hardcoded NEVER SUBMIT defaults.

        Args:
            name: Program slug (e.g. 'h1-acme', 'bugcrowd-acme', 'intigriti-foo')
            scope_text: Free-form scope text from the program brief (referenced by humans, not parsed)
            never_submit_remove: NEVER SUBMIT keys this program DOES accept (e.g. ['user_enumeration', 'tabnabbing'])
            never_submit_add: Extra NEVER SUBMIT keys for this program (e.g. ['rate_limit_login'])
            confidence_floor: Minimum confidence to report (0.0 = accept all REPORT verdicts)
            notes: Free-form operator notes (payout table, triager preferences)
        """
        slug = re.sub(r"[^a-zA-Z0-9._-]", "_", name).strip("_") or "default"
        programs_dir = _programs_dir()
        programs_dir.mkdir(parents=True, exist_ok=True)
        out_path = programs_dir / f"{slug}.json"
        record = {
            "name": name,
            "slug": slug,
            "scope_text": scope_text,
            "never_submit_remove": list(dict.fromkeys(never_submit_remove or [])),
            "never_submit_add": list(dict.fromkeys(never_submit_add or [])),
            "confidence_floor": max(0.0, min(1.0, float(confidence_floor))),
            "notes": notes,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_write_json(out_path, record)
        active_path = programs_dir / "active.json"
        _atomic_write_json(active_path, {"slug": slug})
        return (
            f"Program policy saved: {slug} (now active)\n"
            f"  Path: {out_path}\n"
            f"  Removed from NEVER SUBMIT: {', '.join(record['never_submit_remove']) or '(none)'}\n"
            f"  Added to NEVER SUBMIT: {', '.join(record['never_submit_add']) or '(none)'}\n"
            f"  Confidence floor: {record['confidence_floor']:.2f}\n"
            "assess_finding will apply these overrides on next call."
        )

    @mcp.tool()
    async def get_program_policy(name: str = "") -> str:
        """Return the active program policy or a named one.

        Args:
            name: Program slug. Empty = return active program.
        """
        programs_dir = _programs_dir()
        if not name:
            active = programs_dir / "active.json"
            if not active.exists():
                return "No active program. Use set_program_policy(...) to create one."
            try:
                slug = json.loads(active.read_text()).get("slug", "")
            except (json.JSONDecodeError, OSError):
                return "Active marker corrupted; recreate with set_program_policy."
            target = programs_dir / f"{slug}.json"
        else:
            slug = re.sub(r"[^a-zA-Z0-9._-]", "_", name).strip("_")
            target = programs_dir / f"{slug}.json"
        if not target.exists():
            return f"No policy for '{slug or name}'."
        return target.read_text()


# Module-level loader for advisor.py — pure read, no MCP needed.
def load_active_program_policy() -> dict:
    """Load the active program policy as a dict, or return empty dict if none."""
    programs_dir = _programs_dir()
    active = programs_dir / "active.json"
    if not active.exists():
        return {}
    try:
        slug = json.loads(active.read_text()).get("slug", "")
        if not slug:
            return {}
        path = programs_dir / f"{slug}.json"
        if not path.exists():
            return {}
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
