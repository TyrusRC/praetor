"""save_scan_policy + get_scan_policy + list_scan_policies + delete_scan_policy.

Gap vs a commercial DAST's named scan profiles: `run_vigil`'s `profile` param
(quick|normal|thorough|passive) is a single enum per call — there was no way
to define a reusable, named bundle of {profile, scope_host, rate, templates,
auto_network_check, timeout} once and reference it by name across targets and
engagements, the way "OWASP Top 10", "PCI checks", or "Full Web and Network
Scan" work as a saved preset you pick from.

Persisted to .burp-intel/scan_policies/<slug>.json — mirrors
intel/program_policy.py's pattern, but policies here are all independently
addressable by name (no single "active" one): a scan is launched against a
specific target with a specific policy, picked explicitly each time.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor.tools.intel._internals import _atomic_write_json, _intel_root

_VALID_PROFILES = {"quick", "normal", "thorough", "passive"}


def _policies_dir() -> Path:
    return _intel_root() / "scan_policies"


def _slug(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name).strip("_") or "default"


def load_scan_policy(name: str) -> dict:
    """Pure read for run_vigil's own use — {} if the named policy doesn't exist."""
    import json
    path = _policies_dir() / f"{_slug(name)}.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def save_scan_policy(
        name: str,
        profile: str = "normal",
        scope_host: str = "",
        rate: float = 0.0,
        templates: list[str] | None = None,
        use_proxy: bool = True,
        timeout: int = 600,
        auto_network_check: bool = False,
        notes: str = "",
    ) -> str:
        """Save a named, reusable run_vigil configuration — run it by name later.

        Mirrors the commercial-scanner "named scan profile" pattern (e.g. "OWASP
        Top 10", "PCI checks", "Full Web and Network Scan"): define the check
        depth, scope, rate, and network-pivot setting ONCE, then reference it by
        `name` on every run_vigil(policy=...) call instead of re-specifying every
        argument per target.

        Args:
            name: Policy name (e.g. "pci-quarterly", "full-recheck", "api-only").
            profile: quick | normal | thorough | passive.
            scope_host: Host allowlist passed straight through to run_vigil.
            rate: Cap outbound requests per second (0 = unlimited).
            templates: Extra nuclei template dirs to load.
            use_proxy: Route through Burp proxy.
            timeout: Max scan seconds.
            auto_network_check: Also pivot to a port/TLS check of the host.
            notes: Free-form reminder (e.g. "quarterly PCI scope, no auth").
        """
        if profile not in _VALID_PROFILES:
            return f"profile must be one of {sorted(_VALID_PROFILES)}"
        slug = _slug(name)
        d = _policies_dir()
        record = {
            "name": name, "slug": slug, "profile": profile, "scope_host": scope_host,
            "rate": max(0.0, float(rate)), "templates": list(templates or []),
            "use_proxy": bool(use_proxy), "timeout": max(1, int(timeout)),
            "auto_network_check": bool(auto_network_check), "notes": notes,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_write_json(d / f"{slug}.json", record)
        return (f"scan policy saved: {slug}\n"
                f"  profile={profile} scope_host={scope_host or '(none)'} rate={record['rate']} "
                f"timeout={record['timeout']}s auto_network_check={record['auto_network_check']}\n"
                f"  run it: run_vigil(target=..., policy='{slug}')")

    @mcp.tool()
    async def get_scan_policy(name: str) -> str:
        """Return a saved scan policy's settings.

        Args:
            name: Policy name.
        """
        rec = load_scan_policy(name)
        if not rec:
            return f"no scan policy named '{name}' — list_scan_policies() to see what's saved."
        import json
        return json.dumps(rec, indent=2)

    @mcp.tool()
    async def list_scan_policies() -> str:
        """List every saved scan policy with its key settings, one line each."""
        import json
        d = _policies_dir()
        if not d.exists():
            return "no scan policies saved yet — save_scan_policy(name, ...) to create one."
        rows = []
        for f in sorted(d.glob("*.json")):
            try:
                r = json.loads(f.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue
            rows.append(f"  {r.get('slug', f.stem):<20} profile={r.get('profile','?'):<9} "
                       f"scope_host={r.get('scope_host') or '-':<20} "
                       f"net_pivot={r.get('auto_network_check', False)}"
                       + (f"  # {r['notes']}" if r.get("notes") else ""))
        if not rows:
            return "no scan policies saved yet — save_scan_policy(name, ...) to create one."
        return "Saved scan policies:\n" + "\n".join(rows)

    @mcp.tool()
    async def delete_scan_policy(name: str) -> str:
        """Delete a saved scan policy.

        Args:
            name: Policy name.
        """
        path = _policies_dir() / f"{_slug(name)}.json"
        if not path.exists():
            return f"no scan policy named '{name}'"
        path.unlink()
        return f"deleted scan policy '{name}'"
