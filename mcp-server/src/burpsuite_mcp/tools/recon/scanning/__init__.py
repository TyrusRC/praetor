"""Recon scanning — per-family submodules + re-export shim.

Split from the original monolithic ``recon/scanning.py``. Tools grouped by
recon family:
  - subdomain:   run_amass
  - dirbust:     run_ffuf, run_arjun
  - vuln_scan:   run_nuclei, run_dalfox, run_commix, run_sqlmap,
                 run_nikto, run_wpscan, generate_deserialization_gadget
  - dns_intel:   run_wafw00f, run_httpx
  - archive:     run_gau

SecLists discovery helpers (``detect_seclists`` / ``_cache_seclists`` /
``_SECLISTS_CANDIDATES``) live in this ``__init__.py`` to preserve external
test patching (``mock.patch.object(scanning, "_SECLISTS_CANDIDATES", ...)``)
and to give ``recon.inventory`` and ``tools.wordlist`` the same import path
they had before the split.
"""

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from . import archive, dirbust, dns_intel, subdomain, vuln_scan

_SECLISTS_CANDIDATES = [
    "/usr/share/seclists",
    "/usr/share/SecLists",
    "/opt/SecLists",
    os.path.expanduser("~/SecLists"),
]


def detect_seclists() -> str | None:
    """Return SecLists root path if found, else None.

    Resolution order:
        1. $SECLISTS_PATH env var (if it points at a dir containing 'Discovery/')
        2. Common install paths
    Result is cached to .burp-intel/_seclists_path.json so subsequent calls are O(1).
    """
    env = os.environ.get("SECLISTS_PATH")
    if env and (Path(env) / "Discovery").is_dir():
        _cache_seclists(env)
        return env
    for candidate in _SECLISTS_CANDIDATES:
        if (Path(candidate) / "Discovery").is_dir():
            _cache_seclists(candidate)
            return candidate
    return None


def _cache_seclists(path: str) -> None:
    intel = Path.cwd() / ".burp-intel"
    intel.mkdir(parents=True, exist_ok=True)
    (intel / "_seclists_path.json").write_text(json.dumps({"path": path}))


__all__ = [
    "detect_seclists",
    "_cache_seclists",
    "_SECLISTS_CANDIDATES",
    "register",
    "subdomain",
    "dirbust",
    "vuln_scan",
    "dns_intel",
    "archive",
]


def register(mcp: FastMCP):
    vuln_scan.register(mcp)
    dirbust.register(mcp)
    subdomain.register(mcp)
    dns_intel.register(mcp)
    archive.register(mcp)
