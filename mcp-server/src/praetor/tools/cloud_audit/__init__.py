"""Multi-cloud audit tool pack, split by responsibility:

- recon   — anonymous, read-only cloud recon (public bucket / blob enumeration).
- posture — read-only config-posture audit CLIs (prowler, ScoutSuite, CloudSploit).
- active  — credentialed / post-exploit collectors (azurehound, pacu, gcp_scanner).

`register(mcp)` wires all three. `_check_tool`, `_run_cmd` and `_hint` live here as
package attributes so they can be patched in one place; the submodules resolve them
through this package at call time (see each submodule's `_c`). All OSS
(Apache-2.0 / MIT / BSD).
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _check_tool, _run_cmd


def _hint(tool: str, hint: str) -> str:
    return f"Error: {tool} not installed.\nInstall: {hint}"


# Imported after the shared names above so the submodules can bind this
# (partially initialised) package as `_c` and read its attributes at call time.
from praetor.tools.cloud_audit import active, posture, recon  # noqa: E402


def register(mcp: FastMCP) -> None:
    recon.register(mcp)      # enum_public_buckets — anonymous bucket/blob recon
    posture.register(mcp)    # prowler / scout_suite / cloudsploit — config posture
    active.register(mcp)     # azurehound / pacu / gcp_scanner — credentialed collectors
