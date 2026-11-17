"""Software-composition analysis wrappers — osv-scanner, trivy, grype.

Also: scan_model_artifacts (pickle opcode scan), check_binary_hardening
(checksec), and check_dependency_typosquat (name-distance check).
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import _scanners, _pickle_scan, _binary, _typosquat


def register(mcp: FastMCP) -> None:
    _scanners.register(mcp)
    _pickle_scan.register(mcp)
    _binary.register(mcp)
    _typosquat.register(mcp)
