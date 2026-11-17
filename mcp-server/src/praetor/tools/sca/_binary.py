"""Native binary hardening check (checksec wrapper)."""

from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _check_tool, _run_cmd
from ._common import _hint


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def check_binary_hardening(path: str, timeout: int = 30) -> str:
        """Check a native binary's compile-time hardening flags (checksec).

        Closes MOB-CODE-005 / DESK-CODE-004 / IOT native-binary-class tests —
        wraps the already-installed `checksec` tool (no new dependency).

        Args:
            path: local path to the binary (ELF or PE).
            timeout: seconds.

        Reports NX, PIE, RELRO (full/partial/none), stack canary, Fortify —
        the exact fields those checklist tests ask for. Does not assert
        pass/fail (Rule 13b): a missing mitigation is Low-Medium severity on
        its own and matters most as a prerequisite for another finding
        (chain_with), not as a standalone report.
        """
        if not Path(path).is_file():
            return f"Error: not a file: {path}"
        if not _check_tool("checksec"):
            return _hint("checksec",
                         "apt install checksec  |  https://github.com/slimm609/checksec.sh")
        # Two incompatible tools share the name `checksec` in the wild:
        # classic checksec.sh (--file=<path> --format json) and pwntools'
        # `pwn checksec` (--file <path>, plain-text only, no --format flag —
        # passing it errors out). Try the universal `--file <path>` form,
        # then parse whichever shape comes back: JSON if it is, else the
        # plain-text "Key:    Value" lines both tools print.
        import json
        out, err, rc = await _run_cmd(
            ["checksec", "--file", path],
            timeout=timeout, bypass_proxy=True,
        )
        combined = out or err
        try:
            data = json.loads(combined)
            row = next(iter(data.values()), {}) if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            row = {}
            import re
            for line in combined.splitlines():
                m = re.match(r"^\s*([A-Za-z][A-Za-z \-]{1,20}):\s+(.+?)\s*$", line)
                if m:
                    row[m.group(1).strip()] = m.group(2).strip()
        if not row:
            tail = "\n".join(combined.splitlines()[:20])
            return f"checksec [{path}]: no parseable result (rc={rc}):\n{tail}"
        lines = [f"checksec {path}:"]
        for k, v in row.items():
            lines.append(f"  {k}: {v}")
        return "\n".join(lines)
