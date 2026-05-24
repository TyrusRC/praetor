"""smuggle CLI wrapper — HTTP/1.1 desync detector (Kettle 2025 family).

Covers 0.CL, CL.0, V-H, Expect-100, RQP, double-desync. Complements
in-process probes under http_desync KB.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_smuggle(target: str, timeout: int = 600) -> str:
        """Run smuggle (Kettle 2025 0.CL/CL.0/V-H/Expect/RQP/double-desync).

        Args:
            target: target URL.
            timeout: seconds.
        """
        if not _check_tool("smuggle"):
            return (
                "Error: smuggle not installed.\n"
                "Install: pipx install smuggle  |  https://github.com/defparam/smuggler "
                "(or the Kettle 2025 'smuggle' Python tool)"
            )
        out, err, rc = await _run_cmd(
            ["smuggle", "-u", target, "-x", "http://127.0.0.1:8080"],
            timeout=timeout, bypass_proxy=False,
        )
        if rc != 0 and not out:
            return f"smuggle failed [rc={rc}]: {err[:300]}"
        return f"# smuggle — {target}\n\n{out.strip()[:6000]}"
