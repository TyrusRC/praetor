"""Network scanning tools: nmap."""

from mcp.server.fastmcp import FastMCP

from ._common import _check_tool, _run_cmd


def register(mcp: FastMCP):

    @mcp.tool()
    async def run_nmap(
        target: str,
        ports: str = "",
        scan_type: str = "default",
        timeout: int = 300,
    ) -> str:
        """Run nmap for port scan + service detection.

        nmap does NOT use HTTP; it does TCP/UDP scanning and service probing.
        Therefore it does NOT route through Burp's proxy. Use it for attack-surface
        mapping (open ports, service fingerprints) before HTTP-based scanning.

        Requires nmap: https://nmap.org

        Args:
            target: Target host or CIDR (e.g. 'example.com', '10.0.0.0/24')
            ports: Port spec ('80,443', '1-1000', 'top-1000'). Empty = nmap default (top 1000).
            scan_type: 'default' (fast SYN scan + banner), 'service' (-sV version detect),
                       'script' (-sC default NSE), 'full' (-sV -sC), 'udp' (UDP top-100)
            timeout: Max seconds (default 300)
        """
        if not _check_tool("nmap"):
            return "Error: nmap not installed. Windows: scoop install nmap. Linux/macOS: system package."

        # Reject injection-style inputs for the target
        import re
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._:/\-]*$', target):
            return f"Error: invalid target: {target}"

        cmd = ["nmap", "-T4", "-Pn", "--open"]
        if scan_type == "service":
            cmd.append("-sV")
        elif scan_type == "script":
            cmd.append("-sC")
        elif scan_type == "full":
            cmd.extend(["-sV", "-sC"])
        elif scan_type == "udp":
            cmd.extend(["-sU", "--top-ports", "100"])
        # default: plain SYN scan — no extra flags

        if ports:
            cmd.extend(["-p", ports])
        cmd.append(target)

        stdout, stderr, code = await _run_cmd(cmd, timeout)
        out = stdout.strip() or stderr.strip()
        if not out:
            return f"nmap produced no output (exit {code})"

        # Return a filtered version: drop verbose status lines, keep port/service rows
        keep = []
        for line in out.split("\n"):
            if any(k in line for k in ("open", "Nmap scan report", "PORT", "MAC Address", "Service Info", "OS:")):
                keep.append(line)
        return "\n".join(keep) if keep else out[:3000]
