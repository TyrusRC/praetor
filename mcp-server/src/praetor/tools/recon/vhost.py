"""Virtual-host discovery via ffuf Host-header fuzzing."""

import os
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP

from ._common import _check_tool, _run_cmd, _sanitize_domain, _USER_AGENT, BURP_PROXY_URL


def register(mcp: FastMCP):

    @mcp.tool()
    async def run_vhost_fuzz(  # cost: expensive (external binary, network-bound)
        target: str,
        wordlist: str = "",
        timeout: int = 300,
        filter_size: str = "",
    ) -> str:
        """Discover virtual hosts by fuzzing the Host header with ffuf. Requires ffuf installed.

        Sends 'Host: FUZZ.<base-domain>' against the target URL and reports names
        whose response differs from the wildcard baseline (ffuf auto-calibration,
        or an operator-supplied filter_size).

        Args:
            target: Target URL or host (e.g. 'https://example.com' or 'example.com')
            wordlist: Path to vhost/subdomain wordlist (auto-detected if empty)
            timeout: Max seconds (default 300)
            filter_size: Response size(s) to filter out; empty = ffuf auto-calibration (-ac)
        """
        if not _check_tool("ffuf"):
            return (
                "Error: ffuf not installed.\n"
                "  Linux/macOS: go install github.com/ffuf/ffuf/v2@latest\n"
                "  Or download: https://github.com/ffuf/ffuf/releases"
            )

        split = urlsplit(target if "://" in target else f"https://{target}")
        scheme = split.scheme or "https"
        host = split.hostname
        if not host:
            return f"Error: could not parse a host from target '{target}'"
        base_domain = _sanitize_domain(host)
        url = f"{scheme}://{split.netloc}{split.path or ''}"

        if not wordlist:
            candidates = [
                "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                "/usr/share/seclists/Discovery/DNS/namelist.txt",
                "/usr/share/wordlists/dirb/common.txt",
                os.path.expanduser("~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"),
            ]
            wordlist = next((c for c in candidates if os.path.isfile(c)), "")
            if not wordlist:
                return (
                    "Error: no wordlist found. Provide one via wordlist=..., or install SecLists:\n"
                    "  git clone https://github.com/danielmiessler/SecLists ~/SecLists"
                )

        cmd = [
            "ffuf", "-u", url, "-w", wordlist,
            "-H", f"Host: FUZZ.{base_domain}",
            "-H", f"User-Agent: {_USER_AGENT}",
            "-mc", "all",
            "-s",
            # Route through Burp (Rule 26) — -x proxy, -k skips TLS verify for MITM
            "-x", BURP_PROXY_URL, "-k",
        ]
        # Wildcard vhost setups answer every Host identically; filter the baseline.
        if filter_size:
            cmd.extend(["-fs", filter_size])
        else:
            cmd.append("-ac")  # auto-calibrate: learn the baseline size/words and filter it

        stdout, stderr, code = await _run_cmd(cmd, timeout)

        if code != 0 and not stdout:
            return f"ffuf vhost fuzz failed (exit {code}): {stderr[:500]}"

        hits = [l.strip() for l in stdout.strip().split("\n") if l.strip()]
        if not hits:
            return f"No virtual hosts discovered on {url} (Host: *.{base_domain})"

        lines = [f"vhosts for {url} (Host: FUZZ.{base_domain}) — {len(hits)} candidate(s):", ""]
        lines.extend(f"  {h}" for h in hits[:100])
        if len(hits) > 100:
            lines.append(f"  ... and {len(hits) - 100} more")
        lines.append("\nAll requests routed through Burp proxy — check proxy history.")
        return "\n".join(lines)
