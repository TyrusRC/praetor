"""Directory / parameter fuzzers: ffuf, arjun."""

import os

from mcp.server.fastmcp import FastMCP

from .._common import _check_tool, _run_cmd, _USER_AGENT, BURP_PROXY_URL


def register(mcp: FastMCP):

    @mcp.tool()
    async def run_ffuf(
        target: str,
        wordlist: str = "",
        match_codes: str = "200,204,301,302,307,401,403,405",
        filter_size: str = "",
        filter_words: str = "",
        threads: int = 40,
        use_proxy: bool = True,
        timeout: int = 300,
    ) -> str:
        """Run ffuf for directory/file/parameter fuzzing. Target URL must contain FUZZ keyword. Requires ffuf installed.

        Args:
            target: Target URL with FUZZ placeholder
            wordlist: Path to wordlist file (auto-detected if empty)
            match_codes: HTTP status codes to include (default '200,204,301,302,307,401,403,405')
            filter_size: Response size to filter out
            filter_words: Response word-count to filter out
            threads: Concurrency (default 40)
            use_proxy: Route through Burp proxy (default True)
            timeout: Max seconds (default 300)
        """
        if not _check_tool("ffuf"):
            return (
                "Error: ffuf not installed.\n"
                "  Windows: scoop install ffuf\n"
                "  Linux/macOS: go install github.com/ffuf/ffuf/v2@latest\n"
                "  Or download: https://github.com/ffuf/ffuf/releases"
            )

        if "FUZZ" not in target:
            return "Error: target URL must contain the literal word FUZZ (e.g. 'https://target.com/FUZZ')"

        # Locate a wordlist if none specified
        if not wordlist:
            candidates = [
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/wordlists/dirb/common.txt",
                os.path.expanduser("~/SecLists/Discovery/Web-Content/common.txt"),
            ]
            wordlist = next((c for c in candidates if os.path.isfile(c)), "")
            if not wordlist:
                return (
                    "Error: no wordlist found. Provide one via wordlist=..., or install SecLists:\n"
                    "  git clone https://github.com/danielmiessler/SecLists ~/SecLists"
                )

        cmd = [
            "ffuf", "-u", target, "-w", wordlist,
            "-mc", match_codes,
            "-t", str(threads),
            "-s",                            # silent
            "-H", f"User-Agent: {_USER_AGENT}",
        ]
        if filter_size:
            cmd.extend(["-fs", filter_size])
        if filter_words:
            cmd.extend(["-fw", filter_words])
        if use_proxy:
            # ffuf uses -x for proxy (not --proxy); -k skips TLS verify for Burp MITM
            cmd.extend(["-x", BURP_PROXY_URL, "-k"])

        stdout, stderr, code = await _run_cmd(cmd, timeout)

        if code != 0 and not stdout:
            return f"ffuf failed (exit {code}): {stderr[:500]}"

        # ffuf -s prints one hit per line: '<word>                [Status: 200, Size: ...'
        hits = [l.strip() for l in stdout.strip().split("\n") if l.strip()]
        if not hits:
            return f"No hits from ffuf on {target}"

        lines = [f"ffuf hits for {target} ({len(hits)}):", ""]
        for h in hits[:100]:
            lines.append(f"  {h}")
        if len(hits) > 100:
            lines.append(f"  ... and {len(hits) - 100} more")
        if use_proxy:
            lines.append("\nAll requests routed through Burp proxy — check proxy history.")
        return "\n".join(lines)

    @mcp.tool()
    async def run_arjun(
        target: str,
        method: str = "GET",
        wordlist: str = "",
        stable: bool = False,
        delay: int = 0,
        use_proxy: bool = True,
        timeout: int = 600,
    ) -> str:
        """Discover hidden HTTP parameters with Arjun. Requires arjun installed.

        Arjun is the de-facto parameter discovery tool — finds params that
        backend code reads but documentation doesn't expose. Bug-bounty
        gold: hidden `debug=true`, `admin=1`, `internal_id=...` style.

        Args:
            target: Target URL
            method: GET / POST / JSON (Arjun-native modes)
            wordlist: Custom wordlist path. Empty = Arjun's built-in (~25k).
            stable: True for slower but more reliable detection (-t param)
            delay: Inter-request delay in seconds (SOC-quiet mode)
            use_proxy: Route through Burp proxy (default True)
            timeout: Max seconds (default 600)
        """
        if not _check_tool("arjun"):
            return (
                "Error: arjun not installed.\n"
                "  pip install arjun  OR  git clone https://github.com/s0md3v/Arjun"
            )
        cmd = ["arjun", "-u", target, "-m", method.upper()]
        if wordlist:
            cmd.extend(["-w", wordlist])
        if stable:
            cmd.append("--stable")
        if delay > 0:
            cmd.extend(["-d", str(delay)])
        if use_proxy:
            # Arjun supports raw socks/http proxy via env or --proxy
            cmd.extend(["--proxy", BURP_PROXY_URL])
        stdout, stderr, code = await _run_cmd(cmd, timeout)
        out = (stdout + "\n" + stderr).strip()
        if not out:
            return f"arjun produced no output (exit {code})"
        # Arjun output is fairly clean; surface the "parameter found" lines
        key_lines = [
            line.strip() for line in out.split("\n")
            if any(k in line for k in ("parameter", "Parameter", "valid parameter",
                                        "[+]", "[!]", "anomaly"))
        ]
        lines = [f"arjun for {target} ({len(key_lines)} hits):", ""]
        if key_lines:
            lines.extend(f"  {l[:200]}" for l in key_lines[:80])
        else:
            lines.append("  No hidden parameters found. Try a different wordlist or method=POST/JSON.")
        if use_proxy:
            lines.append("\nAll requests routed through Burp proxy.")
        return "\n".join(lines)
