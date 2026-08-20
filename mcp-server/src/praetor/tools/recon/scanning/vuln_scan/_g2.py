from mcp.server.fastmcp import FastMCP
from ._shared import (
    BURP_PROXY_URL,
    _check_tool,
    _run_cmd,
)


def register(mcp: FastMCP):
    @mcp.tool()
    async def run_sqlmap(
        target: str,
        data: str = "",
        cookie: str = "",
        method: str = "GET",
        level: int = 1,
        risk: int = 1,
        technique: str = "BEUSTQ",
        batch: bool = True,
        use_proxy: bool = True,
        timeout: int = 600,
    ) -> str:
        """Run sqlmap SQL injection scanner against a target URL. Requires sqlmap installed.

        Args:
            target: Target URL with injectable parameter
            data: POST body (auto-switches to POST)
            cookie: Cookie header
            method: HTTP method (default GET)
            level: Test level 1-5 (default 1)
            risk: Risk level 1-3 (default 1)
            technique: Technique flags (B=Boolean, E=Error, U=UNION, S=Stacked, T=Time, Q=Inline)
            batch: Non-interactive mode (default True)
            use_proxy: Route through Burp proxy (default True)
            timeout: Max seconds (default 600)
        """
        if not _check_tool("sqlmap"):
            return (
                "Error: sqlmap not installed.\n"
                "  Windows: scoop install sqlmap\n"
                "  Linux/macOS: pip install sqlmap (or git clone https://github.com/sqlmapproject/sqlmap)"
            )

        cmd = [
            "sqlmap", "-u", target,
            "--level", str(max(1, min(5, level))),
            "--risk", str(max(1, min(3, risk))),
            "--technique", technique,
            "--threads", "4",
            "--disable-coloring",
        ]
        if data:
            cmd.extend(["--data", data])
        elif method.upper() != "GET":
            cmd.extend(["--method", method.upper()])
        if cookie:
            cmd.extend(["--cookie", cookie])
        if batch:
            cmd.append("--batch")
        if use_proxy:
            cmd.extend(["--proxy", BURP_PROXY_URL])

        stdout, stderr, code = await _run_cmd(cmd, timeout)
        out = (stdout + "\n" + stderr).strip()
        if not out:
            return f"sqlmap produced no output (exit {code})"

        # Extract the most informative lines
        key_lines = []
        for line in out.split("\n"):
            if any(k in line for k in ("vulnerable", "injectable", "Payload:", "Parameter:", "Type:", "Title:",
                                        "sqlmap identified", "back-end DBMS", "current user", "current database",
                                        "available databases", "[CRITICAL]", "[WARNING]", "[ERROR]")):
                key_lines.append(line.strip())

        lines = [f"sqlmap findings for {target} ({len(key_lines)}):", ""]
        if key_lines:
            for l in key_lines[:80]:
                lines.append(f"  {l}")
        else:
            lines.append(f"  No injection found at level={level} risk={risk}. Try higher level/risk or more techniques.")

        if use_proxy:
            lines.append("\nAll requests routed through Burp proxy — check proxy history.")
        return "\n".join(lines)

    @mcp.tool()
    async def run_wpscan(
        target: str,
        api_token: str = "",
        enumerate: str = "vp,vt,u1-5",
        random_user_agent: bool = True,
        use_proxy: bool = True,
        timeout: int = 600,
    ) -> str:
        """Run WPScan against a WordPress target. Requires wpscan installed.

        WordPress is huge bug-bounty surface; nuclei templates miss
        plugin-specific bugs. WPScan needs an api_token for the WordPress
        Vulnerability DB lookup (free 25/day at wpvulndb.com / wpscan.com).
        Without a token it still enumerates but won't get CVE counts.

        Args:
            target: Target URL (auto-detects /wp-login.php / wp-content)
            api_token: WPScan API token (https://wpscan.com — 25 free requests/day)
            enumerate: vp (vulnerable plugins), vt (vulnerable themes), u (users 1-5),
                p (all plugins), t (all themes), tt (timthumbs), cb (config backups)
            random_user_agent: True for SOC-quieter UA rotation
            use_proxy: Route through Burp proxy (default True)
            timeout: Max seconds (default 600)
        """
        if not _check_tool("wpscan"):
            return (
                "Error: wpscan not installed.\n"
                "  gem install wpscan  OR  apt install wpscan  OR\n"
                "  docker run -it --rm wpscanteam/wpscan --url TARGET"
            )
        cmd = [
            "wpscan", "--url", target,
            "--enumerate", enumerate,
            "--disable-tls-checks",
            "--no-banner",
            "--format", "cli-no-color",
        ]
        if api_token:
            cmd.extend(["--api-token", api_token])
        if random_user_agent:
            cmd.append("--random-user-agent")
        if use_proxy:
            cmd.extend(["--proxy", BURP_PROXY_URL, "--proxy-auth", ""])
        stdout, stderr, code = await _run_cmd(cmd, timeout)
        out = (stdout + "\n" + stderr).strip()
        if not out:
            return f"wpscan produced no output (exit {code})"
        # Pull out vulns + plugin/theme versions
        key_lines = []
        for line in out.split("\n"):
            l = line.rstrip()
            if any(k in l for k in (
                "[!]", "[+]", "vulnerable", "Title:", "Fixed in:", "References:",
                "Version:", "WordPress version", "found:", "Theme name:",
                "Plugin", "CVE-", "WPVDB",
            )):
                key_lines.append(l)
        lines = [f"wpscan for {target} ({len(key_lines)} significant lines):", ""]
        if key_lines:
            lines.extend(f"  {l[:200]}" for l in key_lines[:120])
        else:
            lines.append("  No findings. Re-check enumerate flags or target.")
        if not api_token:
            lines.append("")
            lines.append("Note: no api_token passed; CVE lookups skipped. Free token: https://wpscan.com")
        if use_proxy:
            lines.append("\nAll requests routed through Burp proxy.")
        return "\n".join(lines)

    @mcp.tool()
    async def run_nikto(
        target: str,
        tuning: str = "",
        port: int = 0,
        use_proxy: bool = True,
        timeout: int = 900,
    ) -> str:
        """Classic web-server scanner. Requires nikto installed.

        Catches outdated server software / default files / CGI bugs that
        nuclei templates often miss. Loud by default — SIEMs will see this.
        Operator owns the noise call.

        Args:
            target: Target URL or host
            tuning: Test tuning string (e.g. '123bde' = files+misconfig+disclosure
                +shell+default). Empty = all (loudest).
            port: Override port (default 0 = derive from URL)
            use_proxy: Route through Burp proxy (default True)
            timeout: Max seconds (default 900)
        """
        if not _check_tool("nikto"):
            return (
                "Error: nikto not installed.\n"
                "  apt install nikto  OR  brew install nikto  OR\n"
                "  git clone https://github.com/sullo/nikto"
            )
        cmd = ["nikto", "-h", target, "-Format", "txt", "-ask", "no", "-nointeractive"]
        if tuning:
            cmd.extend(["-Tuning", tuning])
        if port > 0:
            cmd.extend(["-port", str(port)])
        if use_proxy:
            # nikto uses USEPROXY config; we set via -useproxy + env
            cmd.extend(["-useproxy", BURP_PROXY_URL])
        stdout, stderr, code = await _run_cmd(cmd, timeout)
        out = (stdout + "\n" + stderr).strip()
        if not out:
            return f"nikto produced no output (exit {code})"
        # Surface the "+" findings lines (nikto's hit indicator)
        hits = [line.strip() for line in out.split("\n") if line.strip().startswith("+")]
        lines = [f"nikto for {target} ({len(hits)} findings):", ""]
        if hits:
            for h in hits[:120]:
                lines.append(f"  {h[:300]}")
        else:
            lines.append("  (no '+' findings — server may be hardened or behind WAF)")
        lines.append("")
        lines.append("Warning: nikto is loud. Expect SIEM/IDS hits if blue team is watching.")
        if use_proxy:
            lines.append("All requests routed through Burp proxy.")
        return "\n".join(lines)
