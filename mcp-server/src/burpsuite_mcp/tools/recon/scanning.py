"""Vulnerability scanning tools: nuclei, dalfox, ffuf, sqlmap."""

import json
import os

from mcp.server.fastmcp import FastMCP

from ._common import _check_tool, _run_cmd, _USER_AGENT, BURP_PROXY_URL


def register(mcp: FastMCP):

    @mcp.tool()
    async def run_nuclei(  # cost: expensive (external template-based scan)
        target: str,
        templates: str = "",
        tags: str = "",
        severity: str = "",
        auto_scan: bool = False,
        dast: bool = False,
        use_proxy: bool = True,
        timeout: int = 600,
    ) -> str:
        """Run nuclei vulnerability scanner against a target through Burp proxy. Requires nuclei installed.

        Args:
            target: Target URL
            templates: Template path filter
            tags: Tag filter (comma-separated)
            severity: Severity filter (comma-separated)
            auto_scan: Auto-detect tech and run matching templates
            dast: Enable DAST fuzzing mode
            use_proxy: Route through Burp proxy (default True)
            timeout: Max seconds (default 600)
        """
        if not _check_tool("nuclei"):
            return "Error: nuclei not installed. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

        # Auto-download templates if missing (first run)
        templates_dir = os.path.expanduser("~/nuclei-templates")
        if not os.path.isdir(templates_dir) or len(os.listdir(templates_dir)) < 5:
            await _run_cmd(["nuclei", "-ut"], timeout=120)

        cmd = ["nuclei", "-u", target, "-silent", "-no-color", "-jsonl",
               "-H", f"User-Agent: {_USER_AGENT}",
               "-rl", "100", "-c", "25",       # rate limit + concurrency
               "-bs", "10",                     # bulk size per template
               "-timeout", "10",                # per-request timeout
               "-retries", "1",
               "-mhe", "10",                    # skip host after 10 errors
               "-duc"]                          # disable update check (templates already downloaded)
        if templates:
            cmd.extend(["-t", templates])
        if tags:
            cmd.extend(["-tags", tags])
        if auto_scan and not templates and not tags:
            cmd.append("-as")                   # automatic scan based on tech detection
        if dast:
            cmd.append("-dast")
        if severity:
            cmd.extend(["-severity", severity])
        if use_proxy:
            # Route through Burp. Nuclei v3 removed -insecure/-tls-skip-verify,
            # so HTTPS through Burp's MITM cert only works if the user installed
            # Burp CA into the system trust store (cacert.der from Burp ->
            # Windows Cert Manager / Keychain). If not, HTTPS scans will emit
            # TLS errors in nuclei output — visible to the hunter.
            cmd.extend(["-proxy", BURP_PROXY_URL])

        stdout, stderr, code = await _run_cmd(cmd, timeout)

        if code != 0 and not stdout:
            return f"nuclei failed (exit {code}): {stderr[:500]}"

        findings = []
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
                findings.append({
                    "template": finding.get("template-id", ""),
                    "name": finding.get("info", {}).get("name", ""),
                    "severity": finding.get("info", {}).get("severity", ""),
                    "matched": finding.get("matched-at", ""),
                    "type": finding.get("type", ""),
                })
            except json.JSONDecodeError:
                if line:
                    findings.append({"raw": line})

        if not findings:
            return f"No findings from nuclei scan of {target}"

        lines = [f"Nuclei findings for {target} ({len(findings)}):", ""]
        for f in findings[:50]:
            if "raw" in f:
                lines.append(f"  {f['raw']}")
            else:
                sev = f.get("severity", "?").upper()
                lines.append(f"  [{sev}] {f.get('name', f.get('template', '?'))}")
                if f.get("matched"):
                    lines.append(f"       → {f['matched']}")

        if len(findings) > 50:
            lines.append(f"  ... and {len(findings) - 50} more")

        return "\n".join(lines)

    @mcp.tool()
    async def run_dalfox(
        target: str,
        blind_xss_url: str = "",
        method: str = "GET",
        data: str = "",
        cookie: str = "",
        use_proxy: bool = True,
        timeout: int = 300,
    ) -> str:
        """Run dalfox XSS scanner against a URL through Burp proxy. Requires dalfox installed.

        Args:
            target: Target URL with parameters
            blind_xss_url: Callback URL for blind XSS detection
            method: HTTP method
            data: POST body
            cookie: Cookie header
            use_proxy: Route through Burp proxy (default True)
            timeout: Max seconds (default 300)
        """
        if not _check_tool("dalfox"):
            return "Error: dalfox not installed. Install: go install -v github.com/hahwul/dalfox/v2@latest"

        cmd = ["dalfox", "url", target, "--silence", "--format", "plain",
               "-H", f"User-Agent: {_USER_AGENT}"]
        if method.upper() != "GET":
            cmd.extend(["-X", method.upper()])
        if data:
            cmd.extend(["-d", data])
        if cookie:
            cmd.extend(["-C", cookie])
        if blind_xss_url:
            cmd.extend(["-b", blind_xss_url])
        if use_proxy:
            # dalfox passes -proxy for HTTP proxy; skip-bav reduces preflight noise
            cmd.extend(["--proxy", BURP_PROXY_URL, "--skip-bav"])

        stdout, stderr, code = await _run_cmd(cmd, timeout)
        out = stdout.strip()
        if not out:
            return f"dalfox: no XSS found on {target} (exit {code})"

        hits = [l for l in out.split("\n") if l.startswith("[POC]") or l.startswith("[V]")]
        lines = [f"dalfox results for {target}:"]
        lines.extend(hits[:50] if hits else ["  (see raw output)"])
        if not hits:
            lines.append(out[:2000])
        if use_proxy:
            lines.append("\nAll requests routed through Burp proxy — check proxy history.")
        return "\n".join(lines)

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
