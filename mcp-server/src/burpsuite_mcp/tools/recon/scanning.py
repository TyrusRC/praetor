"""Vulnerability scanning + external-tool wrappers.

Owned tools (in run order through a typical engagement):
  recon:           amass, httpx, gau, wafw00f
  param discovery: arjun
  app-class scan:  nuclei, nikto, wpscan, dalfox, ffuf, sqlmap, commix
  ssti detection:  native test_ssti (see tools/vuln/test_ssti.py)
  exploit gen:     ysoserial gadget generator
  jwt:             jwt_tool

Every wrapper routes through Burp proxy by default (use_proxy=True). The
common pattern: _check_tool() gate -> build argv -> _run_cmd() -> filter
output to operator-relevant lines.
"""

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
        severity: str = "medium,high,critical",
        auto_scan: bool = False,
        dast: bool = False,
        use_proxy: bool = True,
        timeout: int = 600,
    ) -> str:
        """Run nuclei vulnerability scanner against a target through Burp proxy. Requires nuclei installed.

        Default severity is `medium,high,critical` — skips info/low templates
        which are usually false-positive-heavy and slow the scan. Pass
        severity='info,low,medium,high,critical' for a full sweep, or
        severity='critical' for a fast triage pass.

        Args:
            target: Target URL
            templates: Template path filter
            tags: Tag filter (comma-separated)
            severity: Severity filter (default 'medium,high,critical'; pass empty string '' or 'info,low,medium,high,critical' for full sweep)
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
                # Silently drop non-JSON lines (nuclei progress / banner /
                # warning chatter). Previously surfaced as raw entries which
                # padded outputs with 100+ token noise per scan.
                continue

        if not findings:
            return f"No findings from nuclei scan of {target}"

        lines = [f"Nuclei findings for {target} ({len(findings)}):", ""]
        for f in findings[:50]:
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
    async def run_commix(
        target: str,
        data: str = "",
        cookie: str = "",
        parameter: str = "",
        level: int = 1,
        technique: str = "",
        batch: bool = True,
        use_proxy: bool = True,
        timeout: int = 600,
    ) -> str:
        """Run commix command-injection scanner against a target. Requires commix installed.

        commix is the sqlmap-equivalent for OS-command injection — confirms
        injection AND offers `--os-shell` interactive mode. This wrapper runs
        DETECTION + confirmation only (no shell spawn — operator opts in
        manually). Routes through Burp proxy by default.

        Args:
            target: Target URL (with vulnerable parameter)
            data: POST body (auto-switches to POST)
            cookie: Cookie header
            parameter: Restrict tests to a single parameter (-p)
            level: Test level 1-3 (default 1)
            technique: c=classic, e=eval, t=time, f=file. Empty = all.
            batch: Non-interactive (default True)
            use_proxy: Route through Burp proxy (default True)
            timeout: Max seconds (default 600)
        """
        if not _check_tool("commix"):
            return (
                "Error: commix not installed.\n"
                "  pip install commix  OR  git clone https://github.com/commixproject/commix\n"
                "  https://github.com/commixproject/commix"
            )

        cmd = [
            "commix", "--url", target,
            "--level", str(max(1, min(3, level))),
            "--skip-waf",
        ]
        if data:
            cmd.extend(["--data", data])
        if cookie:
            cmd.extend(["--cookie", cookie])
        if parameter:
            cmd.extend(["-p", parameter])
        if technique:
            cmd.extend(["--technique", technique])
        if batch:
            cmd.append("--batch")
        if use_proxy:
            cmd.extend(["--proxy", BURP_PROXY_URL])

        stdout, stderr, code = await _run_cmd(cmd, timeout)
        out = (stdout + "\n" + stderr).strip()
        if not out:
            return f"commix produced no output (exit {code})"

        key_lines = []
        for line in out.split("\n"):
            if any(k in line for k in (
                "injectable", "vulnerable", "injection", "Type:", "Technique:",
                "Payload:", "Parameter:", "[+] ", "[!] ", "[CRITICAL]", "[ERROR]",
            )):
                key_lines.append(line.strip())

        lines = [f"commix findings for {target} ({len(key_lines)}):", ""]
        if key_lines:
            for l in key_lines[:80]:
                lines.append(f"  {l}")
        else:
            lines.append(f"  No injection found at level={level}. Try higher level or specify technique=eft.")

        lines.append("")
        lines.append("Next steps:")
        lines.append("  - Confirm with: confirm_rce(endpoint=TARGET, parameter=PARAM, command='id')")
        lines.append("  - For interactive shell (operator-supervised, SOC-loud): re-run with `--os-shell` via curl_request/send_raw_request")
        if use_proxy:
            lines.append("All requests routed through Burp proxy — check proxy history.")
        return "\n".join(lines)

    @mcp.tool()
    async def generate_deserialization_gadget(
        language: str,
        gadget: str = "",
        command: str = "id",
        encode: str = "base64",
        timeout: int = 60,
    ) -> str:
        """Generate a deserialization gadget chain via ysoserial / ysoserial.net.

        Payload GENERATOR only — does NOT send. Operator pipes the output into
        curl_request / send_raw_request / session_request via the vulnerable
        sink (Java ObjectInputStream, .NET BinaryFormatter, etc.). Per Rule 5
        and the confirm_* safety contract, `command` is filtered against the
        HARD_DESTRUCTIVE denylist (rm -rf, useradd, DROP TABLE blocked).

        Args:
            language: java | dotnet
            gadget: Java: CommonsCollections1..7, Spring1, Spring2, ROME,
                Hibernate1..2, etc. .NET: TypeConfuseDelegate,
                ActivitySurrogateSelector, WindowsIdentity, etc.
                Empty = print available gadget list.
            command: Command for the gadget to run on deserialize. Default 'id'.
                HARD_DESTRUCTIVE patterns refused at tool layer.
            encode: base64 | raw | hex (default base64)
            timeout: Max seconds for the generator process (default 60)
        """
        from burpsuite_mcp.tools.exploit._safety import (
            soc_loud_warning,
            validate_payload,
        )

        lang = language.lower().strip()
        if lang not in {"java", "dotnet", ".net"}:
            return f"Unknown language '{language}'. Use 'java' or 'dotnet'."
        if lang == ".net":
            lang = "dotnet"

        ok, why = validate_payload(command, vuln_type="deserialization")
        if not ok:
            return f"REFUSED: {why}"
        warning = soc_loud_warning(command)

        if lang == "java":
            tool = "ysoserial"
            jar = "ysoserial.jar"
            if not _check_tool("ysoserial") and not _check_tool("java"):
                return (
                    "Error: ysoserial not installed.\n"
                    "  Download: https://github.com/frohoff/ysoserial/releases\n"
                    "  Then alias `ysoserial='java -jar /path/to/ysoserial.jar'`"
                )
            if not gadget:
                cmd = ["ysoserial"] if _check_tool("ysoserial") else ["java", "-jar", jar]
            else:
                base = ["ysoserial"] if _check_tool("ysoserial") else ["java", "-jar", jar]
                cmd = base + [gadget, command]
        else:  # dotnet
            if not _check_tool("ysoserial.exe") and not _check_tool("ysoserial.net"):
                return (
                    "Error: ysoserial.net not installed.\n"
                    "  Download: https://github.com/pwntester/ysoserial.net/releases\n"
                    "  Add to PATH as `ysoserial.exe` (Windows) or `ysoserial.net` (Linux wrapper)."
                )
            tool = "ysoserial.exe" if _check_tool("ysoserial.exe") else "ysoserial.net"
            if not gadget:
                cmd = [tool]
            else:
                cmd = [tool, "-g", gadget, "-c", command, "-f", "BinaryFormatter"]

        stdout, stderr, code = await _run_cmd(cmd, timeout)
        out = (stdout + "\n" + stderr).strip()
        if not out:
            return f"{tool} produced no output (exit {code})"

        # If no gadget specified, return the available-gadgets list verbatim
        if not gadget:
            lines = [f"{tool} available gadgets:", ""]
            for line in out.splitlines()[:80]:
                lines.append(f"  {line}")
            lines.append("")
            lines.append(f"Re-run with gadget=<name> command='id' to generate.")
            return "\n".join(lines)

        # Otherwise the output IS the raw serialized payload. Encode.
        raw_bytes = stdout.encode("latin-1", errors="ignore") if isinstance(stdout, str) else stdout
        import base64 as _b64
        if encode == "base64":
            payload_str = _b64.b64encode(raw_bytes).decode()
        elif encode == "hex":
            payload_str = raw_bytes.hex()
        else:
            payload_str = stdout  # raw

        lines = [
            f"{tool} gadget={gadget} command={command!r} ({len(raw_bytes)} bytes, {encode}):",
        ]
        if warning:
            lines.append(f"  warning: {warning}")
        lines.append("")
        lines.append("Payload:")
        # Wrap at 100 chars/line for readability
        for i in range(0, len(payload_str), 100):
            lines.append(payload_str[i:i + 100])
        lines.append("")
        lines.append("Delivery:")
        lines.append("  - Java: POST as body to ObjectInputStream sink, or stuff into a")
        lines.append("    Cookie / Header value the app deserialises")
        lines.append("  - .NET: BinaryFormatter / NetDataContractSerializer / LosFormatter sink")
        lines.append("  - Verify exec via confirm_rce() with use_collaborator=True if response is opaque")
        if stderr:
            lines.append("")
            lines.append(f"stderr (first 400 chars): {stderr[:400]}")
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

    # ─── Phase-1 external-tool wrappers ────────────────────────────────────

    @mcp.tool()
    async def run_wafw00f(
        target: str,
        find_all: bool = False,
        timeout: int = 120,
    ) -> str:
        """Fingerprint WAF / CDN in front of a target. Requires wafw00f installed.

        Knowing the WAF before sending real probes lets the operator pick the
        right encoding bypass set (see craft-payload.md). Direct connect — does
        not route through Burp because wafw00f sends a fixed probe set the
        operator doesn't need archived.

        Args:
            target: Target URL (https://example.com)
            find_all: True to keep probing after first match (lists every WAF)
            timeout: Max seconds (default 120)
        """
        if not _check_tool("wafw00f"):
            return (
                "Error: wafw00f not installed.\n"
                "  pip install wafw00f  OR  git clone https://github.com/EnableSecurity/wafw00f"
            )
        cmd = ["wafw00f", target]
        if find_all:
            cmd.append("-a")
        stdout, stderr, code = await _run_cmd(cmd, timeout)
        out = (stdout + "\n" + stderr).strip()
        if not out:
            return f"wafw00f produced no output (exit {code})"
        # Extract the interesting lines: "is behind X WAF" / "No WAF detected"
        key_lines = [
            line.strip() for line in out.split("\n")
            if any(k in line for k in ("WAF", "is behind", "No WAF", "Number of requests"))
        ]
        lines = [f"wafw00f for {target}:", ""]
        if key_lines:
            lines.extend(f"  {l}" for l in key_lines[:30])
        else:
            lines.append("  (no detection markers in output)")
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

    @mcp.tool()
    async def run_amass(
        domain: str,
        mode: str = "enum",
        passive: bool = True,
        timeout: int = 900,
    ) -> str:
        """Deep subdomain enumeration via Amass. Requires amass installed.

        Complements subfinder: subfinder is fast and passive, Amass is slower
        but more thorough (53+ data sources passive, brute + zone-walk active).
        Use Amass when subfinder's surface is too thin.

        Args:
            domain: Target apex domain (example.com)
            mode: enum (subdomain discovery) | intel (org/IP intelligence)
            passive: True = sources-only (quiet). False = active probing too.
            timeout: Max seconds (default 900 — Amass is slow)
        """
        if not _check_tool("amass"):
            return (
                "Error: amass not installed.\n"
                "  go install -v github.com/owasp-amass/amass/v4/...@master  OR\n"
                "  snap install amass  OR  brew install amass"
            )
        from ._common import _sanitize_domain
        try:
            domain = _sanitize_domain(domain)
        except ValueError as e:
            return f"Error: {e}"
        cmd = ["amass", mode, "-d", domain, "-nocolor"]
        if passive:
            cmd.append("-passive")
        stdout, stderr, code = await _run_cmd(cmd, timeout)
        out = (stdout + "\n" + stderr).strip()
        if not out:
            return f"amass produced no output (exit {code})"
        # Subdomain lines look like `example.com (FQDN) --> a_record --> 1.2.3.4`
        hosts = set()
        for line in out.split("\n"):
            stripped = line.strip()
            if domain in stripped:
                # Try to pull the FQDN at start of line
                first = stripped.split()[0].rstrip(",")
                if first.endswith(domain) or first == domain:
                    hosts.add(first)
        lines = [f"amass {mode} for {domain} ({len(hosts)} hosts):", ""]
        for h in sorted(hosts)[:200]:
            lines.append(f"  {h}")
        if len(hosts) > 200:
            lines.append(f"  ... +{len(hosts) - 200} more")
        return "\n".join(lines)

    @mcp.tool()
    async def run_httpx(
        targets: str,
        tech_detect: bool = True,
        status_code: bool = True,
        content_length: bool = True,
        title: bool = True,
        follow_redirects: bool = True,
        use_proxy: bool = True,
        threads: int = 50,
        timeout: int = 300,
    ) -> str:
        """Probe a list of URLs with ProjectDiscovery httpx (uses wappalyzergo for tech detect).

        Fast multi-purpose HTTP toolkit. `tech_detect=True` enables the
        wappalyzergo-based fingerprinter that detects 1500+ technologies with
        version extraction — feed the output into `lookup_cve(product=...)`
        or `map_tech_to_cves(target=...)` for CVE intelligence.

        Args:
            targets: Newline-separated URLs OR single URL OR file path (one per line)
            tech_detect: Enable wappalyzergo tech detection (default True)
            status_code: Show status code (default True)
            content_length: Show response length (default True)
            title: Show <title> (default True)
            follow_redirects: Follow 30x (default True)
            use_proxy: Route through Burp proxy (default True)
            threads: Concurrency (default 50, max 200)
            timeout: Max seconds (default 300)
        """
        if not _check_tool("httpx"):
            return (
                "Error: httpx (ProjectDiscovery) not installed.\n"
                "  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
                "  NOT the python httpx library — that's a different httpx."
            )

        # Accept either a literal list or a file path
        targets = targets.strip()
        import tempfile
        if "\n" in targets or "," in targets:
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            for t in targets.replace(",", "\n").splitlines():
                t = t.strip()
                if t:
                    tmp.write(t + "\n")
            tmp.close()
            input_arg = ["-l", tmp.name]
        elif os.path.isfile(targets):
            input_arg = ["-l", targets]
        else:
            input_arg = ["-u", targets]

        cmd = ["httpx", *input_arg,
               "-silent", "-no-color",
               "-threads", str(max(1, min(threads, 200))),
               "-timeout", "10",
               "-retries", "1",
               "-H", f"User-Agent: {_USER_AGENT}"]
        if tech_detect:
            cmd.append("-tech-detect")
        if status_code:
            cmd.append("-status-code")
        if content_length:
            cmd.append("-content-length")
        if title:
            cmd.append("-title")
        if follow_redirects:
            cmd.append("-follow-redirects")
        if use_proxy:
            cmd.extend(["-http-proxy", BURP_PROXY_URL])

        stdout, stderr, code = await _run_cmd(cmd, timeout)
        out = stdout.strip()
        if not out:
            return f"httpx produced no output (exit {code}){' — ' + stderr[:200] if stderr else ''}"

        lines = out.splitlines()
        header = [
            f"httpx probed ({len(lines)} live hosts):",
        ]
        if tech_detect:
            header.append("  (tech detection via wappalyzergo)")
        result = header + [""]
        for line in lines[:300]:
            result.append(f"  {line}")
        if len(lines) > 300:
            result.append(f"  ... +{len(lines) - 300} more")
        if tech_detect:
            result.append("")
            result.append("Pipeline next step: map_tech_to_cves(target=<host>) to chain "
                          "detected tech into Shodan CVEDB lookups + save to .burp-intel/.")
        if use_proxy:
            result.append("\nAll requests routed through Burp proxy.")
        return "\n".join(result)

    @mcp.tool()
    async def run_gau(
        domain: str,
        providers: str = "wayback,otx,urlscan,commoncrawl",
        subdomains: bool = True,
        timeout: int = 300,
    ) -> str:
        """Aggregate URLs across Wayback Machine, AlienVault OTX, URLScan, Common Crawl.

        Broader than our `fetch_wayback_urls` (single-source). Useful for
        finding archived endpoints / parameters that no longer appear in the
        live app. Direct connect — providers are public archives, no point
        proxying through Burp.

        Args:
            domain: Target apex domain (example.com)
            providers: Comma-separated: wayback / otx / urlscan / commoncrawl
            subdomains: True to include subdomain URLs in aggregation
            timeout: Max seconds (default 300)
        """
        if not _check_tool("gau"):
            return (
                "Error: gau not installed.\n"
                "  go install github.com/lc/gau/v2/cmd/gau@latest"
            )
        from ._common import _sanitize_domain
        try:
            domain = _sanitize_domain(domain)
        except ValueError as e:
            return f"Error: {e}"
        cmd = ["gau", domain, "--providers", providers, "--threads", "10"]
        if subdomains:
            cmd.append("--subs")
        stdout, stderr, code = await _run_cmd(cmd, timeout)
        out = stdout.strip()
        if not out:
            return f"gau produced no output (exit {code}). Verify providers and connectivity."
        urls = [u for u in out.split("\n") if u.strip()]
        # Dedupe and sort for readability
        urls = sorted(set(urls))
        lines = [f"gau for {domain} ({len(urls)} unique URLs):", ""]
        for u in urls[:400]:
            lines.append(f"  {u}")
        if len(urls) > 400:
            lines.append(f"  ... +{len(urls) - 400} more")
        lines.append("")
        lines.append("Next: feed into smart_analyze / extract_links / auto_probe for testing.")
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

    # run_jwt_tool removed — superseded by native forge_jwt + crack_jwt_secret
    # which cover the same attack classes (alg=none, HS confusion, kid inject,
    # claim swap, jwk embed, HS dictionary crack) with no external install.
