from mcp.server.fastmcp import FastMCP
from ._shared import (
    BURP_PROXY_URL,
    _USER_AGENT,
    _check_tool,
    _run_cmd,
    json,
    wrap_untrusted,
)


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
        import os
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

        return wrap_untrusted("\n".join(lines), source="nuclei")

    @mcp.tool()
    async def run_assay(  # cost: expensive (native context-aware web scan)
        target: str,
        profile: str = "normal",
        rate: float = 0.0,
        scope_host: str = "",
        use_proxy: bool = True,
        timeout: int = 600,
    ) -> str:
        """Run the assay native web scanner against a target through Burp proxy. Requires assay installed.

        assay is praetor's default web-scan engine. It runs ~100 context-aware
        native detectors plus a Nuclei-compatible template engine and a headless
        two-identity crawl, and maps each finding to WSTG / OWASP Top 10 / API
        Top 10 / CWE with a CVSS vector. It replaces the nuclei external sweep
        (nuclei stays available as a fallback). Findings ingest into findings.json
        via import_scan_results (format 'assay').

        Args:
            target: Target URL
            profile: quick | normal | thorough | passive (default normal)
            rate: Cap outbound requests per second (0 = unlimited)
            scope_host: Restrict traffic to these hosts (comma-separated; '*.x.com' wildcard). Empty = no host restriction
            use_proxy: Route through Burp proxy (default True)
            timeout: Max seconds (default 600)
        """
        if not _check_tool("assay"):
            return ("Error: assay not installed. Build it: "
                    "cd <assay repo> && go build -o ~/go/bin/assay ./cmd/assay")

        cmd = ["assay", "scan", target, "--json", "--timeout", f"{timeout}s"]
        if profile:
            cmd.extend(["--profile", profile])
        if rate and rate > 0:
            cmd.extend(["--rate", str(rate)])
        if scope_host:
            for h in scope_host.split(","):
                h = h.strip()
                if h:
                    cmd.extend(["--scope-host", h])
        if use_proxy:
            # assay routes through Burp and trusts Burp's MITM cert with -k.
            cmd.extend(["--proxy", BURP_PROXY_URL, "-k"])

        # Give the subprocess a little longer than assay's own scan timeout so
        # the process is not killed before it writes its report.
        stdout, stderr, code = await _run_cmd(cmd, timeout + 30, bypass_proxy=not use_proxy)

        if not stdout.strip():
            return f"assay failed (exit {code}): {stderr[:500]}"
        try:
            report = json.loads(stdout)
        except json.JSONDecodeError:
            return f"assay produced no parseable JSON (exit {code}). stderr: {stderr[:300]}"

        scan_result = report.get("scan_result") or {}
        findings = scan_result.get("findings") or []
        if not findings:
            return f"No findings from assay scan of {target}"

        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: order.get(str(f.get("severity", "")).lower(), 5))

        lines = [f"assay findings for {target} ({len(findings)}):", ""]
        for f in findings[:50]:
            sev = str(f.get("severity", "?")).upper()
            name = f.get("title") or f.get("type") or "?"
            lines.append(f"  [{sev}] {name}")
            loc = f.get("url", "")
            if f.get("parameter"):
                loc = f"{loc} (param: {f['parameter']})"
            if loc:
                lines.append(f"       → {loc}")
            cwe = ",".join(f.get("cwe") or [])
            if cwe:
                lines.append(f"       {cwe}")
        if len(findings) > 50:
            lines.append(f"  ... and {len(findings) - 50} more")
        lines.append("")
        lines.append("Verify, then ingest into findings.json with import_scan_results (format 'assay').")

        return wrap_untrusted("\n".join(lines), source="assay")

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
        return wrap_untrusted("\n".join(lines), source="dalfox")
