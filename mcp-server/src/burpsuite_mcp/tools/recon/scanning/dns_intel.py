"""Fingerprint / probe intelligence: wafw00f, httpx."""

import os
import tempfile

from mcp.server.fastmcp import FastMCP

from .._common import _check_tool, _run_cmd, _USER_AGENT, BURP_PROXY_URL


def register(mcp: FastMCP):

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
        stdout, stderr, code = await _run_cmd(cmd, timeout, bypass_proxy=True)
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
