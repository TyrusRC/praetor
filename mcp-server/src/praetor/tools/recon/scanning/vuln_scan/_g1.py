import os
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP
from ._shared import (
    BURP_PROXY_URL,
    _USER_AGENT,
    _check_tool,
    _run_cmd,
    json,
    wrap_untrusted,
)

_NETWORK_PIVOT_TIMEOUT = 120  # bounded sub-timeout per tool, not run_assay's own


async def _network_pivot(target: str, scope_host: str) -> str:
    """Bounded nmap service scan + tlsx TLS check against target's host.
    Fail-open: either sub-scan erroring is reported, never raised."""
    host = urlparse(target if "://" in target else f"//{target}").hostname or target
    out = [f"--- Network/TLS pivot: {host} ---"]
    try:
        from praetor.tools.network.nmap import _format_scan, nmap_scan
        res = await nmap_scan(host, domain=scope_host or host, timeout=_NETWORK_PIVOT_TIMEOUT)
        out.append(_format_scan(res))
    except Exception as exc:  # noqa: BLE001 - this pivot never fails the web scan
        out.append(f"nmap pivot error: {exc}")
    try:
        from praetor.tools.recon_pd._impl import run_tlsx
        out.append(await run_tlsx([host], timeout=_NETWORK_PIVOT_TIMEOUT))
    except Exception as exc:  # noqa: BLE001
        out.append(f"tlsx pivot error: {exc}")
    return "\n".join(out)

# Nuclei template stores assay loads alongside its native detectors.
# PRAETOR_ASSAY_TEMPLATES (os.pathsep-separated dirs) overrides; otherwise the
# default nuclei store and the operator's custom-nuclei-templates clone are
# auto-included when present on disk.
_DEFAULT_TEMPLATE_DIRS = (
    "~/nuclei-templates",
    "~/.local/share/praetor/custom-nuclei-templates",
)


def _assay_template_dirs(extra: list[str] | None = None) -> list[str]:
    """Resolve the existing template dirs to hand assay (deduped), from
    PRAETOR_ASSAY_TEMPLATES or the default store + custom clone, plus `extra`."""
    env = os.getenv("PRAETOR_ASSAY_TEMPLATES", "").strip()
    candidates = (env.split(os.pathsep) if env else list(_DEFAULT_TEMPLATE_DIRS))
    candidates += list(extra or [])
    dirs: list[str] = []
    for c in candidates:
        c = os.path.expanduser(c.strip())
        if c and os.path.isdir(c) and c not in dirs:
            dirs.append(c)
    return dirs


def register(mcp: FastMCP):
    @mcp.tool()
    async def run_assay(  # cost: expensive (native context-aware web scan)
        target: str,
        profile: str = "normal",
        rate: float = 0.0,
        scope_host: str = "",
        templates: list[str] | None = None,
        use_proxy: bool = True,
        timeout: int = 600,
        auto_network_check: bool = False,
        policy: str = "",
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
            templates: Extra nuclei template dirs/files to load. The default nuclei
                store (~/nuclei-templates) and the custom-nuclei-templates clone
                (~/.local/share/praetor/custom-nuclei-templates) are auto-included
                when present; PRAETOR_ASSAY_TEMPLATES (os.pathsep dirs) overrides.
            use_proxy: Route through Burp proxy (default True)
            timeout: Max seconds (default 600)
            auto_network_check: Also run a bounded nmap service scan + tlsx TLS-
                config check against target's host and append the results, so
                a web scan surfaces the underlying host's open ports/TLS
                config in the same call instead of requiring a separate manual
                step. Off by default (a separate, slower, non-Burp-proxied
                lane); bounded to a 120s sub-timeout each so it can't balloon
                this call's overall runtime. Findings here are NOT routed
                through Haruspex — the trained adapters are AD/cloud-IaC
                phrasing, not raw nmap/TLS output, so forcing that match would
                be an unvalidated guess, not a real fit.
            policy: Name of a policy saved with save_scan_policy — when given,
                its profile/scope_host/rate/templates/use_proxy/timeout/
                auto_network_check REPLACE the values above for this call (the
                named-profile pattern: save once, run by name across targets).
                Pass '' and the args directly for a one-off call; don't mix a
                policy name with explicit overrides in the same call.
        """
        if policy:
            from .scan_policy import load_scan_policy
            pol = load_scan_policy(policy)
            if not pol:
                return f"Error: no scan policy named '{policy}' — list_scan_policies() to see what's saved."
            profile = pol.get("profile", profile)
            scope_host = pol.get("scope_host", scope_host)
            rate = pol.get("rate", rate)
            templates = pol.get("templates") or templates
            use_proxy = pol.get("use_proxy", use_proxy)
            timeout = pol.get("timeout", timeout)
            auto_network_check = pol.get("auto_network_check", auto_network_check)

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
        for tdir in _assay_template_dirs(templates):
            cmd.extend(["--templates", tdir])
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

        if auto_network_check:
            lines.append("")
            lines.append(await _network_pivot(target, scope_host))

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
