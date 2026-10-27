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

_NETWORK_PIVOT_TIMEOUT = 120  # bounded sub-timeout per tool, not run_vigil's own


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

# Nuclei template stores vigil loads alongside its native detectors.
# PRAETOR_VIGIL_TEMPLATES (os.pathsep-separated dirs) overrides; otherwise the
# default nuclei store and the operator's custom-nuclei-templates clone are
# auto-included when present on disk.
_DEFAULT_TEMPLATE_DIRS = (
    "~/.local/nuclei-templates",
    "~/nuclei-templates",
    "~/.local/share/praetor/custom-nuclei-templates",
    "~/.local/share/vigil/custom-nuclei-templates/templates",
)


def _vigil_template_dirs(extra: list[str] | None = None) -> list[str]:
    """Resolve the existing template dirs to hand vigil (deduped), from
    PRAETOR_VIGIL_TEMPLATES or the default store + custom clone, plus `extra`."""
    env = os.getenv("PRAETOR_VIGIL_TEMPLATES", "").strip()
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
    async def run_vigil(  # cost: expensive (native context-aware web scan)
        target: str,
        profile: str = "normal",
        rate: float = 0.0,
        scope_host: str = "",
        templates: list[str] | None = None,
        use_proxy: bool = True,
        timeout: int = 600,
        auto_network_check: bool = False,
        policy: str = "",
        iast: bool = False,
        iast_addr: str = "",
        min_confidence: str = "",
        verify: bool = True,
        cookie: str = "",
        header: list[str] | None = None,
        data: str = "",
        method: str = "",
        login_url: str = "",
        login_user: str = "",
        login_pass: str = "",
        login_success: str = "",
        auth_a_cookie: str = "",
        auth_b_cookie: str = "",
        crawl: bool = False,
        stored_xss: bool = False,
        api_spec: str = "",
        level: int = 0,
        risk: int = 0,
        coverage: str = "",
        internal_only: bool = False,
        haruspex_url: str = "",
        baseline: str = "",
        fail_on: str = "",
        h2_probes: bool = False,
        mass_assign: bool = False,
        crawl_states: bool = False,
        exclude_path: list[str] | None = None,
        include_path: list[str] | None = None,
        fp_database: str = "",
        compliance: str = "",
    ) -> str:
        """Run the vigil DAST scanner against a target through Burp proxy.

        vigil is praetor's default web-scan engine. It runs 110+ context-aware
        native detectors covering full OWASP Top 10 + WSTG, 12 third-party
        tool integrations (sqlmap, dalfox, commix, ghauri, nikto, wpscan,
        nuclei, tplmap + 4 discovery tools) with smart auto-dispatch, OGNL/
        Struts2 SSTI, tiered parameter testing, and a Nuclei-compatible
        template engine. Maps each finding to WSTG / OWASP Top 10 / API
        Top 10 / CWE with a CVSS vector.

        Detection classes: SQLi (error/boolean/time/union), XSS (reflected/
        stored/DOM), CMDi, SSTI (Jinja2/Twig/FreeMarker/OGNL/Mako/ERB/+12),
        SSRF, LFI/RFI, XXE, NoSQL, LDAP, XPath, XSLT, CRLF, HPP, CSRF,
        IDOR, BAC, JWT, OAuth, SAML, mass assignment, race conditions,
        request smuggling (CL.TE/TE.CL/CL.0/TE.0), cache poisoning/deception,
        prototype pollution, deserialization, file upload, GraphQL injection,
        prompt injection, HTTP/2 desync, DNS rebinding, MFA bypass, session
        fixation, + 40 more.

        Workflow: run_vigil → import_scan_results('vigil') → findings.json.
        Praetor then deepens leads: confirm_sqli, escalate_ssrf, test_auth_matrix.

        When vigil runs thorough profile, individual run_sqlmap / run_dalfox /
        run_commix etc. are redundant for the same target.

        Args:
            target: Target URL
            profile: quick | normal | thorough | passive (default normal)
            rate: Requests/second cap (0 = unlimited)
            scope_host: Restrict traffic to these hosts (comma-separated)
            templates: Extra nuclei template dirs/files
            use_proxy: Route through Burp proxy (default True)
            timeout: Max seconds (default 600)
            auto_network_check: Also run nmap + tlsx against target host
            policy: Named scan policy (overrides all other args)
            iast: Enable IAST callback server for taint-marker confirmation
            iast_addr: IAST callback address (default :7880)
            min_confidence: Filter findings below this (confirmed/high/medium/low)
            verify: Re-exercise findings to confirm them (default True)
            cookie: Cookie header string for authenticated scanning
            header: Custom headers (list of 'Key: Value')
            data: POST body data
            method: HTTP method override (GET/POST/PUT/DELETE)
            login_url: HTML login form URL — vigil logs in and uses session
            login_user: Username for login form
            login_pass: Password for login form
            login_success: Substring expected after successful login
            auth_a_cookie: Identity-A cookie for two-identity IDOR probe
            auth_b_cookie: Identity-B cookie for two-identity IDOR probe
            crawl: Crawl SPA routes via headless browser (requires Chrome)
            stored_xss: Enable stored XSS detection (inject+crawl+match)
            api_spec: OpenAPI/Swagger JSON URL — exercises all documented endpoints
            level: Scan level 1-5 (higher = more payloads; 0 = auto)
            risk: Risk level 1-3 (higher = more intrusive; 0 = auto)
            coverage: Write coverage JSON to this file path
            internal_only: Skip external tools, run only native detectors
            haruspex_url: Haruspex decision engine URL (e.g. http://127.0.0.1:3000).
                When set, vigil uses ML-based finding adjudication for noise filtering.
                Without it, vigil falls back to heuristic confidence scoring.
            baseline: Path to a prior vigil JSON report. Prints new/fixed findings only.
            fail_on: CI gate — exit non-zero if any finding >= this severity (critical/high/medium/low).
            h2_probes: Enable HTTP/2 probes (rapid-reset CVE-2023-44487, CONTINUATION flood, MadeYouReset).
            mass_assign: Enable mass-assignment probe (mutates state via PUT/POST/PATCH).
            crawl_states: State-aware HTTP crawl — expand targets by following links/forms.
            exclude_path: Never request paths matching these regexps (repeatable).
            include_path: Only request paths matching these regexps (repeatable).
            fp_database: Path to FP feedback database (.vigil-fp.json). Known FPs get confidence=low.
            compliance: Emit compliance mapping (pci-dss, hipaa, iso-27001, or 'all').
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
            iast = pol.get("iast", iast)
            iast_addr = pol.get("iast_addr", iast_addr)
            min_confidence = pol.get("min_confidence", min_confidence)

        if not _check_tool("vigil"):
            return ("Error: vigil not installed. Build it: "
                    "cd <vigil repo> && go build -o ~/go/bin/vigil ./cmd/vigil")

        cmd = ["vigil", "scan", target, "--json", "--headless", "--timeout", f"{timeout}s"]
        if profile:
            cmd.extend(["--profile", profile])
        if rate and rate > 0:
            cmd.extend(["--rate", str(rate)])
        if scope_host:
            for h in scope_host.split(","):
                h = h.strip()
                if h:
                    cmd.extend(["--scope-host", h])
        for tdir in _vigil_template_dirs(templates):
            cmd.extend(["--templates", tdir])
        if use_proxy:
            cmd.extend(["--proxy", BURP_PROXY_URL, "-k"])
        if iast:
            cmd.append("--iast")
            if iast_addr:
                cmd.extend(["--iast-addr", iast_addr])
        if min_confidence:
            cmd.extend(["--min-confidence", min_confidence])
        if verify:
            cmd.append("--verify")
        if cookie:
            cmd.extend(["--cookie", cookie])
        if header:
            for h in header:
                cmd.extend(["-H", h])
        if data:
            cmd.extend(["-d", data])
        if method:
            cmd.extend(["-X", method])
        if login_url:
            cmd.extend(["--login-url", login_url])
            if login_user:
                cmd.extend(["--login-user", login_user])
            if login_pass:
                cmd.extend(["--login-pass", login_pass])
            if login_success:
                cmd.extend(["--login-success", login_success])
        if auth_a_cookie:
            cmd.extend(["--auth-a-cookie", auth_a_cookie])
        if auth_b_cookie:
            cmd.extend(["--auth-b-cookie", auth_b_cookie])
        if crawl:
            cmd.append("--crawl")
        if stored_xss:
            cmd.append("--stored-xss")
        if api_spec:
            cmd.extend(["--api-spec", api_spec])
        if level and level > 0:
            cmd.extend(["--level", str(level)])
        if risk and risk > 0:
            cmd.extend(["--risk", str(risk)])
        if coverage:
            cmd.extend(["--coverage", coverage])
        if internal_only:
            cmd.append("--internal-only")
        if baseline:
            cmd.extend(["--baseline", baseline])
        if fail_on:
            cmd.extend(["--fail-on", fail_on])
        if h2_probes:
            cmd.extend(["--h2-reset", "--h2-continuation", "--h2-madeyoureset"])
        if mass_assign:
            cmd.append("--mass-assign")
        if crawl_states:
            cmd.append("--crawl-states")
        if exclude_path:
            for p in exclude_path:
                cmd.extend(["--exclude-path", p])
        if include_path:
            for p in include_path:
                cmd.extend(["--include-path", p])
        if fp_database:
            cmd.extend(["--fp-database", fp_database])
        if compliance:
            cmd.extend(["--compliance", compliance])

        # Pass haruspex URL to vigil via env var (inherited by subprocess).
        if haruspex_url:
            os.environ["VIGIL_DECISION_BASE_URL"] = haruspex_url
        elif not os.environ.get("VIGIL_DECISION_BASE_URL"):
            # Auto-detect local haruspex on default port
            import socket as _sock
            for port in (3000, 3001):
                try:
                    with _sock.create_connection(("127.0.0.1", port), timeout=0.5):
                        os.environ["VIGIL_DECISION_BASE_URL"] = f"http://127.0.0.1:{port}"
                        break
                except OSError:
                    pass

        # Give the subprocess a little longer than vigil's own scan timeout so
        # the process is not killed before it writes its report.
        stdout, stderr, code = await _run_cmd(cmd, timeout + 30, bypass_proxy=not use_proxy)

        if not stdout.strip():
            return f"vigil failed (exit {code}): {stderr[:500]}"
        try:
            report = json.loads(stdout)
        except json.JSONDecodeError:
            return f"vigil produced no parseable JSON (exit {code}). stderr: {stderr[:300]}"

        scan_result = report.get("scan_result") or {}
        findings = scan_result.get("findings") or []
        if not findings:
            return f"No findings from vigil scan of {target}"

        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: order.get(str(f.get("severity", "")).lower(), 5))

        # Count by severity for summary
        counts: dict[str, int] = {}
        for f in findings:
            s = str(f.get("severity", "?")).lower()
            counts[s] = counts.get(s, 0) + 1
        summary_parts = [f"{counts.get(s, 0)}{s[0].upper()}" for s in ("critical", "high", "medium", "low") if counts.get(s)]

        lines = [f"vigil findings for {target}: {len(findings)} ({'/'.join(summary_parts)})", ""]
        for f in findings[:50]:
            sev = str(f.get("severity", "?")).upper()
            name = f.get("title") or f.get("type") or "?"
            conf = f.get("confidence", "")
            tool = f.get("tool", "")
            tag = ""
            if conf:
                tag += f" [{conf}]"
            if tool:
                tag += f" ({tool})"
            lines.append(f"  [{sev}] {name}{tag}")
            loc = f.get("url", "")
            if f.get("parameter"):
                loc = f"{loc} (param: {f['parameter']})"
            if loc:
                lines.append(f"       → {loc}")
            wstg = ",".join(f.get("wstg") or [])
            cwe = ",".join(f.get("cwe") or [])
            refs = " ".join(x for x in (wstg, cwe) if x)
            if refs:
                lines.append(f"       {refs}")
        if len(findings) > 50:
            lines.append(f"  ... and {len(findings) - 50} more")
        lines.append("")
        lines.append("Next: import_scan_results(format='vigil') to ingest, then deepen leads with confirm_*/escalate_* tools.")

        if auto_network_check:
            lines.append("")
            lines.append(await _network_pivot(target, scope_host))

        return wrap_untrusted("\n".join(lines), source="vigil")

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

    @mcp.tool()
    async def deploy_iast_sensor(
        target_path: str,
        language: str = "auto",
        callback_url: str = "",
    ) -> str:
        """Deploy vigil IAST sensor to a target application directory.

        Copies the appropriate sensor file (PHP/Node.js/Python) to the
        target application. The sensor hooks dangerous functions (SQL query,
        system command, file open, unserialize, etc.) and reports taint
        markers back to the vigil IAST callback server when a DAST payload
        reaches a dangerous sink.

        After deployment, run vigil with --iast to start the callback
        server and inject taint markers into DAST payloads. When the marker
        reaches a sink, vigil upgrades the finding confidence from 'medium'
        to 'confirmed' and includes the stack trace from the sensor.

        Args:
            target_path: Path to the target application root directory
            language: Sensor language — auto, php, nodejs, python. Auto-detects
                from file extensions in the target directory.
            callback_url: IAST callback URL override (default uses vigil's
                default http://host.docker.internal:7880)
        """
        if not _check_tool("vigil"):
            return ("Error: vigil not installed. Build it: "
                    "cd <vigil repo> && go build -o ~/go/bin/vigil ./cmd/vigil")

        cmd = ["vigil", "iast", "deploy", target_path]
        if language != "auto":
            cmd.extend(["--language", language])
        if callback_url:
            cmd.extend(["--callback-url", callback_url])

        stdout, stderr, code = await _run_cmd(cmd, 30)
        if code != 0:
            return f"IAST sensor deployment failed (exit {code}): {stderr[:300]}"

        # Record deployment so merge_scan can auto-enable --iast
        domain_dir = os.path.join(".burp-intel", os.path.basename(target_path))
        os.makedirs(domain_dir, exist_ok=True)
        marker = os.path.join(domain_dir, "iast-deployed")
        try:
            with open(marker, "w") as f:
                f.write(f"language={language}\npath={target_path}\n")
        except OSError:
            pass  # best-effort marker

        return stdout.strip() or f"IAST sensor deployed to {target_path}"
