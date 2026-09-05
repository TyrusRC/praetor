from mcp.server.fastmcp import FastMCP
from ._shared import (
    BURP_PROXY_URL,
    _check_tool,
    _run_cmd,
)
from ._g2 import _cap_tamper, _sqlmap_cmd, _ghauri_cmd  # noqa: F401 (re-used builders)


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
        tamper: str = "",
        dbms: str = "",
        hex_encode: bool = False,
        random_agent: bool = False,
        ignore_code: str = "",
        batch: bool = True,
        use_proxy: bool = True,
        timeout: int = 600,
    ) -> str:
        """Run sqlmap SQL injection scanner against a target URL. Requires sqlmap installed.

        Detection/enumeration only — no os-shell / file-write / dump-all (HARD Rule 5/7).

        Args:
            target: Target URL with injectable parameter
            data: POST body (auto-switches to POST); JSON bodies supported
            cookie: Cookie header
            method: HTTP method (default GET)
            level: Test level 1-5 (default 1)
            risk: Risk level 1-3 (default 1)
            technique: Technique flags (B=Boolean, E=Error, U=UNION, S=Stacked, T=Time, Q=Inline)
            tamper: WAF-bypass tamper scripts, comma-separated — CAPPED AT 3 (more
                triggers WAF blocks/false positives). E.g. Cloudflare:
                'space2comment,randomcase,charencode'; ModSecurity: 'between,space2comment'.
            dbms: Force backend DBMS (mysql/postgresql/mssql/oracle) — engine-specific
                payloads evade signatures and run faster once fingerprinted.
            hex_encode: --hex; encode extracted data to slip past input filters.
            random_agent: --random-agent; randomize User-Agent per request.
            ignore_code: --ignore-code (e.g. '403,500'); keep testing when a WAF blocks.
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

        cmd = _sqlmap_cmd(target, data, cookie, method, level, risk, technique,
                          tamper, dbms, hex_encode, random_agent, ignore_code,
                          batch, use_proxy)

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
    async def run_ghauri(
        target: str,
        data: str = "",
        cookie: str = "",
        method: str = "GET",
        param: str = "",
        level: int = 1,
        technique: str = "",
        dbms: str = "",
        confirm: bool = False,
        time_sec: int = 0,
        delay: int = 0,
        prefix: str = "",
        suffix: str = "",
        random_agent: bool = False,
        use_proxy: bool = True,
        timeout: int = 600,
    ) -> str:
        """Run Ghauri — adaptive SQLi framework, strong on cloud WAFs (Cloudflare/
        Akamai), blind/time-based, and REST/JSON APIs. Complements run_sqlmap:
        test with BOTH — one often succeeds where the other is filtered.

        Detection/enumeration only. Ghauri obfuscates payloads and calibrates
        timing to look like human traffic, evading behaviour-based WAFs that block
        fixed patterns.

        Args:
            target: Target URL with injectable parameter
            data: POST body (JSON supported — often better than a raw request file)
            cookie: Cookie header
            method: HTTP method (default GET)
            param: Restrict testing to this parameter (-p)
            level: Test depth 1-3 (default 1)
            technique: e.g. 'T' (time), 'B' (boolean) — focus inference type
            dbms: Force backend DBMS for faster, engine-specific payloads
            confirm: --confirm; re-validate payloads to cut false positives
            time_sec: --time-sec for time-based inference (e.g. 10)
            delay: --delay seconds between requests (rate/behaviour evasion)
            prefix: break out of the query context, e.g. "')/**/"
            suffix: terminate the original query, e.g. "--+"
            random_agent: randomize User-Agent per request
            use_proxy: Route through Burp proxy (default True)
            timeout: Max seconds (default 600)
        """
        if not _check_tool("ghauri"):
            return (
                "Error: ghauri not installed.\n"
                "  pip install ghauri (or git clone https://github.com/r0oth3x49/ghauri)"
            )

        cmd = _ghauri_cmd(target, data, cookie, method, param, level, technique,
                          dbms, confirm, time_sec, delay, prefix, suffix,
                          random_agent, use_proxy)

        stdout, stderr, code = await _run_cmd(cmd, timeout)
        out = (stdout + "\n" + stderr).strip()
        if not out:
            return f"ghauri produced no output (exit {code})"

        key_lines = []
        for line in out.split("\n"):
            if any(k in line for k in ("vulnerable", "injectable", "Payload:", "Parameter:",
                                        "Type:", "Title:", "back-end DBMS", "current user",
                                        "current database", "available databases",
                                        "[CRITICAL]", "[WARNING]", "[ERROR]", "confirmed")):
                key_lines.append(line.strip())

        lines = [f"ghauri findings for {target} ({len(key_lines)}):", ""]
        if key_lines:
            for l in key_lines[:80]:
                lines.append(f"  {l}")
        else:
            lines.append(f"  No injection confirmed at level={level}. Try --confirm, higher level, "
                         f"a known --dbms, or run_sqlmap with tamper scripts.")
        if use_proxy:
            lines.append("\nAll requests routed through Burp proxy — check proxy history.")
        return "\n".join(lines)
