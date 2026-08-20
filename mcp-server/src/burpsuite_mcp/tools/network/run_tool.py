"""run_network_tool — sanctioned AD/post-ex tool runner (impacket, netexec,
enum4linux-ng, smbmap, kerbrute, certipy, bloodhound-python, responder,
evil-winrm, ...). Runs the tool, saves output, records an ATT&CK-tagged
operator-log entry. `run_sanctioned()` is the core the pipeline reuses.

HARD: sanctioned tools only; destructive args refused (Rules 5/7/8); online
brute refused (Rule 6); scope is mode-aware.
"""

from __future__ import annotations

from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.exploit._safety import validate_payload
from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd

from ._guards import sanitize_target, scope_gate
from ._store import write_tool_output

# Sanctioned binaries. Prefix match covers the impacket family.
_SANCTIONED = {
    "nmap", "masscan", "rustscan",
    "netexec", "nxc", "crackmapexec",
    "enum4linux", "enum4linux-ng", "smbmap", "rpcclient", "smbclient",
    "ldapsearch", "ldapdomaindump", "adidnsdump", "nbtscan", "onesixtyone",
    "kerbrute", "certipy", "certipy-ad", "bloodhound-python", "bloodhound",
    "responder", "evil-winrm", "sshuttle", "chisel", "ligolo-ng", "ligolo-proxy",
    "getuserspns.py", "getnpusers.py", "secretsdump.py", "psexec.py",
    "wmiexec.py", "smbexec.py", "dcomexec.py", "ntlmrelayx.py",
    "getadusers.py", "lookupsid.py", "finddelegation.py", "gettgt.py",
    "impacket-secretsdump", "impacket-psexec", "impacket-wmiexec",
    "impacket-getuserspns", "impacket-getnpusers", "impacket-ntlmrelayx",
    "impacket-smbexec", "impacket-smbclient", "impacket-lookupsid",
}
# Online credential brute — HARD Rule 6. Blocked regardless of mode.
_ONLINE_BRUTE = {"hydra", "medusa", "ncrack", "patator"}


def _tool_ok(binary: str) -> bool:
    b = binary.lower().rsplit("/", 1)[-1]
    if b in _SANCTIONED:
        return True
    return b.startswith("impacket-")


async def run_sanctioned(
    tool: str,
    args: str = "",
    domain: str = "",
    target: str = "",
    description: str = "",
    timeout: int = 300,
) -> dict:
    """Structured core. Returns {ok, error, oplog_id, rc, output, output_path,
    tool, target}. `error` set (ok=False) on any guard rejection / not-installed.
    """
    binary = tool.strip()
    if not binary:
        return {"ok": False, "error": "no tool given"}
    b = binary.lower().rsplit("/", 1)[-1]
    if b in _ONLINE_BRUTE:
        return {"ok": False, "error": (
            f"{binary} is online credential brute-force (HARD Rule 6). "
            "Single-password spray via netexec is allowed; dictionary brute is not.")}
    if not _tool_ok(binary):
        return {"ok": False, "error": (
            f"{binary!r} is not a sanctioned network tool. See redteam_tool_guide().")}

    ok, why = validate_payload(args, vuln_type="network")
    if not ok:
        return {"ok": False, "error": f"destructive args refused (Rules 5/7/8): {why}"}

    if target:
        _t, terr = sanitize_target(target)
        if terr:
            return {"ok": False, "error": terr}
        scope_err = scope_gate(target, tool=b)
        if scope_err:
            return {"ok": False, "error": scope_err}

    if not _check_tool(binary):
        return {"ok": False, "error": f"{binary} not installed — redteam_tool_guide(tool='{b}')"}

    resolved_domain = domain or target or binary
    cmd = [binary] + (args.split() if args else [])
    stdout, stderr, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
    combined = stdout + (("\n[stderr]\n" + stderr) if stderr.strip() else "")

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    out_path = ""
    try:
        safe = b.replace("/", "_").replace(".", "_")
        out_path = str(write_tool_output(resolved_domain, f"{safe}-{ts}.txt", combined))
    except (OSError, ValueError):
        pass

    from burpsuite_mcp.tools.redteam._oplog import record_action
    op_id = record_action(resolved_domain, binary, " ".join(cmd), description=description,
                          target=target, output=combined, output_path=out_path, returncode=rc)

    return {"ok": True, "error": "", "oplog_id": op_id, "rc": rc,
            "output": combined, "output_path": out_path, "tool": binary, "target": target}


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_network_tool(
        tool: str,
        args: str = "",
        domain: str = "",
        target: str = "",
        description: str = "",
        timeout: int = 300,
    ) -> str:
        """Run a sanctioned network/AD/post-ex tool and record it as evidence.

        Args:
            tool: sanctioned binary — impacket-secretsdump / netexec / nxc /
                enum4linux-ng / smbmap / kerbrute / certipy / bloodhound-python /
                responder / evil-winrm / rpcclient / ldapsearch. redteam_tool_guide()
                lists them + install commands.
            args: arguments as one string (split on spaces; each becomes an argv
                token — no shell). Destructive args refused (Rules 5,7,8).
            domain: engagement key for evidence + operator-log persistence.
            target: host/IP for the scope gate + operator-log dest (recommended).
            description: operator intent for the log ("dump domain hashes").
            timeout: seconds (default 300).

        Records an operator-log entry with ATT&CK auto-mapped from `tool` and
        saves stdout to material/tool-output/. Capture secrets with record_loot().
        For the full chained sweep use run_network_recon.
        """
        res = await run_sanctioned(tool, args, domain, target, description, timeout)
        if not res["ok"]:
            return f"REFUSED / error: {res['error']}"
        tail = "\n".join(res["output"].strip().splitlines()[-25:])
        return (f"{res['tool']} (rc={res['rc']}) -> operator-log {res['oplog_id']}"
                + (f"  output: {res['output_path']}" if res["output_path"] else "")
                + f"\n--- output tail ---\n{tail}")
