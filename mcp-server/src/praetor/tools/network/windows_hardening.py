"""check_windows_hardening — named registry-read checks over SMB via the
sanctioned netexec `smb -x` module (wmiexec exec-method). netexec/impacket
already give an authenticated remote-command primitive on Windows hosts, but
nothing wrapped it into the host-local settings checklist asks for (LSA
protection, Credential Guard, WDigest, cached logons, AppLocker, PowerShell
logging, AlwaysInstallElevated, UAC — NET-WIN-004..010/012/014, 9 checks) —
an engagement with valid local-admin creds still had to hand-build each
registry read.

NET-WIN-001/002/003/011/013 and NET-WRMT-001..003 are NOT here: 001-003 and
011 are already covered by netexec's own SMB/enum output (signing state,
NTLM version, writable-service enumeration) and 013/WRMT-003 need a
secedit /export round-trip (writes a temp file on the target) that is
deliberately left to a manual step rather than built in here.

Every check is a single `reg query` — read-only, no destructive pattern.
Verdicts are NOT auto-scored (Rule 13b) — this returns the raw registry
value next to the checklist test id; read it against the control yourself.
"""

from __future__ import annotations

import shlex

from mcp.server.fastmcp import FastMCP

from .pipeline import _parse_creds
from .run_tool import run_sanctioned

_CHECKS: dict[str, dict] = {
    "win-lsaprotect": {
        "tests": ["NET-WIN-004"],
        "title": "LSASS runs as a protected process (LSA protection)",
        "cmds": ['reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RunAsPPL'],
    },
    "win-credguard": {
        "tests": ["NET-WIN-005"],
        "title": "Credential Guard is running",
        "cmds": ['reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA" /v LsaCfgFlags'],
    },
    "win-wdigest": {
        "tests": ["NET-WIN-006"],
        "title": "WDigest does not keep clear-text passwords",
        "cmds": ['reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" /v UseLogonCredential'],
    },
    "win-cachedlogon": {
        "tests": ["NET-WIN-007"],
        "title": "Number of cached domain logons",
        "cmds": ['reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v CachedLogonsCount'],
    },
    "win-applocker": {
        "tests": ["NET-WIN-008"],
        "title": "App Control / AppLocker enforces rules on servers",
        "cmds": [
            'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2"',
            "sc qc AppIDSvc",
        ],
    },
    "win-pslogging": {
        "tests": ["NET-WIN-009"],
        "title": "PowerShell logging and language mode",
        "cmds": [
            'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" /v EnableScriptBlockLogging',
            'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\PowerShell" /v ExecutionPolicy',
        ],
    },
    "win-installelevated": {
        "tests": ["NET-WIN-010"],
        "title": "AlwaysInstallElevated is off (HKLM policy hive)",
        "cmds": ['reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" /v AlwaysInstallElevated'],
    },
    "win-autorun": {
        "tests": ["NET-WIN-012"],
        "title": "Autorun targets (Run keys) — scheduled-task ACL walk is a manual follow-up",
        "cmds": [
            'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"',
            'reg query "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"',
        ],
    },
    "win-uac": {
        "tests": ["NET-WIN-014"],
        "title": "UAC Admin Approval Mode",
        "cmds": [
            'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA',
            'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ConsentPromptBehaviorAdmin',
        ],
    },
}


async def _run_one(target: str, domain: str, user: str, pw: str,
                    cmd: str, check_id: str, timeout: int) -> dict:
    args = f"smb {target} -u {shlex.quote(user)} -p {shlex.quote(pw)} -x {shlex.quote(cmd)}"
    return await run_sanctioned(
        "netexec", args, domain, target=target,
        description=f"win-hardening:{check_id}: {cmd[:60]}", timeout=timeout,
    )


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def check_windows_hardening(
        target: str,
        domain: str = "",
        creds: str = "",
        checks: str = "",
        timeout: int = 60,
    ) -> str:
        """Run named Windows registry-hardening checks over SMB (netexec smb -x).

        Closes NET-WIN-004/005/006/007/008/009/010/012/014 — wraps the
        already-sanctioned remote-command primitive (netexec smb -x / impacket
        wmiexec) into named `reg query` checks instead of hand-building each
        registry path per engagement. Needs local-admin (or domain-admin)
        creds on the target.

        Args:
            target: host/IP to check.
            domain: engagement key for evidence (defaults to target).
            creds: 'DOMAIN/user:password' or 'user:password' for local auth.
            checks: comma list of check ids; blank runs all 9.
                list_windows_hardening_checks() prints id -> test-id -> title.
            timeout: seconds per command (default 60).

        NOT covered here (see module docstring): NET-WIN-001/002/003/011/013,
        NET-WRMT-001..003 — 001-003/011 already come out of netexec's own SMB
        enumeration; 013/WRMT-003 need a secedit export round-trip left as a
        manual step. This tool does NOT auto-score pass/fail (Rule 13b) — read
        each registry value against the control and record the verdict
        yourself.
        """
        if not creds.strip():
            return "Error: creds required, e.g. creds='CORP/admin:P@ssw0rd' or 'admin:P@ssw0rd'."
        cdom, user, pw = _parse_creds(creds)
        if not user:
            return "Error: creds must include a username."

        resolved = domain or target
        want = [c.strip() for c in checks.split(",") if c.strip()] if checks else sorted(_CHECKS)
        unknown = [c for c in want if c not in _CHECKS]
        if unknown:
            return (f"Error: unknown check id(s) {unknown}. "
                     "Call list_windows_hardening_checks() for the valid ids.")

        lines = [f"check_windows_hardening {target} ({len(want)} check(s)) domain={resolved}"]
        for cid in want:
            spec = _CHECKS[cid]
            tests = ",".join(spec["tests"])
            lines.append(f"\n[{cid}] {tests} -- {spec['title']}")
            for cmd in spec["cmds"]:
                res = await _run_one(target, resolved, user, pw, cmd, cid, timeout)
                if not res["ok"]:
                    lines.append(f"  $ {cmd}\n  ERROR: {res['error']}")
                    continue
                out = res["output"].strip() or "(empty output)"
                lines.append(f"  $ {cmd}  (oplog {res['oplog_id']})\n  {out[:600]}")

        lines.append(
            "\nVerdicts are not auto-scored (Rule 13b). Read each control's output, "
            "then record_probe_outcome / save_finding / save_target_notes."
        )
        return "\n".join(lines)

    @mcp.tool()
    def list_windows_hardening_checks() -> str:
        """List check_windows_hardening's check ids, checklist test ids, titles."""
        lines = ["Windows hardening checks (check_windows_hardening(target, creds, checks=...)):"]
        for cid, spec in sorted(_CHECKS.items()):
            lines.append(f"  {cid:<20} {','.join(spec['tests']):<14} {spec['title']}")
        return "\n".join(lines)


__all__ = ["register"]
