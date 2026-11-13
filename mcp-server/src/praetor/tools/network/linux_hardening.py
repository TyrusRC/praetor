"""check_linux_hardening — named host-hardening checks over SSH via the
sanctioned netexec `ssh` module. The access primitive (netexec ssh -x) was
already available, but nothing wrapped it into the PAM/auditd/package-manager
host-hardening controls (NET-PAM-*, NET-AUDIT-*, NET-PKG-*, 29 checks) — an
engagement with creds still had to hand-build each command.

Each check is a short, read-only command (grep / cat / stat / rpm -qa /
systemctl is-active). validate_payload still runs on the full
`netexec ssh ... -x "<cmd>"` line (Rules 5/7/8) — no check here needs a
destructive pattern to answer its control.

Verdicts are NOT auto-scored (Rule 13b: no verdict without evidence in either
direction — a one-line regex guess on free-form command output is exactly the
"tested nothing, called it benign" failure mode Rule 13b exists to block).
The tool runs the right command for each control and returns the raw
output next to the checklist test id; the operator/caller reads it against
the control and records the verdict with `record_probe_outcome` /
`save_finding`.
"""

from __future__ import annotations

import shlex

from mcp.server.fastmcp import FastMCP

from .pipeline import _parse_creds
from .run_tool import run_sanctioned

# check_id -> {tests: [checklist ids], title, cmds: [one or more read-only
# commands, each run as a separate `netexec ssh -x` call so each line of
# evidence gets its own oplog id].
_CHECKS: dict[str, dict] = {
    # --- PAM (NET-PAM-001..011) ---
    "pam-lockout": {
        "tests": ["NET-PAM-001"],
        "title": "Account lockout after repeated failed logins",
        "cmds": ["grep -REn 'pam_faillock|pam_tally2' /etc/pam.d/ 2>/dev/null"],
    },
    "pam-complexity": {
        "tests": ["NET-PAM-002"],
        "title": "Password complexity rules",
        "cmds": [
            "grep -E 'pam_pwquality|pam_cracklib' /etc/pam.d/common-password /etc/pam.d/system-auth 2>/dev/null",
            "cat /etc/security/pwquality.conf 2>/dev/null | grep -Ev '^\\s*#|^\\s*$'",
        ],
    },
    "pam-hashing": {
        "tests": ["NET-PAM-003"],
        "title": "Password hashing algorithm, history, module order",
        "cmds": ["grep -E 'pam_unix\\.so' /etc/pam.d/common-password /etc/pam.d/system-auth 2>/dev/null"],
    },
    "pam-aging": {
        "tests": ["NET-PAM-004"],
        "title": "Password aging and account expiration",
        "cmds": ["grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|INACTIVE)' /etc/login.defs 2>/dev/null"],
    },
    "pam-dup-empty": {
        "tests": ["NET-PAM-005"],
        "title": "Duplicate UID 0, empty passwords, root misuse",
        "cmds": [
            "awk -F: '$3==0{print}' /etc/passwd",
            "awk -F: '($2==\"\"){print $1\" has empty password field\"}' /etc/shadow 2>/dev/null",
        ],
    },
    "pam-session": {
        "tests": ["NET-PAM-006"],
        "title": "Session limits, umask, home directories, root PATH",
        "cmds": [
            "grep -E '^UMASK' /etc/login.defs 2>/dev/null",
            "grep -E 'ulimit|umask' /etc/profile /etc/profile.d/*.sh 2>/dev/null",
            "echo \"root PATH: $PATH\"",
        ],
    },
    "pam-banner": {
        "tests": ["NET-PAM-007"],
        "title": "Login warning banners",
        "cmds": ["cat /etc/issue /etc/issue.net /etc/motd 2>/dev/null"],
    },
    "pam-console": {
        "tests": ["NET-PAM-008"],
        "title": "Console access controls, Ctrl-Alt-Del, session lock",
        "cmds": ["systemctl is-enabled ctrl-alt-del.target 2>/dev/null; which vlock tmux screen 2>/dev/null"],
    },
    "pam-smartcard": {
        "tests": ["NET-PAM-009"],
        "title": "Smart card login (PAM/SSSD)",
        "cmds": ["grep -E 'pam_pkcs11|pam_sss|pam_p11' /etc/pam.d/* 2>/dev/null"],
    },
    "pam-sssd": {
        "tests": ["NET-PAM-010"],
        "title": "Central authentication client (SSSD/LDAP/Kerberos/authselect)",
        "cmds": ["authselect current 2>/dev/null; test -f /etc/sssd/sssd.conf && echo sssd.conf present"],
    },
    "pam-sudo": {
        "tests": ["NET-PAM-011"],
        "title": "Sudo configuration, file permissions, privilege rules",
        "cmds": [
            "visudo -c 2>&1",
            "stat -c '%a %U %G %n' /etc/sudoers /etc/sudoers.d 2>/dev/null",
            "cat /etc/sudoers.d/* 2>/dev/null | grep -Ev '^\\s*#|^\\s*$'",
        ],
    },
    # --- AUDIT (NET-AUDIT-001..012) ---
    "audit-active": {
        "tests": ["NET-AUDIT-001"],
        "title": "auditd installed, enabled, active from boot",
        "cmds": ["systemctl is-enabled auditd 2>&1; systemctl is-active auditd 2>&1"],
    },
    "audit-logsize": {
        "tests": ["NET-AUDIT-002"],
        "title": "auditd log size, disk-full action, flush setting",
        "cmds": ["grep -E '^(max_log_file|space_left_action|disk_full_action|flush)' /etc/audit/auditd.conf 2>/dev/null"],
    },
    "audit-fileperm": {
        "tests": ["NET-AUDIT-003"],
        "title": "Owner and mode of audit logs, rules, tools",
        "cmds": ["stat -c '%a %U %G %n' /var/log/audit /etc/audit/rules.d /etc/audit/auditd.conf 2>/dev/null; which auditctl 2>/dev/null | xargs -r stat -c '%a %U %G %n'"],
    },
    "audit-baserules": {
        "tests": ["NET-AUDIT-004"],
        "title": "Base audit rules, immutable mode, OSPP rule set",
        "cmds": ["auditctl -l 2>&1 | tail -3; auditctl -s 2>&1 | grep -i enabled; ls /etc/audit/rules.d/ 2>/dev/null"],
    },
    "audit-identity": {
        "tests": ["NET-AUDIT-005"],
        "title": "Audit rules for identity files, logins, sudoers, cron",
        "cmds": ["auditctl -l 2>/dev/null | grep -E '/etc/(passwd|shadow|sudoers|group|cron)'"],
    },
    "audit-privcmd": {
        "tests": ["NET-AUDIT-006"],
        "title": "Audit rules for privileged commands and security tools",
        "cmds": ["auditctl -l 2>/dev/null | grep -E 'perm=x'"],
    },
    "audit-permchange": {
        "tests": ["NET-AUDIT-007"],
        "title": "Audit rules for permission, owner, extended-attribute changes",
        "cmds": ["auditctl -l 2>/dev/null | grep -E 'chmod|chown|setxattr|lsetxattr|fchmod|fchown|fchownat'"],
    },
    "audit-failedaccess": {
        "tests": ["NET-AUDIT-008"],
        "title": "Audit rules for failed access, file creation/change/deletion",
        "cmds": ["auditctl -l 2>/dev/null | grep -E 'EACCES|EPERM|-S creat|-S unlink|-S rename'"],
    },
    "audit-kernelmac": {
        "tests": ["NET-AUDIT-009"],
        "title": "Audit rules for kernel modules, time, network, MAC changes",
        "cmds": ["auditctl -l 2>/dev/null | grep -E 'init_module|delete_module|settimeofday|sethostname|setdomainname|selinux|apparmor'"],
    },
    "audit-syslog": {
        "tests": ["NET-AUDIT-010"],
        "title": "rsyslog/syslog-ng remote input and logging services",
        "cmds": [
            "grep -E '@@?' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null",
            "systemctl is-active rsyslog syslog-ng 2>&1",
        ],
    },
    "audit-journald": {
        "tests": ["NET-AUDIT-011"],
        "title": "journald storage, forwarding, journal file permissions",
        "cmds": [
            "grep -Ev '^\\s*#|^\\s*$' /etc/systemd/journald.conf 2>/dev/null",
            "stat -c '%a %U %G %n' /var/log/journal 2>/dev/null",
        ],
    },
    "audit-logperm": {
        "tests": ["NET-AUDIT-012"],
        "title": "/var/log file permissions and log-rotation setup",
        "cmds": [
            "stat -c '%a %U %G %n' /var/log /var/log/*.log 2>/dev/null | head -20",
            "grep -Ev '^\\s*#|^\\s*$' /etc/logrotate.conf 2>/dev/null",
        ],
    },
    # --- PKG (NET-PKG-001..006) ---
    "pkg-cryptopolicy": {
        "tests": ["NET-PKG-001"],
        "title": "System crypto policy and its use by services",
        "cmds": ["update-crypto-policies --show 2>/dev/null; cat /etc/crypto-policies/config 2>/dev/null"],
    },
    "pkg-fips": {
        "tests": ["NET-PKG-002"],
        "title": "FIPS mode, boot setup, certified OS status",
        "cmds": ["cat /proc/sys/crypto/fips_enabled 2>/dev/null; fips-mode-setup --check 2>/dev/null"],
    },
    "pkg-endpoint": {
        "tests": ["NET-PKG-003"],
        "title": "Endpoint protection, HIDS, backup tools",
        "cmds": [
            "rpm -qa 2>/dev/null | grep -iE 'aide|ossec|wazuh|clamav|falco'",
            "dpkg -l 2>/dev/null | grep -iE 'aide|ossec|wazuh|clamav|falco'",
        ],
    },
    "pkg-sigcheck": {
        "tests": ["NET-PKG-004"],
        "title": "Package signature checks, repositories, automatic updates",
        "cmds": [
            "grep -iE 'gpgcheck' /etc/yum.conf /etc/dnf/dnf.conf 2>/dev/null",
            "apt-config dump 2>/dev/null | grep -i allowunauth",
            "systemctl is-enabled dnf-automatic.timer unattended-upgrades 2>&1",
        ],
    },
    "pkg-apt": {
        "tests": ["NET-PKG-005"],
        "title": "APT sources, keys, authentication, file permissions",
        "cmds": [
            "cat /etc/apt/sources.list 2>/dev/null; ls /etc/apt/sources.list.d/ 2>/dev/null",
            "apt-key list 2>/dev/null | head -20",
            "stat -c '%a %U %G %n' /etc/apt/sources.list 2>/dev/null",
        ],
    },
    "pkg-installed": {
        "tests": ["NET-PKG-006"],
        "title": "Installed and removed system tool packages vs the standard",
        "cmds": ["rpm -qa 2>/dev/null | wc -l; dpkg -l 2>/dev/null | wc -l"],
    },
}


async def _run_one(target: str, domain: str, user: str, pw: str, port: int,
                    cmd: str, check_id: str, timeout: int) -> dict:
    port_flag = f" --port {port}" if port and port != 22 else ""
    args = f"ssh {target} -u {shlex.quote(user)} -p {shlex.quote(pw)}{port_flag} -x {shlex.quote(cmd)}"
    return await run_sanctioned(
        "netexec", args, domain, target=target,
        description=f"linux-hardening:{check_id}: {cmd[:60]}", timeout=timeout,
    )


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def check_linux_hardening(
        target: str,
        domain: str = "",
        creds: str = "",
        checks: str = "",
        port: int = 22,
        timeout: int = 60,
    ) -> str:
        """Run named Linux host-hardening checks over SSH (netexec ssh -x).

        Closes NET-PAM-001..011 / NET-AUDIT-001..012 / NET-PKG-001..006 — the
        access primitive (an authenticated SSH command) already exists via
        run_network_tool('netexec', 'ssh ...'); this wraps it into the 29
        named checks the checklist asks for instead of hand-building each
        grep/cat/stat command per engagement.

        Args:
            target: host/IP to check.
            domain: engagement key for evidence (defaults to target).
            creds: 'user:password' (or 'DOMAIN/user:password' — the domain
                part is ignored, SSH auth is local/PAM, not Kerberos).
            checks: comma list of check ids to run; blank runs all 29.
                list_linux_hardening_checks() prints the id -> test-id -> title
                table.
            port: SSH port (default 22).
            timeout: seconds per command (default 60).

        Each check runs 1-3 read-only commands and returns their raw output
        next to the checklist test id(s) it answers. This tool does NOT
        auto-score pass/fail (Rule 13b) — read the output against the
        control and record the verdict yourself.
        """
        if not creds.strip():
            return "Error: creds required, e.g. creds='root:hunter2'."
        _, user, pw = _parse_creds(creds)
        if not user:
            return "Error: creds must include a username, e.g. 'user:password'."

        resolved = domain or target
        want = [c.strip() for c in checks.split(",") if c.strip()] if checks else sorted(_CHECKS)
        unknown = [c for c in want if c not in _CHECKS]
        if unknown:
            return (f"Error: unknown check id(s) {unknown}. "
                     "Call list_linux_hardening_checks() for the valid ids.")

        lines = [f"check_linux_hardening {target} ({len(want)} check(s)) domain={resolved}"]
        for cid in want:
            spec = _CHECKS[cid]
            tests = ",".join(spec["tests"])
            lines.append(f"\n[{cid}] {tests} -- {spec['title']}")
            for cmd in spec["cmds"]:
                res = await _run_one(target, resolved, user, pw, port, cmd, cid, timeout)
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
    def list_linux_hardening_checks() -> str:
        """List check_linux_hardening's check ids, checklist test ids, titles."""
        lines = ["Linux hardening checks (check_linux_hardening(target, creds, checks=...)):"]
        for cid, spec in sorted(_CHECKS.items()):
            lines.append(f"  {cid:<18} {','.join(spec['tests']):<14} {spec['title']}")
        return "\n".join(lines)


__all__ = ["register"]
