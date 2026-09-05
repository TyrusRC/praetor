---
name: playbook-c2-sliver
description: Technical knowledge for using Sliver C2 in an authorized red-team campaign. Sliver is NOT wrapped as a tool — it runs on operator-provided infrastructure. ASK about the server and objective before any C2 action.
---

# Sliver C2 — Knowledge Playbook (no auto-wrapper)

Sliver (BishopFox) is a cross-platform adversary-emulation / C2 framework. It is
**deliberately not a Praetor tool**: a C2 server is long-lived operator
infrastructure on a separate host, and its use is a campaign decision, not a
probe. Praetor gives you the knowledge to drive it — you drive it.

## STOP — ask before any C2 action

Before generating an implant, starting a listener, or issuing a task, ASK the
operator:
1. Is a Sliver server already stood up? Where (host, how do you reach the console
   — `sliver-client` config / mTLS)? Never assume 127.0.0.1.
2. What is the objective and the authorized scope/hosts for this campaign?
3. What noise/OPSEC budget applies (see `noise-budget.md`)? Beacon vs session?
   Jitter? Egress channel (mTLS / HTTP(S) / DNS / WireGuard)?
4. Are we authorized for persistence / lateral movement, or callback-only?

Do not fabricate a server address or credentials. If no server exists, say so and
help plan setup — do not improvise one.

## Capability map (what to reach for)

- **Listeners:** `mtls`, `https`, `dns`, `wg` (WireGuard). Prefer mTLS/HTTPS with a
  real redirector; DNS only when egress is locked down (slow, noisy).
- **Implants:** `generate` (session) vs `generate beacon` (low-and-slow, jittered).
  Beacons for stealth; sessions for interactive work. `--evasion`, `--os`, `--arch`,
  `--format` (exe/shellcode/shared-lib), profiles via `profiles new`.
- **Post-ex:** `execute-assembly` (.NET, in-proc), `sideload`, `spawndll`,
  `getsystem`, `getprivs`, `portfwd`, `socks5` (pivoting), `screenshot`, `procdump`.
- **Lateral:** `psexec`, service creation; pair with the network lane's
  credential store (captured creds) and BloodHound paths.
- **Armory:** `armory install` for vetted extensions (seatbelt, sharpup,
  rubeus, etc.) rather than dropping raw tooling.

## Evidence + reporting (Praetor integration)

C2 actions bypass Burp — record them in the operator log like any network-lane
action so the kill chain is reconstructable:
- `record_redteam_action(...)` for each meaningful step (ATT&CK-tagged: T1059,
  T1021, T1055, T1071, T1550, T1003 as applicable).
- `record_loot(...)` for captured credentials/hashes/tokens (chain-of-custody).
- Feed captured creds into the credential store (`record_credential`) so the AD
  lane (`run_network_tool netexec`, bloodhound) and `crack_hashes` can reuse them.
- Forward to Ghostwriter via `sync_to_ghostwriter` for the narrative report.

## Safety (HARD)

- HARD Rules 5-9 hold: no destructive actions, no data exfil beyond authorized
  scope, no targeting outside the engagement's authorized hosts.
- Anything that changes victim state (persistence, service install, credential
  dumping on a host) is an ALWAYS-APPROVAL action — confirm with the operator
  first, even in aggressive autopilot modes.
- Never hardcode C2 addresses, implant configs, or operator credentials into the
  repo, notes, or reports. Reference them by role.
