---
description: Nmap scan-technique methodology for the network lane — SYN/ACK/FIN/NULL/XMAS/UDP scan selection, how to READ each result (firewall map vs OS inference vs open|filtered caveat), NSE for enumeration/vuln, timing/IDS-evasion tuning, and the observe-the-packets principle. Use when running run_nmap and deciding scan type or interpreting a state that is not plainly open/closed.
globs:
---

# Network Scan Techniques (nmap, network lane)

Load when: choosing an nmap scan type, reading an ACK/FIN/NULL/XMAS/UDP result, tuning timing for a slow-and-quiet or fast-LAN scan, or picking NSE scripts. All of this is one tool — `run_nmap` — not a parallel scanner. Network lane: traffic bypasses Burp, evidence is the operator log (`run_id`), HTTP(S) services found are bridged back to the web lane automatically.

## The one principle that governs every scan

**nmap output is INFERENCE from probe responses, not ground truth.** Every "open", "closed", "filtered" is nmap guessing the port's state from whether (and how) a packet came back. A firewall, a rate-limiter, a non-RFC-793 TCP stack, or a dropped packet all change the inference without changing the truth. Before you trust a *surprising* verdict — a critical port "filtered", a host "all closed" on XMAS, a UDP service "open|filtered" — corroborate at the packet level:

- **Wireshark / tcpdump** on the probe — did the SYN/ACK/RST actually arrive?
- **Praetor `tcp_proxy_*`** (burp-expedition TCP proxy) — `tcp_proxy_add_listener` + `tcp_proxy_messages` capture the real TCP exchange for a TCP service so you see the handshake nmap only inferred.

A scan verdict + a packet capture that agrees is evidence. A scan verdict alone is a lead.

## The seven techniques

### 1. TCP SYN half-open — `scan_type='syn'` (-sS)

Default stealth scan. Sends SYN, reads SYN/ACK (open) or RST (closed), **never completes the handshake** (sends RST instead of the final ACK) so the connection is never logged by the application. Needs raw-socket privilege; falls back to connect if unprivileged.

```
run_nmap(target, scan_type='syn', ports='1-1000')
```
Read: `open` / `closed` / `filtered` directly. This is the baseline — use it unless a firewall or an OS question sends you to another type.

### 2. ACK scan — `scan_type='ack'` (-sA) — FIREWALL MAPPING

**Does NOT find open ports.** It maps whether a **stateful firewall** filters a port.

```
run_nmap(target, scan_type='ack', flags='-Pn')
```
Read (the tool surfaces this in `Interpretation:`):
- **unfiltered** — the ACK got an RST back → no stateful firewall is dropping this port (it may still be open or closed; ACK can't tell).
- **filtered** — no response / ICMP unreachable → a stateful firewall is dropping the ACK.
- All-unfiltered → no stateful packet filter in path → go back to `-sS` for open ports.
- All-filtered → stateful firewall present → try FIN/NULL/XMAS to slip past it.

Use ACK to answer "is there a stateful firewall, and which ports does it guard?" — then pick the next scan accordingly.

### 3. FIN / NULL / XMAS — `scan_type='fin' | 'null' | 'xmas'` (-sF / -sN / -sX) — bypass + OS inference

Stateless-firewall bypass (many packet filters only block SYN). Also an **OS-family fingerprint**:
- **RFC 793-compliant stacks** (most Linux/Unix) reply **RST to a closed port** and **stay silent on open|filtered**.
- **Windows, Cisco IOS, many BSD-derived and embedded stacks** reply **RST regardless** of state.

```
run_nmap(target, scan_type='xmas', flags='-Pn')
```
Read (surfaced in `Interpretation:`):
- **open|filtered** present → RFC-compliant stack (Linux/Unix); the open|filtered set is your open-port candidate list — confirm each with `-sS`.
- **all closed** (every probed port replied RST, never silent) → a **non-RFC-793 stack that RSTs regardless** → **likely Windows / Cisco / BSD device**, and this scan type *cannot* distinguish open from closed here. Confirm with `-sS` + `os_detect=True`.

"All closed from XMAS" is therefore usually an OS signal, not a real all-closed host.

### 4. UDP scan — `scan_type='udp'` (-sU) — connectionless

```
run_nmap(target, scan_type='udp', ports='53,161,123', flags='-Pn')   # or pair with --top-ports
```
Read (surfaced in `Interpretation:`):
- **open** — a UDP payload came back (rare, definitive).
- **open|filtered** — **no response** → service may be open-and-silent OR a firewall dropped the probe. **This is not a confirmed-open verdict** — disambiguate with a service-specific NSE script (`snmp-info`, `dns-recursion`) or a real client.
- **closed** — ICMP port-unreachable received.

UDP is **slow** (ICMP-unreachable rate limiting). Pair with `--top-ports` (via `flags='--top-ports 100'` or explicit `ports=`) and expect long runtimes; raise `host_timeout`.

### 5. NSE — `nse_scripts='...'` (--script) — enumeration / vuln / unauthorized-access

Service enumeration, vuln detection, and unauthorized-access checks. Comma-separated categories or script names.

```
run_nmap(target, ports='445', nse_scripts='smb-enum-shares,smb-os-discovery')
run_nmap(target, nse_scripts='vuln')                 # recon-active vuln checks
run_nmap(target, ports='445', nse_scripts='smb-vuln-ms17-010')
```
Curated safe/enum picks: `default`, `safe`, `banner`, `auth`, `smb-enum-shares`, `smb-os-discovery`, `smb-vuln-*`, `http-title`, `ssl-cert`.

`vuln` and `smb-vuln-*` are **recon-active** — allowed (they detect, they don't exploit). **Refused HARD in both engagement modes (Rules 5-6):** the `dos`, `brute`, `broadcast`, `exploit` categories and any `unsafe=1` script-arg. Those mutate target state or brute-force credentials; the tool rejects them before nmap runs.

### 6. Timing / performance — `timing`, `max_retries`, `scan_delay`, `host_timeout`

Tune for the network and the IDS posture:
```
run_nmap(target, timing='4', max_retries='1')                 # fast LAN
run_nmap(target, timing='1', scan_delay='2s')                 # slow, quiet, IDS-evasion
run_nmap(target, host_timeout='30m')                          # cap slow hosts
```
- `timing` 0-5 (-T): 0-1 = paranoid/sneaky (evade IDS thresholds), 3 = default, 4-5 = aggressive/insane (fast, loud).
- `max_retries` — lower = faster, less reliable on lossy links.
- `scan_delay` — space probes out (`'500ms'`, `'2s'`) to stay under rate-limit / IDS rate thresholds.
- `host_timeout` — abandon a host that is dragging the whole scan (`'30m'`).

### 7. OS / service detection — `os_detect=True` (-O), `svc_detect=True` (-sV)

`svc_detect` (-sV) is already in the default `flags`. Add `os_detect=True` for a TCP/IP-stack OS fingerprint — pairs naturally with a FIN/NULL/XMAS OS inference (step 3) to confirm the family. `-O` needs at least one open and one closed port to fingerprint well, so run it alongside `-sS`, not alongside a firewall-map ACK scan.

## Reading a result: three outcomes, not two

A status is not a verdict (Rule 13a/13b). For every scan:
1. Read the `Interpretation:` block the tool prints — it already turns the state tally into the firewall/OS/UDP meaning above.
2. If the verdict is surprising or the state is `filtered` / `open|filtered` / all-closed-on-XMAS, it is **INCONCLUSIVE**, not a clean pass/fail — corroborate with a packet capture (`tcp_proxy_*` for TCP, Wireshark/tcpdump otherwise) before recording it.
3. Only a scan verdict that agrees with an observed packet exchange is evidence.

## Evidence / persistence

- Every `run_nmap` records a `run_id` in the operator log (network-lane evidence — not a Burp `proxy_history_index`) and merges open ports into `network.json`.
- HTTP(S) services are auto-bridged: the result lists `http://` / `https://` URLs → `configure_scope(keep_in_scope=[...])` → `browser_crawl` / `auto_probe` to pivot to the web lane.
- Network-lane findings cite the operator-log `run_id`; forward with `sync_to_ghostwriter`.

## Related

- `run_network_recon` — full chained sweep (discovery → service enum → leads → auto-loot → web bridge); use it instead of hand-driving `run_nmap` for a whole subnet.
- `run_network_tool` — sanctioned impacket/netexec/... for post-discovery enum.
- `tcp_proxy_add_listener` / `tcp_proxy_messages` / `tcp_repeat` — packet-level TCP capture to corroborate a scan verdict.
- `nmap_report_html` — render the inventory as a network-lane deliverable.
