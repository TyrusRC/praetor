---
name: playbook-network-recon-scan
description: Systematic network-lane recon — subdomains to unique non-CDN origins to full-port scan to nuclei/ffuf on ALL ports; the discipline that finds bugs on non-standard ports others miss
---

# Playbook: Network Recon & Scanning (find what others skip)

Most hunters scan the obvious assets on 80/443 and move on. The wins hide on
non-standard ports, forgotten IP ranges, and long-running services. This is the
network-lane pipeline that surfaces them. Every step is an existing tool — the
value is the ORDER and the pro-tips, not new tooling. All of this is the network
lane (bypasses Burp); record actions to the operator log.

## Pipeline

```
chaos/subfinder → httpx (live + IP, DEDUP) → cdncheck (drop CDN edge)
   → naabu (verify open ports) → nmap+nmap_report_html → nuclei (ALL ports) → ffuf
```

### Phase 1 — Subdomains
`run_chaos(domain)` (CT logs + PTR + TLS, no API-key juggling) and/or
`run_subfinder(domain)`. Merge, dedup. Broaden, don't brute yet.

### Phase 2 — Live hosts + IP dedup + CDN filter (the step most people skip)
- `run_httpx(hosts)` → live assets AND their IPs.
- **Dedup to UNIQUE IPs.** Many subdomains resolve to one backend/load balancer;
  scanning each name re-scans the same host. Collapse to unique origins.
- **Drop CDN/WAF IPs BEFORE scanning:** `run_cdncheck(ips)` — Cloudflare / Akamai
  / Fastly edges are not the origin. Scanning them is pointless AND gets you
  banned. Verify a candidate origin by title (`run_httpx` `-title`): if the title
  matches the real site it is likely origin; generic CDN/WAF pages are not worth
  targeting.

### Phase 3 — Port scan the unique origins
`run_naabu(target=<unique non-CDN IPs>, ports="top-100")` with verify. This is
the BASELINE — the exact open-port set every later step consumes. Save it.

### Phase 4 — Service detection + readable report
- `run_nmap` (`-sV -sC` / NSE) against the naabu port set → software, versions,
  script audits.
- `nmap_report_html(xml_path=<nmap -oX out>)` → offline HTML exposure report;
  non-standard ports are flagged. Use it to eyeball low-hanging fruit
  (outdated versions, admin panels) across hosts at a glance.

### Phase 5 — Vuln scan on ALL ports (not just web)
`run_nuclei` with the CVE/misconfig/default-cred/exposed-token tags, fed the
naabu port set — every discovered port, not only 80/443. Admin panels, APIs,
Redis/Elasticsearch/Jenkins on odd ports are where the criticals live.

### Phase 6 — Content discovery / fuzzing
`run_ffuf` (or `discover_common_files`) for hidden dirs, backup archives
(`.bak`/`.zip`/`.old`), and sensitive paths (`/admin`, `.env`, `.git`) — on the
live hosts INCLUDING non-standard ports.

## Fuzzing pro-tips (why this finds more)

- **Read size + word count, not just status.** A 200 that matches a known error
  page's size is a custom 404. Filter with ffuf `-fs`/`-fw`; a distinct
  size/word count is the real signal.
- **Carry the naabu port list into fuzzing.** Internal services on unusual ports
  are frequently unauthenticated.
- **Investigate every 403.** A Forbidden often means something sensitive exists;
  route it to `probe_40x_bypass` / `run_byp4xx` / `run_dontgo403` and the header/
  path-mangling bypass set (`test_login_bypass`).

## Evidence + handoff

Network-lane findings cite an operator-log id (not a Burp index). When a live
web service turns up, bridge it into the web lane
(`discover_attack_surface` / `auto_probe`) for deep testing. Report the
kill-chain to impact, not a scan log (Rule 16a).
