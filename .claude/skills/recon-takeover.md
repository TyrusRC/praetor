---
description: Subdomain takeover + broken-link-hijacking hunt — CNAME-fingerprint match, dns_only signal, dangling external-resource takeover. Use when target has wildcard scope, a subdomain list, or pages linking external resources.
globs:
---

# Subdomain Takeover Hunt

Load when: target program has wildcard scope (`*.example.com`) or you have a subdomain list from `query_crtsh` / `run_subfinder` / `run_amass` / `fetch_wayback_urls`.

## Two detection modes

### 1. Body-fingerprint match (default)

Most takeover services return a vendor-specific 404 body when the resource doesn't exist (`"There isn't a GitHub Pages site here"`, `"The deployment could not be found"` — vercel, `"Site Not Found | Framer"`).

Workflow:
1. CNAME resolves to `vendor.tld` (e.g. `vercel-dns.com`).
2. HTTPS GET to the subdomain → response body matches vendor's "missing resource" marker.
3. Claim the resource on the vendor side → serve attacker content under the victim subdomain.

Praetor: `test_subdomain_takeover(subdomains=[...])`. Fingerprint table is `tools/recon_extended/fingerprints.py::TAKEOVER_FINGERPRINTS` (129 entries post-W9 including W8's nuclei-templates pass).

### 2. DNS-only signal (`dns_only=True`, W9+)

Some vendors **never serve a 404 body**. The CNAME resolves to a regional endpoint but the target hostname simply has no A record (NXDOMAIN at the A-record layer). Body fingerprinting can't fire — the only signal is the DNS gap.

Examples shipped W9:
- `elasticbeanstalk-us-east-1.elasticbeanstalk.com` (and 7 other AWS regions)
- `trafficmanager.net` (Azure Traffic Manager)
- `azureedge.net` (Azure CDN)
- `redis.cache.windows.net` (Azure managed Redis)

Workflow for `dns_only=True`:
1. CNAME of victim subdomain matches one of the regional patterns.
2. Detector queries A record on the CNAME target itself.
3. `NXDOMAIN` / no A → **VULNERABLE** (the regional resource was deleted; attacker can claim the exact name in the same region).
4. Resolution → `cname_match_but_resolves` (active resource — not vulnerable).

## When to use which

- Body-match: 90%+ of takeover hunts. Vendor lists in `can-i-take-over-xyz`.
- DNS-only: cloud-provider regional endpoints, dynamic-DNS providers, Redis/Memcache/queue endpoints that return TCP refused at the A-record layer rather than serving an HTTP body.

## Reporting cap

- DNS-only finding alone with NO further claim: **NEVER_SUBMIT** unless chained with cookie-scope hijack (Rule 17). The "I could register this name" claim without evidence of impact is low-value.
- Body-fingerprint finding with attacker actually claiming the vendor resource and serving content from victim subdomain: **CRITICAL** when the parent domain shares cookies (cookie-scope hijack class).
- Body-fingerprint finding without claim attempted: **HIGH** (PoC-by-claim is the missing bar; some programs accept fingerprint-only).

Save with `vuln_type='subdomain_takeover'`. For chain reporting use `chain_with=[<takeover_finding_id>]` and reference cookie-scope hijack from `chain-findings.md`.

## Broken Link Hijacking (BLH)

Sibling of subdomain takeover, different sink: the target *page* references an
external resource that is now unclaimed — not a dangling DNS record. Claim the
resource and you serve content the victim's page trusts.

Workflow:
1. `browser_crawl(url)` then `extract_links` / `extract_links_batch` /
   `fetch_page_resources` over the captured pages — pull every external
   `script src`, `link href`, `img`, `a href`, `form action`, and social handle.
   `extract_js_secrets` also surfaces hardcoded external endpoints.
2. For each external target, check if it is claimable:
   - **Dead domain** (NXDOMAIN / expired / parked-for-sale) → register it.
   - **Unclaimed cloud bucket** (`<script src>` → an S3/GCS/Azure bucket that 404s
     as missing, not access-denied) → claim the bucket (`test_subdomain_takeover`
     fingerprints + the `cloud_storage_misconfig` KB both help classify).
   - **Dead social handle** (github/medium/twitter linked from the victim) → register it.
3. Impact tiers decide reportability:
   - **Executable include** — a hijackable `<script src>` / SRI-less JS on a dead
     or claimable host runs JS in the victim origin = stored-XSS-equivalent →
     HIGH/CRITICAL.
   - **Non-executable link** — a dead `<a href>` / image / social handle is
     content/brand only → LOW, usually informative alone (NEVER_SUBMIT, cf.
     Tabnabbing) unless chained. Escalate per Rule 29 before filing.

Save the executable case as `vuln_type='subdomain_takeover'` (dangling-resource
class) with the hijacked resource URL in evidence; chain non-executable ones.

## SNI vs non-SNI cert comparison (hidden-origin lead)

Compare the cert served with and without SNI — a mismatch reveals a default/fallback backend vhost behind the same IP:
```
openssl s_client -connect <host>:443 -servername <host> </dev/null 2>/dev/null | openssl x509 -noout -subject   # SNI
openssl s_client -connect <host>:443                    </dev/null 2>/dev/null | openssl x509 -noout -subject   # no SNI → default vhost
```
Different subjects/SANs = a hidden-origin app or shared-hosting default sitting behind the same IP — a lead for host-header routing attacks (`test_host_header`) and origin discovery. Praetor's `run_tlsx` is currently SNI-only, so run this raw `openssl` comparison manually.

## Related

- `query_crtsh(domain)` — bulk-harvest subdomains from cert logs
- `run_subfinder(domain)` / `run_chaos(domain)` — passive enum (W8)
- `run_dnsx(subdomains)` — bulk DNS resolve
- `extract_links` / `extract_links_batch` / `fetch_page_resources` — pull external links/resources for BLH
- `chain-findings.md` — chain takeover into ATO via cookie-scope hijack
