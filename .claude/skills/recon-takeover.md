---
description: Subdomain takeover hunt — CNAME-fingerprint match + dns_only signal. Use when target has wildcard scope or you've harvested a subdomain list.
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

## Related

- `query_crtsh(domain)` — bulk-harvest subdomains from cert logs
- `run_subfinder(domain)` / `run_chaos(domain)` — passive enum (W8)
- `run_dnsx(subdomains)` — bulk DNS resolve
- `chain-findings.md` — chain takeover into ATO via cookie-scope hijack
