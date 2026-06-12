# Fuzz Hidden Paths — Smart Wordlist + ffuf

Use when discovering hidden directories / files on a known target. Replaces spray fuzzing with tech-aware SecLists slicing fed by recon intel.

## SMART MOVE — first call

```
1. detect_tech_stack(url)             — slice wordlist to stack
2. wl = generate_smart_wordlist(domain, tier='small')
3. run_ffuf(url, wordlist=wl, status_codes='200,301,302,401,403')
4. for hit in hits[:10]: smart_request_triage(index_of_hit)
5. annotate_request + send_to_organizer per Rule 18
```

## Preconditions

- Target intel populated: `.burp-intel/<domain>/fingerprint.json` (tech stack) + `endpoints.json` (recon-derived paths). Run `full_recon` or `discover_attack_surface` first if missing.
- SecLists installed and discoverable. Run `check_recon_tools` — if "SecLists: NOT FOUND", install per the hint.
- ffuf installed. `run_ffuf` is the project's ffuf wrapper; it auto-proxies through Burp (127.0.0.1:8080).

## Workflow

1. `detect_tech_stack(domain)` — confirm `fingerprint.json` is current
2. `generate_smart_wordlist(domain, tier='medium')` — returns `{path, total, breakdown}`
3. Establish baseline. Hit a known-bad path (e.g., `/this-does-not-exist-XYZ`). Note response length — that's your `filter_size`.
4. `run_ffuf(url='https://target.example/FUZZ', wordlist=<path from step 2>, match_codes=[200,204,301,307,401,403,500], filter_size=<baseline>)` — routes through Burp proxy automatically (Rule 26a). Hits land in Proxy history.
5. For each hit:
   - `annotate_request(idx, color='YELLOW', comment='<f-id> | hidden-path | ' + url)`
   - `send_to_organizer(idx)`
6. After the run, `save_target_intel(domain, kind='endpoints', data={...})` — merge new hits with the existing endpoints list. Dedup by URL.

## Tier guidance

- `shallow` (~500): quick triage. Use mid-engagement to recheck after KB updates.
- `medium` (~5k): default. One pass per new asset.
- `deep` (~50k): heavy. Use only when shallow + medium yielded nothing and time permits.

## Extensions

Pass `extensions=['php','bak','old','swp']` to permute each entry. Useful when fingerprint shows PHP but you suspect leftover backup files.

## Anti-patterns

- Do NOT use a generic 2-million-line wordlist. That's the noise tier. Fingerprinted-stack-first.
- Do NOT run two ffuf passes against the same host in parallel (WAF tripping). The `fuzz-agent` dispatch rule enforces this — respect it.
- Do NOT skip the baseline-`filter_size` step. False positives multiply otherwise.
