---
description: Structure-aware file-upload fuzzing to find server-side parser bugs (memory corruption / DoS) + CVE-exploitability verdict. Use when a target accepts file uploads (image/PDF/archive) or when a detected tech+version has a memory-corruption/parser CVE to confirm.
globs:
---

# File-Upload Fuzzing + CVE Exploitability

Load when: the target has an upload endpoint (avatar/image/document/import), a
server-side image/PDF thumbnailer or converter is in the stack (ImageMagick,
libvips, libwebp, Ghostscript, poppler), or a fingerprinted tech+version maps
to a memory-corruption/parser CVE you need to confirm is real *here*.

## Safety (HARD Rules 5–9 — non-negotiable)

The PoC is a **crash / sanitizer report / server-side parser anomaly** (5xx,
hang/timeout, differential internal error). That is the professional deliverable
for a memory-corruption bug — it proves the parser mishandles attacker input.
The tools **find, triage, and reproduce** crashes; they do **not** weaponize a
shell. Campaigns are **bounded** and **DoS-gated** (`confirmed=True` above the
threshold) — upload-fuzzing volume can DoS the target (Rule 6 / ToS).

## Why structure-aware, not blind

Random bitflipping rarely reaches parser code past the magic-byte/length checks.
Real CVEs come from **format-aware** mutation: valid seeds + dictionaries
(PNG chunks, JPEG markers, WebP `RIFF`/`VP8L` atoms, PDF objects, ZIP records),
then corrupting length fields, duplicating/truncating chunks, and injecting
structural tokens at boundaries. Canonical target: **CVE-2023-4863** — a crafted
`.webp` lossless (`VP8L`) triggers a heap overflow in libwebp; the built-in webp
seed is a `VP8L` chunk for exactly this surface.

## Workflow

### 1. Black-box mutation-upload (universal — no local binary)

```
fuzz_upload(endpoint, fmt="webp", parameter="file", count=200, domain=<d>)
```
- Auto-uses a built-in valid seed + dictionary when `seed_files` is omitted;
  supply real samples for a richer corpus.
- Mutation engine precedence: `afl-fuzz` → `radamsa` → in-process (deterministic,
  seeded). The `engine` field in the result says which ran.
- Takes ONE clean baseline upload first; if the clean upload errors/blocks it
  returns an error (Rule 13b — no baseline, no verdict).
- Flags only real anomalies vs baseline: **5xx**, **hang** (elapsed ≫ baseline),
  **new internal-error signature**, size divergence. A clean 4xx is expected,
  not an anomaly.
- Bounded: `count<=500` and `timeout<=600s` run freely; above either, re-call
  with `confirmed=True` (DoS gate). Reproducer mutants + `summary.json` land in
  `.burp-intel/<domain>/artifacts/fuzz/<run_id>/`.
- Each upload routes through Burp → cite the anomaly's `proxy_history_index`.

Then verify a flagged mutant per the normal pipeline: replay ≥3× (crash/hang is
a timing/blind class → `reproductions[]`), `assess_finding`, `save_finding`. A
reproduced server-side parser crash is HIGH (DoS) / CRITICAL if the class +
context indicate memory corruption with attacker-controlled size.

### 2. CVE exploitability verdict (is the CVE real *here*)

```
assess_cve_exploitability(domain, tech="ImageMagick", version="7.1.0", endpoint=<upload>)
```
- Resolves candidate CVEs → weights by KEV/EPSS → checks the target actually
  meets the CVE's **preconditions** (reachable route/feature, not a banner guess)
  → fires the adapted **benign** PoC.
- `exploitable_here=True` ONLY when the benign PoC fired and produced
  class-consistent evidence with a citable `proxy_history_index`/collaborator id.
  A version match alone is `reachable`, **not** `exploitable_here` (Rule 13c: a
  banner/scanner guess is a lead, not proof).
- Memory-corruption/parser CVEs (CWE-119/125/416/787) are routed to the fuzzing
  lane instead of a fake in-band verdict (Phase-2 AFL bridge).

## Interpreting results

- **5xx on a mutant** = the parser threw on attacker input — strong lead; replay
  and read the body (stack trace / library name pins the vulnerable parser).
- **Hang/timeout** = potential algorithmic-complexity or infinite-loop DoS.
- **Differential internal error not in baseline** = parser reached an unexpected
  state — investigate, may be the edge of a memory bug.
- No anomaly after a valid baseline + real mutants = covered-negative for that
  format/endpoint; a malformed baseline or wrong `parameter` = INCONCLUSIVE, not
  benign (fix the upload, re-run).

## Local coverage-guided AFL++ (Phase 2 — when available)

When a local build/binary of the parser exists, coverage-guided AFL++ finds
deeper bugs: instrument with ASan+UBSan (+CmpLog), fuzz to real crashes, triage
with the exploitability rubric (read the sanitizer report → LIKELY-EXPLOITABLE /
MEDIUM / BENIGN, dedup by stack-hash, minimize with `afl-tmin`), then bridge the
crashing input to `fuzz_upload` to confirm it crashes the server-side parser.
