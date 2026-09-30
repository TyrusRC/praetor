"""fuzz_upload — black-box, structure-aware file-upload fuzzer (Phase 1).

Mutates a minimal valid seed (format-aware) and uploads each mutant THROUGH
Burp (Rule 26 — every send is Logger/Proxy-visible and citable), classifying
parser anomalies (5xx crash, hang, new internal-error signature, size/hash
divergence) against a clean baseline upload.

Safety (HARD Rules 5-9): the deliverable is a crash / parser-anomaly PoC, never
a weaponized upload. No overwrite of existing objects. Campaigns are BOUNDED —
over-threshold volume/time requires an explicit operator `confirmed=True`
(fuzzing volume can DoS the target, Rule 6). Findings are NOT auto-saved: the
tool returns evidence for the operator to run assess_finding / save_finding.
"""

from __future__ import annotations

import hashlib
import json
import random
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP

from praetor import client
from praetor.tools.recon._common import _check_tool, _run_cmd
from . import _seeds

# ── Bounds (DoS gate) ────────────────────────────────────────────────────────
_MAX_FREE_COUNT = 500      # mutants sent without confirmed=True
_MAX_FREE_TIMEOUT = 600    # wall-clock seconds without confirmed=True
_HARD_MAX_COUNT = 5000     # absolute ceiling even with confirmed=True
_HARD_MAX_TIMEOUT = 3600

_MAX_SEED_BYTES = 2 * 1024 * 1024   # reject oversized seeds

# Deterministic in-process RNG seed → reproducible corpus (Rule 10a replay).
_RNG_SEED = 0x50524554  # 'PRET'

# Response-body markers that signal a server-side parser blew up (not a clean
# 4xx rejection). High-signal only, to keep error_signature low-noise.
_ERROR_MARKERS = (
    "traceback (most recent call last)", "segmentation fault", "segfault",
    "core dumped", "fatal error", "panic:", "nullpointerexception",
    "out of memory", "addresssanitizer", "asan:", "heap-buffer-overflow",
    "stack-buffer-overflow", "use-after-free", "double free", "buffer overflow",
    "access violation", "assertion failed", "libpng", "libwebp", "libtiff",
    "imagemagick", "ghostscript", "call to undefined", "unhandled exception",
    "stack trace", "\tat java.", "\tat org.", "\tat com.",
)

_SIZE_DELTA_THRESHOLD = 2048   # bytes; response len divergence to flag differential
_HANG_FLOOR_MS = 500           # never call anything under this a hang
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

_CONTENT_TYPES = {
    "png": "image/png", "jpeg": "image/jpeg", "gif": "image/gif",
    "webp": "image/webp", "pdf": "application/pdf", "svg": "image/svg+xml",
    "zip": "application/zip",
}
_EXT = {"jpeg": "jpg"}


def _default_ct(fmt: str) -> str:
    return _CONTENT_TYPES.get(fmt, "application/octet-stream")


def _default_name(fmt: str) -> str:
    return f"fuzz.{_EXT.get(fmt, fmt or 'bin')}"


# ── Mutation engine selection: afl-fuzz -> radamsa -> in-process ─────────────
async def _radamsa_mutants(seed: bytes, count: int, work: Path) -> list[bytes] | None:
    """Emit `count` mutants via radamsa (deterministic with -s). None on failure."""
    seed_path = work / "seed.in"
    out_pat = str(work / "radamsa-%n.bin")
    try:
        seed_path.write_bytes(seed)
    except Exception:
        return None
    # -s fixes the PRNG seed so the corpus is reproducible.
    _out, _err, rc = await _run_cmd(
        ["radamsa", "-n", str(count), "-s", str(_RNG_SEED), "-o", out_pat, str(seed_path)],
        timeout=120, bypass_proxy=True,
    )
    if rc != 0:
        return None
    mutants: list[bytes] = []
    for p in sorted(work.glob("radamsa-*.bin")):
        try:
            data = p.read_bytes()
        except Exception:
            continue
        if data and data != seed:
            mutants.append(data)
    return mutants or None


async def _gen_mutants(seeds: list[bytes], fmt: str, count: int,
                       work: Path) -> tuple[str, list[bytes]]:
    """Return (engine_name, mutants). Precedence: afl-fuzz -> radamsa -> in-process."""
    per_seed = max(1, count // len(seeds))

    # afl-fuzz havoc: the deep engine needs an INSTRUMENTED harness/binary
    # (Phase 2). It cannot emit mutants standalone in a black-box run, so when
    # only afl-fuzz is present we note it and degrade to the next engine.
    afl_note = " (afl-fuzz present; needs a Phase-2 harness, not used here)" \
        if _check_tool("afl-fuzz") else ""

    if _check_tool("radamsa"):
        collected: list[bytes] = []
        for i, sd in enumerate(seeds):
            sub = work / f"radamsa-{i}"
            sub.mkdir(parents=True, exist_ok=True)
            got = await _radamsa_mutants(sd, per_seed, sub)
            if got is None:
                collected = []
                break
            collected.extend(got)
        if collected:
            # Dedup, keep order, cap to count.
            seen: set[bytes] = set()
            uniq = [m for m in collected if not (m in seen or seen.add(m))]
            return "radamsa" + afl_note, uniq[:count]

    # In-process, structure-aware, deterministic. Blend ~70% grammar-aware
    # (valid-envelope, corrupt-payload — reaches the deep decoder) with ~30%
    # dumb structure-aware edits (breadth). Fixed rng seed => reproducible corpus.
    rng = random.Random(_RNG_SEED)

    def _blend(sd: bytes, want: int) -> list[bytes]:
        g = max(1, (want * 7) // 10)
        m = want - g
        got = _seeds.grammar_mutate(sd, fmt, g, rng)
        if m > 0:
            got += _seeds.mutate(sd, fmt, m, rng)
        return got

    out: list[bytes] = []
    for sd in seeds:
        out.extend(_blend(sd, per_seed))
    if len(out) < count and seeds:
        out.extend(_blend(seeds[0], count - len(out)))
    seen2: set[bytes] = set()
    uniq2 = [m for m in out if not (m in seen2 or seen2.add(m))]
    return "in-process" + afl_note, uniq2[:count]


# ── Upload one file through Burp (raw multipart, byte-exact via ISO-8859-1) ───
def _build_raw(host: str, path: str, parameter: str, filename: str,
               content_type: str, file_bytes: bytes) -> str:
    """Raw multipart/form-data POST as an ISO-8859-1 string (1 char == 1 byte).

    The raw endpoint delivers the request via Burp's ISO-8859-1 byte mapping, so
    a latin-1-decoded body round-trips byte-exact — binary formats survive.
    """
    boundary = "----PraetorFuzz" + uuid.uuid4().hex[:16]
    pre = (f"--{boundary}\r\n"
           f'Content-Disposition: form-data; name="{parameter}"; filename="{filename}"\r\n'
           f"Content-Type: {content_type}\r\n\r\n")
    tail = f"\r\n--{boundary}--\r\n"
    body = pre + file_bytes.decode("latin-1") + tail
    clen = len(body)  # latin-1 => byte count
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {_UA}\r\n"
        f"Accept: */*\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {clen}\r\n"
        f"\r\n"
        f"{body}"
    )


async def _upload(host: str, port: int, https: bool, path: str, parameter: str,
                  filename: str, content_type: str, file_bytes: bytes) -> dict:
    """Send one upload, return {status, length, hash, elapsed_ms, index, body, error?}."""
    raw = _build_raw(host, path, parameter, filename, content_type, file_bytes)
    t0 = time.monotonic()
    resp = await client.post("/api/http/raw", json={
        "raw": raw, "host": host, "port": port, "https": https,
        "cookie_jar": True,
    })
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    if not isinstance(resp, dict) or "error" in resp:
        return {"error": (resp.get("error") if isinstance(resp, dict) else str(resp))}
    status = int(resp.get("status_code", resp.get("status", 0)) or 0)
    body = resp.get("response_body") or ""
    length = int(resp.get("response_length", len(body)) or 0)
    idx = resp.get("history_index", resp.get("proxy_history_index", resp.get("index", -1)))
    if not isinstance(idx, int):
        idx = -1
    return {
        "status": status,
        "length": length,
        "hash": hashlib.sha256(body.encode("latin-1", "replace")).hexdigest()[:16],
        "elapsed_ms": elapsed_ms,
        "index": idx,
        "send_ref": resp.get("send_ref", ""),
        "body": body,
    }


def _classify(baseline: dict, r: dict, budget_ms: int) -> tuple[str, str]:
    """(anomaly_class, marker) vs baseline, or ("", "") when non-anomalous."""
    b_body = baseline.get("body", "").lower()

    # 5xx: the parser choked server-side (a clean 4xx rejection is EXPECTED, not
    # an anomaly — malformed input SHOULD be refused).
    if r["status"] >= 500 and baseline["status"] < 500:
        return "server_error", f"HTTP {r['status']} (baseline {baseline['status']})"

    # Hang: elapsed far over baseline AND over the per-request budget.
    hang_gate = max(5 * baseline["elapsed_ms"], budget_ms, _HANG_FLOOR_MS)
    if r["elapsed_ms"] > hang_gate:
        return "hang", f"{r['elapsed_ms']}ms (baseline {baseline['elapsed_ms']}ms, gate {hang_gate}ms)"

    # New internal-error signature in the body that the baseline did not have.
    low = r["body"].lower()
    for m in _ERROR_MARKERS:
        if m in low and m not in b_body:
            return "error_signature", m.strip()

    # Size/hash divergence beyond threshold (weakest signal).
    if abs(r["length"] - baseline["length"]) > _SIZE_DELTA_THRESHOLD:
        return "differential", f"len {r['length']} vs baseline {baseline['length']}"
    # same length, different content is usually a benign echo — not flagged.
    return "", ""


def _load_seeds(seed_files: list[str] | None, fmt: str) -> tuple[list[bytes], str]:
    """Load seed bytes and resolve the working fmt. Raises ValueError on bad input."""
    if seed_files:
        seeds: list[bytes] = []
        for sf in seed_files:
            p = Path(sf).expanduser()
            if not p.is_file():
                raise ValueError(f"seed file not found: {sf}")
            data = p.read_bytes()
            if not data:
                raise ValueError(f"empty seed file: {sf}")
            if len(data) > _MAX_SEED_BYTES:
                raise ValueError(
                    f"seed too large ({len(data)} B > {_MAX_SEED_BYTES}); reject: {sf}")
            seeds.append(data)
        resolved = fmt or _seeds.detect_fmt(seeds[0]) or "png"
        return seeds, resolved.lower()
    resolved = (fmt or "png").lower()
    return [_seeds.seed_for(resolved)], resolved


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def fuzz_upload(
        endpoint: str,
        seed_files: list[str] | None = None,
        fmt: str = "",
        count: int = 200,
        parameter: str = "file",
        filename: str = "",
        content_type: str = "",
        timeout: int = 300,
        confirmed: bool = False,
        domain: str = "",
    ) -> dict:
        """Black-box structure-aware file-upload fuzzer.

        Mutates a minimal valid seed (format-aware: png/jpeg/gif/webp/pdf/svg/zip,
        or operator-supplied seed_files) and uploads each mutant through Burp,
        classifying server-side parser anomalies against a clean baseline upload:
        5xx crash, hang, new internal-error signature, size/hash divergence. A
        clean 4xx rejection of malformed input is EXPECTED, not an anomaly.

        Deliverable is a crash / parser-anomaly PoC (benign). Findings are NOT
        auto-saved — the returned anomalies (each citing a Burp index/send_ref)
        feed assess_finding / save_finding.

        DoS gate (Rule 6): count<=500 and timeout<=600s run freely; above either
        threshold requires confirmed=True (fuzzing volume can DoS the target).

        Args:
            endpoint: Full upload URL (https://host/path). Scope is tool-enforced.
            seed_files: Paths to operator seed files (a corpus); else a built-in seed.
            fmt: png/jpeg/gif/webp/pdf/svg/zip. Inferred from seed_files/endpoint if omitted.
            count: Mutants to send (default 200). >500 needs confirmed=True.
            parameter: Multipart form field name (default "file").
            filename: Upload filename (default fuzz.<ext>).
            content_type: Part Content-Type (default per fmt).
            timeout: Wall-clock budget seconds (default 300). >600 needs confirmed=True.
            confirmed: Operator sign-off for an over-threshold (DoS-capable) campaign.
            domain: Workspace domain for artifacts (default: endpoint host).
        """
        parts = urlsplit(endpoint if "://" in endpoint else "https://" + endpoint)
        host = parts.hostname
        if not host:
            return {"error": f"could not parse host from endpoint: {endpoint!r}"}
        https = parts.scheme != "http"
        port = parts.port or (443 if https else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        dom = domain or host

        # DoS gate — refuse over-threshold campaigns without explicit confirm.
        if (count > _MAX_FREE_COUNT or timeout > _MAX_FREE_TIMEOUT) and not confirmed:
            return {"error": (
                f"DoS gate: count={count} (max {_MAX_FREE_COUNT}) / "
                f"timeout={timeout}s (max {_MAX_FREE_TIMEOUT}s) exceeds the free "
                "campaign bound. High-volume/long upload fuzzing can DoS the "
                "target (Rule 6). Confirm with the operator and re-call "
                "fuzz_upload(..., confirmed=True) to run this exact campaign.")}
        count = min(count, _HARD_MAX_COUNT)
        timeout = min(timeout, _HARD_MAX_TIMEOUT)

        try:
            seeds, fmt = _load_seeds(seed_files, fmt)
        except ValueError as e:
            return {"error": str(e)}

        ct = content_type or _default_ct(fmt)
        name = filename or _default_name(fmt)

        # Baseline: one CLEAN upload. No baseline => cannot fuzz (Rule 13b).
        base = await _upload(host, port, https, path, parameter, name, ct, seeds[0])
        if "error" in base:
            return {"error": (
                "baseline (clean) upload failed — cannot fuzz without a baseline "
                f"(Rule 13b): {base['error']}")}
        baseline = {
            "status": base["status"], "length": base["length"],
            "response_hash": base["hash"], "elapsed_ms": base["elapsed_ms"],
            "proxy_history_index": base["index"], "body": base["body"],
        }

        # Artifact dir.
        from praetor.tools.workspace import workspace_paths
        run_id = time.strftime("%Y%m%d-%H%M%S")
        try:
            fuzz_root = workspace_paths(dom)["artifacts"] / "fuzz" / run_id
        except ValueError as e:
            return {"error": f"bad domain for workspace: {e}"}
        fuzz_root.mkdir(parents=True, exist_ok=True)

        engine, mutants = await _gen_mutants(seeds, fmt, count, fuzz_root / "_work")
        if not mutants:
            return {"error": f"mutation engine ({engine}) produced no mutants"}

        budget_ms = int(timeout * 1000 / max(len(mutants), 1))
        wall_deadline = time.monotonic() + timeout

        anomalies: list[dict] = []
        sent = 0
        for i, mut in enumerate(mutants):
            if time.monotonic() > wall_deadline:
                break
            r = await _upload(host, port, https, path, parameter, name, ct, mut)
            sent += 1
            if "error" in r:
                continue
            cls, marker = _classify(baseline, r, budget_ms)
            if not cls:
                continue
            # Persist the reproducer mutant (chain of custody).
            mut_name = f"mut-{i:04d}-{cls}.{_EXT.get(fmt, fmt or 'bin')}"
            try:
                (fuzz_root / mut_name).write_bytes(mut)
            except Exception:
                mut_name = ""
            anomalies.append({
                "proxy_history_index": r["index"],
                "send_ref": r.get("send_ref", ""),
                "class": cls,
                "status": r["status"],
                "len_delta": r["length"] - baseline["length"],
                "elapsed_ms": r["elapsed_ms"],
                "marker": marker,
                "mutant_file": mut_name,
            })

        # Persist campaign summary (canonical record; Rule 30).
        summary = {
            "endpoint": endpoint, "fmt": fmt, "engine": engine,
            "parameter": parameter, "baseline": {k: v for k, v in baseline.items()
                                                 if k != "body"},
            "mutants_generated": len(mutants), "sent": sent,
            "anomaly_count": len(anomalies), "anomalies": anomalies,
        }
        try:
            (fuzz_root / "summary.json").write_text(json.dumps(summary, indent=2))
            # Clean up the raw mutation work dir (keeps only reproducers + summary).
            work = fuzz_root / "_work"
            if work.exists():
                for p in work.rglob("*"):
                    if p.is_file():
                        try:
                            p.unlink()
                        except Exception:
                            pass
        except Exception:
            pass

        _CAP = 25  # keep the response compact
        return {
            "engine": engine,
            "fmt": fmt,
            "baseline": {k: v for k, v in baseline.items() if k != "body"},
            "sent": sent,
            "mutants_generated": len(mutants),
            "anomaly_count": len(anomalies),
            "anomalies": anomalies[:_CAP],
            "anomalies_truncated": max(0, len(anomalies) - _CAP),
            "artifact_dir": str(fuzz_root),
            "next": ("assess_finding(vuln_type='file_upload_parser', "
                     "proxy_history_index=<anomaly index>, ...) then save_finding "
                     "for any confirmed parser crash/DoS." if anomalies else
                     "No parser anomalies vs baseline — mutants covered, no finding."),
        }
