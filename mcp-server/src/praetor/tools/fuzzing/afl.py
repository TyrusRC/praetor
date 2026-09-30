"""Local coverage-guided AFL++ lane (Phase 2): build -> fuzz -> triage.

Three operator-invoked tools over an operator-owned harness/binary:

- `afl_build_harness` — compile an ASan+UBSan (optionally CmpLog) instrumented
  harness with afl-clang-fast / afl-cc (fallback afl-gcc).
- `afl_fuzz_target`   — bounded `afl-fuzz` campaign; auto seed-corpus + AFL
  dictionary from the format when omitted; a persistent cross-run corpus
  (`_corpus`) that seeds from and merges back everything earlier runs found; an
  optional CmpLog binary (`-c`); crashes/hangs -> oplog + loot.
- `triage_crashes`    — the exploitability rubric: re-run each crash under the
  sanitizer, parse the report, dedup by stack-hash, classify
  LIKELY-EXPLOITABLE / MEDIUM / BENIGN, minimize with afl-tmin, then judge the
  memory-corruption primitive + byte-taint controllability (+ gdb 'exploitable'
  when present) into a refined_class, and (optionally) confirm the same input
  crashes the SERVER-SIDE parser via the upload lane.

Safety (HARD Rules 5-9): everything here is BENIGN — it FINDS, TRIAGES and
REPRODUCES crashes. It does NOT build shellcode/ROP/working exploits. The rubric
CLASSIFIES exploitability from the sanitizer report; it does not weaponize.

Evidence model: local AFL runs bypass Burp, so crashes are network-lane-style
evidence — operator log (`record_action`) + loot chain-of-custody
(`record_loot`), NOT a proxy_history_index. The crash->upload bridge is the one
step that returns a Burp `proxy_history_index` (the server-side confirm).

Degradation: afl-cc / afl-fuzz / afl-tmin absent -> install hint, never a crash.
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import tempfile
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _check_tool, _run_cmd
from praetor.tools.redteam._oplog import record_action, record_loot
from praetor.tools.workspace import workspace_paths
from . import _seeds

_AFL_INSTALL_HINT = (
    "sudo apt install afl++   (Kali/Debian)   or   "
    "https://github.com/AFLplusplus/AFLplusplus"
)

# afl-tmin can time out on a slow harness; keep per-crash minimize bounded.
_TMIN_TIMEOUT = 60
_TRIAGE_RUN_TIMEOUT = 30
_SAMPLE_CAP = 25          # paths returned in a response (rest are on disk/loot)
_LOOT_CAP = 100           # crash files copied into the loot store per run
_EXCERPT_MAX = 1500       # sanitizer excerpt length stored per unique crash

# Deep exploitability analysis (Part A) — bounded re-execution budgets.
_GDB_TIMEOUT = 30         # gdb+exploitable classification, per crash
_CTRL_EXEC_TIMEOUT = 10   # per byte-taint re-exec of the ASan harness
_CTRL_WALL = 45           # total wall-clock cap for one crash's controllability scan
_CTRL_BUDGET = 64         # max sampled byte offsets per crash (all bytes if smaller)
_CTRL_ADJACENT = 64       # ASan "located <N> bytes to the right" < this => linear off-by-N

# Sanitizer env for a clean, symbolized, deterministic triage re-run.
_TRIAGE_ENV = {
    "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=1:print_summary=1",
    "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
}
# afl-fuzz / afl-cmin / afl-tmin env that keeps them non-interactive and from
# hard-aborting on WSL/CI hosts (no free CPU-governor / affinity / core files).
_AFL_RUN_ENV = {
    "AFL_NO_UI": "1", "AFL_SKIP_CPUFREQ": "1", "AFL_NO_AFFINITY": "1",
    "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1", "AFL_FAST_CAL": "1",
}

_CPP_EXT = (".cc", ".cpp", ".cxx", ".c++", ".cp")
# base compiler -> its C++ driver (used when the source is C++).
_CXX_DRIVER = {
    "afl-clang-fast": "afl-clang-fast++",
    "afl-cc": "afl-c++",
    "afl-gcc": "afl-g++",
}


# ── subprocess helper: reuse _run_cmd but inject AFL/sanitizer env ────────────
# _run_cmd() has no env parameter (it builds its own from os.environ). AFL reads
# its knobs (AFL_USE_ASAN, AFL_LLVM_CMPLOG, AFL_NO_UI, ...) only from the process
# env, so we patch os.environ around the call and restore it.
# NOTE (known ceiling): a global-env patch is not concurrency-safe. The fuzz lane
# is 1-per-host (AGENTS.md fuzz-agent), so AFL calls don't overlap; if that ever
# changes, give this its own env-passing subprocess call instead.
async def _run_afl(cmd: list[str], timeout: int,
                   env: dict[str, str] | None = None) -> tuple[str, str, int]:
    saved: dict[str, str] = {}
    added: list[str] = []
    if env:
        for k, v in env.items():
            if k in os.environ:
                saved[k] = os.environ[k]
            else:
                added.append(k)
            os.environ[k] = str(v)
    try:
        return await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
    finally:
        for k, v in saved.items():
            os.environ[k] = v
        for k in added:
            os.environ.pop(k, None)


def _tail(text: str, n: int = 1500) -> str:
    return (text or "")[-n:].strip()


def _sanitizer_env_flags(sanitizer: str) -> dict[str, str]:
    """Map an 'asan+ubsan'-style spec to AFL_USE_* build env vars."""
    s = (sanitizer or "").lower()
    env = {"AFL_QUIET": "1"}
    if "asan" in s or "address" in s:
        env["AFL_USE_ASAN"] = "1"
    if "ubsan" in s or "undefined" in s:
        env["AFL_USE_UBSAN"] = "1"
    if "msan" in s or "memory" in s:
        env["AFL_USE_MSAN"] = "1"
    if "cfisan" in s or "cfi" in s:
        env["AFL_USE_CFISAN"] = "1"
    if "tsan" in s or "thread" in s:
        env["AFL_USE_TSAN"] = "1"
    return env


def _pick_compiler(is_cpp: bool) -> str:
    """First available AFL compiler (afl-clang-fast > afl-cc > afl-gcc), C++ aware."""
    for base in ("afl-clang-fast", "afl-cc", "afl-gcc"):
        if _check_tool(base):
            if is_cpp:
                cxx = _CXX_DRIVER[base]
                return cxx if _check_tool(cxx) else base
            return base
    return ""


# ── AFL dictionary + seed materialisation (from _seeds) ──────────────────────
def _write_afl_dict(fmt: str, path: Path) -> bool:
    """Write an AFL dictionary from the _seeds format dictionary. False if none."""
    toks = _seeds._DICTS.get((fmt or "").lower())
    if not toks:
        return False
    lines = []
    for i, tok in enumerate(toks):
        esc = "".join(f"\\x{b:02x}" for b in tok)  # every byte escaped => always valid
        lines.append(f'{fmt}_{i}="{esc}"')
    try:
        path.write_text("\n".join(lines) + "\n")
    except Exception:
        return False
    return True


def _materialize_seeds(fmt: str, seed_root: Path) -> str:
    """Write one built-in valid seed for `fmt` into a fresh dir. Returns the dir."""
    seed_root.mkdir(parents=True, exist_ok=True)
    key = (fmt or "png").lower()
    try:
        data = _seeds.seed_for(key)
    except ValueError:
        data = _seeds.seed_for("png")
        key = "png"
    ext = {"jpeg": "jpg"}.get(key, key)
    (seed_root / f"seed0.{ext}").write_bytes(data)
    return str(seed_root)


def _collect_crashes(out_dir: Path) -> tuple[list[Path], list[Path]]:
    """(crashes, hangs) from an afl-fuzz output dir (single-instance 'default')."""
    for base in (out_dir / "default", out_dir):
        cdir, hdir = base / "crashes", base / "hangs"
        crashes = ([p for p in sorted(cdir.iterdir())
                    if p.is_file() and p.name != "README.txt"]
                   if cdir.is_dir() else [])
        hangs = ([p for p in sorted(hdir.iterdir())
                  if p.is_file() and p.name != "README.txt"]
                 if hdir.is_dir() else [])
        if crashes or hangs or cdir.is_dir():
            return crashes, hangs
    return [], []


# ── Sanitizer report parser + exploitability rubric (pure; unit-tested) ──────
_ASAN_TYPE_RE = re.compile(r"AddressSanitizer:\s+([A-Za-z0-9\-]+)")
_UBSAN_RE = re.compile(r"runtime error:\s+([^\n]+)")
_ACCESS_RE = re.compile(r"\b(WRITE|READ) of size (\d+)")
_SEGV_ADDR_RE = re.compile(r"SEGV on unknown address\s+(0x[0-9a-fA-F]+)")
_FRAME_RE = re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)")
_FRAME_RE_MOD = re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+(\([^)]+\))")
# ASan locates an OOB access relative to an allocation: "... 0 bytes to the right
# of 10-byte region". A small offset is an adjacent (linear) overflow; a large or
# absent one is attacker-shaped.
_ASAN_OFFSET_RE = re.compile(r"located\s+(\d+)\s+bytes\s+to\s+the\s+(?:right|left)")


def _parse_sanitizer(report: str, top_n: int = 5) -> dict:
    """Parse an ASan/UBSan stderr report into a structured, hashable summary.

    Returns crash_type, access (WRITE/READ), addr (SEGV fault addr or None), the
    top-N frame function names, a stable stack_hash (dedup key), and an excerpt.
    """
    report = report or ""
    crash_type, access, addr, access_size = "", "", None, None

    m = _ASAN_TYPE_RE.search(report)
    if m:
        crash_type = m.group(1).lower()

    seg = _SEGV_ADDR_RE.search(report)
    if seg:
        try:
            addr = int(seg.group(1), 16)
        except ValueError:
            addr = None
        crash_type = crash_type or "segv"

    am = _ACCESS_RE.search(report)
    if am:
        access = am.group(1).upper()
        try:
            access_size = int(am.group(2))
        except ValueError:
            access_size = None

    if not crash_type:
        u = _UBSAN_RE.search(report)
        if u:
            msg = u.group(1).lower()
            if "member access" in msg or "downcast" in msg or "vptr" in report.lower():
                crash_type = "type-confusion"
            else:
                crash_type = "undefined-behavior"

    frames = _FRAME_RE.findall(report) or _FRAME_RE_MOD.findall(report)
    top = frames[:top_n]

    basis = crash_type + "|" + "|".join(top)
    stack_hash = hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:12]

    idx = report.find("ERROR:")
    if idx < 0:
        idx = report.find("runtime error:")
    excerpt = (report[idx:idx + _EXCERPT_MAX] if idx >= 0
               else report[:_EXCERPT_MAX]).strip()

    return {"crash_type": crash_type, "access": access, "addr": addr,
            "access_size": access_size, "frames": top, "stack_hash": stack_hash,
            "excerpt": excerpt}


def _classify_exploitability(info: dict) -> str:
    """Benign reach-to-shell rubric: crash summary -> exploitability class.

    LIKELY-EXPLOITABLE — WRITE primitives / lifetime bugs (heap-buffer-overflow
      WRITE, use-after-free, double-free, stack-buffer-overflow, type-confusion).
    BENIGN — DoS only (NULL-deref / SEGV at addr ~0, recursion stack-overflow).
    MEDIUM — READ overflows, non-null SEGV, or an unclassified crash.
    """
    ct = (info.get("crash_type") or "").lower()
    access = info.get("access") or ""
    addr = info.get("addr")

    # BENIGN: recursion stack exhaustion (distinct from stack-BUFFER-overflow).
    if ct == "stack-overflow":
        return "BENIGN"
    # BENIGN vs MEDIUM: NULL-deref DoS vs a controllable non-null fault.
    if ct == "segv":
        if addr is not None and addr < 0x1000:
            return "BENIGN"
        return "MEDIUM"

    likely = ("use-after-free", "heap-use-after-free", "double-free",
              "stack-buffer-overflow", "dynamic-stack-buffer-overflow",
              "type-confusion")
    if any(k in ct for k in likely):
        return "LIKELY-EXPLOITABLE"
    if ("heap-buffer-overflow" in ct or "global-buffer-overflow" in ct) and access == "WRITE":
        return "LIKELY-EXPLOITABLE"

    # MEDIUM: READ overflows, other OOB, or an unclassified but real crash.
    return "MEDIUM"


# ── Deep exploitability analysis (pure parts; unit-tested) ───────────────────
def _addr_looks_adjacent(excerpt: str) -> bool:
    """True when the ASan report shows a SMALL 'located <N> bytes to the right/left'
    offset — an adjacent (linear) overflow rather than an attacker-shaped write."""
    m = _ASAN_OFFSET_RE.search(excerpt or "")
    if not m:
        return False
    try:
        return int(m.group(1)) < _CTRL_ADJACENT
    except ValueError:
        return False


def _primitive_from_report(parsed: dict) -> dict:
    """Judge the memory-corruption PRIMITIVE from the ASan parse (benign, static).

    WRITE into an overflow/lifetime class ⇒ a write primitive: attacker-shaped
    (write-what-where, wxw_potential True) unless the report proves it is a small
    ADJACENT overflow (linear-write). READ ⇒ read-oob (info-leak/DoS). Everything
    else ⇒ unknown. This does NOT weaponize — it labels reachability of control.
    """
    ct = (parsed.get("crash_type") or "").lower()
    access = (parsed.get("access") or "").upper()
    size = parsed.get("access_size")
    excerpt = parsed.get("sanitizer_excerpt") or parsed.get("excerpt") or ""

    overflow = any(k in ct for k in
                   ("heap-buffer-overflow", "stack-buffer-overflow",
                    "global-buffer-overflow", "dynamic-stack-buffer-overflow"))
    lifetime = any(k in ct for k in
                   ("use-after-free", "double-free", "type-confusion"))

    if access == "READ":
        return {"primitive": "read-oob", "wxw_potential": False,
                "access_size": size,
                "rationale": "out-of-bounds READ — info-leak / DoS, not a write primitive"}

    if access == "WRITE" and (overflow or lifetime):
        if _addr_looks_adjacent(excerpt) and not lifetime:
            return {"primitive": "linear-write", "wxw_potential": False,
                    "access_size": size,
                    "rationale": "adjacent OOB WRITE (small offset) — linear overflow"}
        return {"primitive": "write-what-where", "wxw_potential": True,
                "access_size": size,
                "rationale": f"attacker-influenced WRITE via {ct or 'memory corruption'}"}

    if access == "WRITE":
        return {"primitive": "linear-write", "wxw_potential": False,
                "access_size": size, "rationale": "WRITE fault, class unclassified"}

    return {"primitive": "unknown", "wxw_potential": False,
            "access_size": size, "rationale": "no WRITE/READ access parsed"}


def _fault_changed(base: dict, info: dict, rc: int) -> bool:
    """Did a one-byte edit REMOVE or RELOCATE the fault vs the base crash?

    Removed  — no crash now (clean rc, no ASan type).
    Relocated — different crash_type, different stack_hash, or a SEGV addr delta.
    Either means that byte STEERS the fault ⇒ it is a controlling byte.
    """
    if not (info.get("crash_type") or "") and rc == 0:
        return True
    if (info.get("crash_type") or "") != (base.get("crash_type") or ""):
        return True
    bh, ih = base.get("stack_hash"), info.get("stack_hash")
    if bh and ih and bh != ih:
        return True
    ba, ia = base.get("addr"), info.get("addr")
    if ba is not None and ia is not None and ba != ia:
        return True
    return False


def _field_windows(data: bytes, fmt: str) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    """Best-effort (size_windows, offset_windows) byte ranges from the format's
    structural tokens: the 4 bytes BEFORE a token are a PNG-style length field;
    the 4 bytes AFTER are a candidate offset/length field. Empty when fmt unknown."""
    toks = _seeds._DICTS.get((fmt or "").lower(), ())
    size_w: list[tuple[int, int]] = []
    off_w: list[tuple[int, int]] = []
    for tok in toks:
        start = 0
        while True:
            i = data.find(tok, start)
            if i < 0:
                break
            if i >= 4:
                size_w.append((i - 4, i))
            off_w.append((i + len(tok), i + len(tok) + 4))
            start = i + 1
    return size_w, off_w


def _in_windows(offset: int, windows: list[tuple[int, int]]) -> bool:
    return any(a <= offset < b for a, b in windows)


def _refine_class(base_class: str, primitive: dict,
                  controllability: dict, gdb: str | None) -> str:
    """Combine class + primitive + byte-taint + gdb into one benign refined label.

    Rules: never UPGRADE a BENIGN NULL-deref/DoS. DOWNGRADE a WRITE to MEDIUM when
    the byte-taint shows the crash is NOT input-driven (0 controlling bytes over a
    non-empty sample). A gdb 'exploitable' verdict corroborates but never fabricates
    control. Stays a CLASSIFICATION, never a weaponization claim.
    """
    prim = (primitive or {}).get("primitive", "unknown")
    wxw = (primitive or {}).get("wxw_potential", False)
    ctrl = controllability or {}
    controlling = ctrl.get("controlling_bytes", 0)
    sampled = ctrl.get("sampled", 0)
    gdb_cls = (gdb or "").upper()
    ratio = f"~{controlling}/{sampled}" if sampled else "not sampled"

    if base_class == "BENIGN":
        return "BENIGN (DoS / not input-shaped)"

    gdb_note = (f", gdb!exploitable={gdb_cls}"
                if gdb_cls in ("EXPLOITABLE", "PROBABLY_EXPLOITABLE") else "")

    if base_class == "LIKELY-EXPLOITABLE":
        if sampled > 0 and controlling == 0:
            return (f"MEDIUM (WRITE not input-driven — 0/{sampled} controlling bytes; "
                    f"crash reproduces but attacker input does not steer the fault)")
        shape = "attacker-controlled WRITE" if wxw else prim
        return f"LIKELY-EXPLOITABLE ({shape}, {ratio} controlling bytes{gdb_note})"

    if base_class == "MEDIUM":
        if gdb_cls == "EXPLOITABLE" and prim != "read-oob":
            return f"LIKELY-EXPLOITABLE (gdb!exploitable, {prim}, {ratio} controlling bytes)"
        return f"MEDIUM ({prim}, {ratio} controlling bytes{gdb_note})"

    return f"{base_class} ({prim})"


def _resolve_crash_inputs(target: str) -> tuple[list[Path], str]:
    """(inputs, error). target = an AFL out dir OR a single crashing-input file."""
    tp = Path(target).expanduser()
    if tp.is_file():
        return [tp], ""
    if tp.is_dir():
        for sub in (tp / "default" / "crashes", tp / "crashes", tp):
            if sub.is_dir():
                found = [p for p in sorted(sub.iterdir())
                         if p.is_file() and p.name != "README.txt"]
                if found:
                    return found, ""
        return [], f"no crashing inputs under {target!r}"
    return [], f"target not found: {target!r}"


# ── Deep exploitability analysis (async; re-runs the ASan harness) ───────────
async def _controllability(harness: Path, crash_input: str, base_parsed: dict,
                           budget: int = _CTRL_BUDGET,
                           timeout: int = _CTRL_EXEC_TIMEOUT) -> dict:
    """Byte-taint the minimized crash input to measure attacker control.

    Zero (or, if already zero, 0xFF) each of up to `budget` sampled offsets, re-run
    the harness under ASan, and count offsets whose edit removes/relocates the fault
    (`_fault_changed`). Bounded by both the sample budget and a wall-clock deadline
    so a slow harness cannot run away. Best-effort: any failure degrades to sampled=0.
    """
    empty = {"controlling_bytes": 0, "sampled": 0, "input_size": 0,
             "size_field_controlled": False, "offset_controlled": False,
             "controlling_offsets": []}
    try:
        data = Path(crash_input).read_bytes()
    except Exception:
        return {**empty, "note": "crash input unreadable"}
    n = len(data)
    if n == 0:
        return {**empty, "note": "empty input"}

    if n <= budget:
        offsets = list(range(n))
    else:
        step = n / float(budget)
        offsets = sorted({int(i * step) for i in range(budget)})

    controlling_offsets: list[int] = []
    sampled = 0
    deadline = time.monotonic() + _CTRL_WALL
    tmp_path = ""
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=Path(crash_input).suffix or ".bin")
        os.close(fd)
        for off in offsets:
            if time.monotonic() > deadline:
                break
            mutant = bytearray(data)
            mutant[off] = 0x00 if mutant[off] != 0x00 else 0xFF
            try:
                Path(tmp_path).write_bytes(bytes(mutant))
                _o, _e, rc = await _run_afl([str(harness), tmp_path],
                                            timeout=timeout, env=_TRIAGE_ENV)
            except Exception:
                continue
            sampled += 1
            info = _parse_sanitizer(_e or _o)
            if _fault_changed(base_parsed, info, rc):
                controlling_offsets.append(off)
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    fmt = _seeds.detect_fmt(data)
    size_w, off_w = _field_windows(data, fmt) if fmt else ([], [])
    return {
        "controlling_bytes": len(controlling_offsets),
        "sampled": sampled,
        "input_size": n,
        "size_field_controlled": any(_in_windows(o, size_w) for o in controlling_offsets),
        "offset_controlled": any(_in_windows(o, off_w) for o in controlling_offsets),
        "controlling_offsets": controlling_offsets[:32],
    }


async def _gdb_exploitable(harness: Path, crash_input: str) -> str | None:
    """Run gdb's 'exploitable' plugin on the crash and return its classification
    (EXPLOITABLE / PROBABLY_EXPLOITABLE / UNKNOWN / ...). None when gdb or the
    plugin is absent, or the classification cannot be parsed. Never raises."""
    if not _check_tool("gdb"):
        return None
    cmd = ["gdb", "-batch", "-nx", "-ex", "run", "-ex", "exploitable",
           "--args", str(harness), str(crash_input)]
    try:
        out, err, _rc = await _run_afl(cmd, timeout=_GDB_TIMEOUT, env=_TRIAGE_ENV)
    except Exception:
        return None
    blob = (out or "") + "\n" + (err or "")
    if "Undefined command" in blob and "exploitable" in blob:
        return None  # gdb present but the plugin is not loaded
    m = re.search(r"Exploitability Classification:\s*([A-Z_]+)", blob)
    return m.group(1) if m else None


# ── crash -> upload bridge (reuses upload.py's upload-through-Burp core) ──────
async def _server_side_confirm(upload_endpoint: str, unique: list[dict],
                               parameter: str = "file") -> dict:
    """Upload each unique crashing input to the server parser and classify vs a
    clean baseline. Reuses upload.py's `_upload` + `_classify` cores (Burp),
    returning citable proxy_history_index anomalies — the web-lane confirm."""
    from urllib.parse import urlsplit
    from .upload import _upload, _classify, _default_ct, _default_name, _MAX_SEED_BYTES

    parts = urlsplit(upload_endpoint if "://" in upload_endpoint
                     else "https://" + upload_endpoint)
    host = parts.hostname
    if not host:
        return {"error": f"could not parse host from upload_endpoint: {upload_endpoint!r}"}
    https = parts.scheme != "http"
    port = parts.port or (443 if https else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    # Format + clean baseline from the first crashing input's magic bytes.
    try:
        first = Path(unique[0]["input"]).read_bytes()
    except Exception as e:
        return {"error": f"could not read crash input for baseline: {e}"}
    fmt = _seeds.detect_fmt(first) or "png"
    ct, name = _default_ct(fmt), _default_name(fmt)

    base = await _upload(host, port, https, path, parameter, name, ct, _seeds.seed_for(fmt))
    if "error" in base:
        return {"error": f"baseline (clean) upload failed — cannot confirm: {base['error']}"}
    baseline = {"status": base["status"], "length": base["length"],
                "elapsed_ms": base["elapsed_ms"], "body": base["body"]}

    confirms = []
    for rec in unique:
        try:
            data = Path(rec["input"]).read_bytes()
        except Exception:
            continue
        if not data or len(data) > _MAX_SEED_BYTES:
            continue
        r = await _upload(host, port, https, path, parameter, name, ct, data)
        if "error" in r:
            continue
        cls, marker = _classify(baseline, r, 10000)
        confirms.append({
            "input": rec["input"],
            "triage_class": rec["class"],
            "server_class": cls or "none",
            "proxy_history_index": r["index"],
            "status": r["status"],
            "marker": marker,
        })
    return {
        "endpoint": upload_endpoint,
        "fmt": fmt,
        "baseline": {"status": baseline["status"], "length": baseline["length"],
                     "elapsed_ms": baseline["elapsed_ms"]},
        "confirms": confirms,
        "anomaly_count": sum(1 for c in confirms if c["server_class"] != "none"),
    }


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def afl_build_harness(
        source: str,
        entrypoint: str = "",
        fmt: str = "",
        sanitizer: str = "asan+ubsan",
        cmplog: bool = False,
        output: str = "",
        timeout: int = 180,
    ) -> dict:
        """Compile an ASan+UBSan-instrumented AFL++ harness from a source file.

        Prefers afl-clang-fast (falls back to afl-cc, then afl-gcc). Enables the
        sanitizers via AFL_USE_ASAN / AFL_USE_UBSAN. Supports both a plain C/C++
        harness (a main() that reads the testcase from its argv file / stdin) and
        a libFuzzer-style harness exporting LLVMFuzzerTestOneInput — the latter is
        linked with -fsanitize=fuzzer (afl-clang-fast supplies the AFL++ driver).
        An optional CmpLog second build (AFL_LLVM_CMPLOG=1) solves magic-byte /
        length comparisons (input-to-state).

        BENIGN (HARD Rules 5-9): builds an instrumented crash-finding harness, not
        an exploit. afl-cc absent -> install hint, no crash.

        Args:
            source: Path to the harness .c/.cc/.cpp source file.
            entrypoint: Reserved (documentational) — the tested entry function name.
            fmt: Target file format (png/jpeg/gif/webp/pdf/svg/zip), for the doc trail.
            sanitizer: Sanitizer spec, e.g. 'asan+ubsan' (also msan/cfisan/tsan).
            cmplog: Also produce a CmpLog build (<harness>.cmplog) for -c in afl-fuzz.
            output: Output harness path (default: <source> with a .afl suffix).
            timeout: Per-compile wall-clock budget (seconds).
        """
        src = Path(source).expanduser()
        if not src.is_file():
            return {"error": f"source file not found: {source}"}

        is_cpp = src.suffix.lower() in _CPP_EXT
        compiler = _pick_compiler(is_cpp)
        if not compiler:
            return {"error": f"afl-cc / afl-clang-fast not installed. Install: {_AFL_INSTALL_HINT}"}

        try:
            text = src.read_text(errors="replace")
        except Exception:
            text = ""
        is_libfuzzer = "LLVMFuzzerTestOneInput" in text

        out = str(Path(output).expanduser()) if output else str(src.with_suffix(".afl"))
        env = _sanitizer_env_flags(sanitizer)

        cmd = [compiler, str(src), "-g", "-O1", "-o", out]
        notes = []
        if is_libfuzzer:
            if "clang" in compiler:
                cmd.append("-fsanitize=fuzzer")
            else:
                notes.append("libFuzzer harness detected but the compiler is not "
                             "clang-based; a main()-driven harness is recommended "
                             "with afl-gcc.")

        out_s, err_s, rc = await _run_afl(cmd, timeout=timeout, env=env)
        build_log = out_s + "\n" + err_s
        if rc != 0:
            return {"error": f"harness compile failed (rc={rc}) with {compiler}",
                    "build_log_tail": _tail(build_log), "notes": notes}
        if not Path(out).is_file():
            return {"error": f"compiler reported success but {out} is missing",
                    "build_log_tail": _tail(build_log), "notes": notes}

        result = {
            "harness_path": out,
            "compiler": compiler,
            "sanitizer": sanitizer,
            "libfuzzer_style": is_libfuzzer,
            "fmt": (fmt or "").lower(),
            "build_log_tail": _tail(build_log),
        }
        if notes:
            result["notes"] = notes

        # Optional CmpLog second build (input-to-state). LLVM-only.
        if cmplog:
            if "clang" not in compiler:
                result["cmplog_note"] = ("CmpLog needs an LLVM compiler "
                                         "(afl-clang-fast); skipped for " + compiler)
            else:
                cmplog_out = out + ".cmplog"
                cmplog_env = dict(env)
                cmplog_env["AFL_LLVM_CMPLOG"] = "1"
                c_out, c_err, c_rc = await _run_afl(
                    [compiler, str(src), "-g", "-O1", "-o", cmplog_out]
                    + (["-fsanitize=fuzzer"] if is_libfuzzer else []),
                    timeout=timeout, env=cmplog_env)
                if c_rc == 0 and Path(cmplog_out).is_file():
                    result["cmplog_path"] = cmplog_out
                    result["cmplog_hint"] = f"pass to afl_fuzz_target via cmplog_binary='{cmplog_out}'"
                else:
                    result["cmplog_note"] = "CmpLog build failed"
                    result["cmplog_log_tail"] = _tail(c_out + "\n" + c_err)

        result["next"] = (f"afl_fuzz_target(harness='{out}', "
                          f"fmt='{(fmt or '').lower()}', timeout=600, domain='<domain>')")
        return result

    @mcp.tool()
    async def afl_fuzz_target(
        harness: str,
        seed_dir: str = "",
        dict_path: str = "",
        fmt: str = "",
        timeout: int = 600,
        extra_args: str = "",
        domain: str = "",
        persist: bool = True,
        cmplog_binary: str = "",
    ) -> dict:
        """Run a bounded, time-boxed AFL++ campaign against an instrumented harness.

        Auto-provisions what is missing: an empty seed_dir is seeded from the
        persistent cross-run corpus (built-in valid seed for `fmt` ∪ everything
        earlier runs discovered); an empty dict_path is written from the `fmt`
        structural dictionary (chunk/marker/atom tokens); the corpus is minimized
        with afl-cmin when present. Runs `afl-fuzz -i .. -o .. -V <timeout>`
        (self-exits after the budget) with a hard timeout guard on top. Crashes/
        hangs are recorded to the operator log + loot chain-of-custody (local AFL
        bypasses Burp — no proxy_history_index here).

        With `persist` (default) the campaign SEEDS from and MERGES BACK into a
        per-(domain, fmt) corpus under artifacts/fuzz/corpus/<fmt>/, so input-to-
        state progress compounds across runs instead of restarting from one seed.
        With `cmplog_binary` (the `cmplog_path` from afl_build_harness), `-c <bin>`
        is added so AFL++ solves magic-byte / length comparisons (input-to-state).

        BENIGN (HARD Rules 5-9): produces crashing inputs, not exploits. afl-fuzz
        absent -> install hint, no crash. The harness receives each testcase as an
        argv file ('@@').

        Args:
            harness: Path to an AFL-instrumented harness (from afl_build_harness).
            seed_dir: Corpus dir; empty -> persistent corpus / built-in seed for `fmt`.
            dict_path: AFL dictionary; empty + known `fmt` -> auto-written.
            fmt: png/jpeg/gif/webp/pdf/svg/zip — drives seed + dictionary selection.
            timeout: Campaign seconds (`-V`). Wall-clock guard is timeout+60.
            extra_args: Extra afl-fuzz flags before '--' (e.g. '-x <dict>').
            domain: Workspace domain for artifacts + oplog (default 'local-afl').
            persist: Seed from and merge queue/crashes back into the persistent corpus.
            cmplog_binary: CmpLog build (afl_build_harness `cmplog_path`) -> `-c <bin>`.
        """
        if not _check_tool("afl-fuzz"):
            return {"error": f"afl-fuzz not installed. Install: {_AFL_INSTALL_HINT}"}
        hp = Path(harness).expanduser()
        if not hp.is_file():
            return {"error": f"harness not found: {harness}"}

        dom = domain or "local-afl"
        try:
            fuzz_root = workspace_paths(dom)["artifacts"] / "fuzz" / time.strftime("afl-%Y%m%d-%H%M%S")
        except ValueError as e:
            return {"error": f"bad domain for workspace: {e}"}
        fuzz_root.mkdir(parents=True, exist_ok=True)

        fmt = (fmt or "").lower()
        # Lazy import keeps fuzzing package import ordering safe (afl <-> _corpus).
        from . import _corpus
        corpus_fmt = fmt or "bin"
        if seed_dir and not Path(seed_dir).exists():
            return {"error": f"seed_dir not found: {seed_dir}"}
        if persist:
            try:
                extra = [seed_dir] if seed_dir else []
                seed_dir = _corpus.seed_corpus(dom, corpus_fmt, extra)
            except Exception:
                if not seed_dir:
                    seed_dir = _materialize_seeds(fmt, fuzz_root / "seeds")
        elif not seed_dir:
            seed_dir = _materialize_seeds(fmt, fuzz_root / "seeds")
        elif not Path(seed_dir).is_dir():
            return {"error": f"seed_dir not found: {seed_dir}"}

        if not dict_path and fmt:
            dp = fuzz_root / f"{fmt}.dict"
            if _write_afl_dict(fmt, dp):
                dict_path = str(dp)

        # Optional corpus minimization.
        cmin_note = ""
        if _check_tool("afl-cmin"):
            min_dir = fuzz_root / "seeds_min"
            _o, _e, rc = await _run_afl(
                ["afl-cmin", "-i", seed_dir, "-o", str(min_dir), "--", str(hp), "@@"],
                timeout=min(120, timeout), env=_AFL_RUN_ENV)
            if rc == 0 and min_dir.is_dir() and any(min_dir.iterdir()):
                seed_dir = str(min_dir)
                cmin_note = "corpus minimized with afl-cmin"

        out_dir = fuzz_root / "out"
        cmd = ["afl-fuzz", "-i", seed_dir, "-o", str(out_dir), "-V", str(timeout)]
        if dict_path:
            cmd += ["-x", dict_path]
        cmplog_note = ""
        if cmplog_binary:
            cb = Path(cmplog_binary).expanduser()
            if cb.is_file():
                cmd += ["-c", str(cb)]
            else:
                cmplog_note = f"cmplog_binary not found, ran without -c: {cmplog_binary}"
        if extra_args:
            cmd += shlex.split(extra_args)
        cmd += ["--", str(hp), "@@"]

        out_s, err_s, rc = await _run_afl(cmd, timeout=timeout + 60, env=_AFL_RUN_ENV)
        crashes, hangs = _collect_crashes(out_dir)

        if rc != 0 and not crashes and not hangs:
            return {"error": f"afl-fuzz did not start/complete (rc={rc})",
                    "log_tail": _tail(out_s + "\n" + err_s), "out_dir": str(out_dir)}

        # Evidence: operator log + loot chain-of-custody (network-lane style).
        oplog_id = record_action(
            dom, tool="afl-fuzz", command=" ".join(cmd),
            description=f"AFL++ campaign fmt={fmt or '?'} V={timeout}s "
                        f"crashes={len(crashes)} hangs={len(hangs)}",
            target=str(hp), output=_tail(err_s or out_s, 2000), returncode=rc,
            tactic="Resource Development", technique="T1587.004",
            tags=["fuzz", "afl++"])
        for c in crashes[:_LOOT_CAP]:
            try:
                record_loot(dom, "afl-crash", str(c), source_host=str(hp),
                            obtained_via="afl-fuzz", oplog_id=oplog_id, is_path=True)
            except Exception:
                pass

        # Persistent corpus: fold this run's queue + crashes back into the store.
        corpus_merged = None
        if persist:
            try:
                corpus_merged = _corpus.merge_back(dom, corpus_fmt, out_dir)
            except Exception:
                corpus_merged = None

        result = {
            "out_dir": str(out_dir),
            "crashes": len(crashes),
            "hangs": len(hangs),
            "sample_crashes": [str(p) for p in crashes[:_SAMPLE_CAP]],
            "seed_dir": seed_dir,
            "dict": dict_path or "",
            "oplog_id": oplog_id,
            "engine": "afl-fuzz",
            "persist": persist,
            "cmplog": bool(cmplog_binary),
        }
        if corpus_merged is not None:
            result["corpus_merged"] = corpus_merged
        if cmplog_note:
            result["cmplog_note"] = cmplog_note
        if cmin_note:
            result["cmin"] = cmin_note
        result["next"] = (
            f"triage_crashes(target='{out_dir}', harness='{harness}', "
            f"upload_endpoint='<server upload URL>', domain='{dom}')"
            if crashes else
            "no crashes in the budget — raise timeout, pass a CmpLog build "
            "(cmplog_binary='<harness>.afl.cmplog'), or improve the seed corpus/dictionary")
        return result

    @mcp.tool()
    async def triage_crashes(
        target: str,
        harness: str,
        minimize: bool = True,
        upload_endpoint: str = "",
        domain: str = "",
        deep: bool = True,
    ) -> dict:
        """Exploitability rubric: classify AFL crashes benignly (reach-to-shell).

        For each crashing input (target = an AFL out dir OR a single input file):
        re-run `harness <input>` under the sanitizer, parse the ASan/UBSan report
        (crash type + faulting access + top frames), compute a stable stack_hash,
        and CLASSIFY:
          LIKELY-EXPLOITABLE — heap-buffer-overflow WRITE, use-after-free,
            double-free, stack-buffer-overflow, type-confusion (write primitives).
          MEDIUM — READ overflows, non-null SEGV, or unclassified crashes.
          BENIGN — NULL-deref / SEGV at addr ~0 / recursion stack-overflow (DoS).
        Duplicates (same stack_hash) collapse to one unique reproducer; each is
        minimized with afl-tmin when present and recorded as loot.

        With `deep` (default) each unique, minimized crash also gets an
        exploitability JUDGMENT (never a weaponization): the memory-corruption
        `primitive` (write-what-where / linear-write / read-oob), a byte-taint
        `controllability` scan (which input bytes steer the fault), an optional
        `gdb_exploitable` classification (gdb + the 'exploitable' plugin, when
        present), and a combined `refined_class` — a WRITE with no input-driven
        bytes is DOWNGRADED, a BENIGN NULL-deref is never upgraded. `deep=False`
        skips the extra bounded re-executions.

        This CLASSIFIES exploitability from the sanitizer output (HARD Rules 5-9);
        it does not weaponize. Given `upload_endpoint`, it also confirms the same
        inputs crash the SERVER-SIDE parser (server_side_confirm, with citable
        proxy_history_index anomalies) via the upload lane.

        Args:
            target: An afl-fuzz output dir, a .../crashes dir, or one crash file.
            harness: The ASan-instrumented harness to re-run each input against.
            minimize: Minimize each unique reproducer with afl-tmin (when present).
            upload_endpoint: Optional server upload URL for the crash->upload confirm.
            domain: Workspace domain for artifacts + oplog (default 'local-afl').
            deep: Run the bounded primitive / byte-taint / gdb exploitability judgment.
        """
        hp = Path(harness).expanduser()
        if not hp.is_file():
            return {"error": f"harness not found: {harness}"}
        inputs, err = _resolve_crash_inputs(target)
        if err:
            return {"error": err}

        dom = domain or "local-afl"
        try:
            tri_root = workspace_paths(dom)["artifacts"] / "fuzz" / time.strftime("triage-%Y%m%d-%H%M%S")
        except ValueError as e:
            return {"error": f"bad domain for workspace: {e}"}
        tri_root.mkdir(parents=True, exist_ok=True)

        do_min = minimize and _check_tool("afl-tmin")
        seen: dict[str, dict] = {}
        unique: list[dict] = []
        counts = {"LIKELY-EXPLOITABLE": 0, "MEDIUM": 0, "BENIGN": 0}
        reproduced = 0

        for inp in inputs:
            out_s, err_s, rc = await _run_afl([str(hp), str(inp)],
                                              timeout=_TRIAGE_RUN_TIMEOUT, env=_TRIAGE_ENV)
            report = err_s or out_s
            info = _parse_sanitizer(report)
            # A crash is a sanitizer report OR a non-zero/aborted exit.
            if not info["crash_type"] and rc == 0:
                continue
            reproduced += 1
            sh = info["stack_hash"]
            if sh in seen:
                seen[sh]["duplicate_count"] += 1
                continue
            klass = _classify_exploitability(info)
            rec = {
                "input": str(inp),
                "class": klass,
                "crash_type": info["crash_type"] or "unknown",
                "access": info["access"],
                "stack_hash": sh,
                "top_frames": info["frames"],
                "sanitizer_excerpt": info["excerpt"],
                "duplicate_count": 0,
            }
            # Minimize first so the deep analysis taints the SMALL reproducer.
            analysis_input = str(inp)
            if do_min:
                min_path = tri_root / f"min-{sh}{inp.suffix or '.bin'}"
                _o, _e, m_rc = await _run_afl(
                    ["afl-tmin", "-i", str(inp), "-o", str(min_path), "--", str(hp), "@@"],
                    timeout=_TMIN_TIMEOUT, env=_AFL_RUN_ENV)
                if m_rc == 0 and min_path.is_file():
                    rec["minimized_path"] = str(min_path)
                    analysis_input = str(min_path)

            # Deep exploitability judgment (bounded re-execs) — benign classification.
            primitive = _primitive_from_report(info)
            controllability: dict = {}
            gdb_cls = None
            if deep:
                try:
                    controllability = await _controllability(hp, analysis_input, info)
                except Exception:
                    controllability = {}
                try:
                    gdb_cls = await _gdb_exploitable(hp, analysis_input)
                except Exception:
                    gdb_cls = None
            rec["primitive"] = primitive
            rec["controllability"] = controllability
            rec["gdb_exploitable"] = gdb_cls
            rec["refined_class"] = _refine_class(klass, primitive, controllability, gdb_cls)

            seen[sh] = rec
            unique.append(rec)
            counts[klass] = counts.get(klass, 0) + 1

        # Evidence: operator log + loot (minimized reproducer + sanitizer excerpt).
        oplog_id = record_action(
            dom, tool="afl-triage",
            command=f"triage {len(inputs)} input(s) against {hp}",
            description=f"{reproduced} reproduced, {len(unique)} unique; "
                        f"L/M/B={counts['LIKELY-EXPLOITABLE']}/{counts['MEDIUM']}/{counts['BENIGN']}",
            target=str(hp), returncode=0,
            tactic="Resource Development", technique="T1587.004",
            tags=["fuzz", "triage"])
        for rec in unique:
            try:
                record_loot(dom, "afl-crash-reproducer",
                            rec.get("minimized_path") or rec["input"],
                            source_host=str(hp), obtained_via="triage_crashes",
                            oplog_id=oplog_id, is_path=True)
                if rec["sanitizer_excerpt"]:
                    record_loot(dom, "sanitizer-report", rec["sanitizer_excerpt"],
                                source_host=str(hp), obtained_via="triage_crashes",
                                oplog_id=oplog_id)
            except Exception:
                pass

        result = {
            "harness": str(hp),
            "inputs_examined": len(inputs),
            "reproduced": reproduced,
            "non_reproduced": len(inputs) - reproduced,
            "unique_crashes": unique[:_SAMPLE_CAP],
            "unique_truncated": max(0, len(unique) - _SAMPLE_CAP),
            "counts_by_class": counts,
            "minimized": do_min,
            "deep": deep,
            "oplog_id": oplog_id,
        }
        if not do_min and minimize:
            result["minimize_note"] = f"afl-tmin not installed. Install: {_AFL_INSTALL_HINT}"

        # Crash -> upload bridge (server-side parser confirm, web-lane evidence).
        if upload_endpoint and unique:
            result["server_side_confirm"] = await _server_side_confirm(upload_endpoint, unique)

        likely = counts["LIKELY-EXPLOITABLE"]
        result["next"] = (
            "LIKELY-EXPLOITABLE crash(es) with a reproducer -> assess_finding("
            "vuln_type='memory_corruption', ...) then save_finding (HIGH/CRITICAL "
            "for a reproduced parser memory-corruption). Cite the server_side_confirm "
            "proxy_history_index when the same input crashes the target."
            if likely else
            "no LIKELY-EXPLOITABLE crash — MEDIUM/BENIGN are DoS-class; add a CmpLog "
            "build or better seeds, or record as a DoS note.")
        return result
