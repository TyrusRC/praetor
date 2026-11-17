"""Sanitizer report parser + exploitability rubric for AFL++ triage.

Pure functions (unit-testable, no Burp) that parse ASan/UBSan crash reports,
classify exploitability (LIKELY-EXPLOITABLE / MEDIUM / BENIGN), judge the
memory-corruption primitive, and measure byte-taint controllability.

Extracted from afl.py — called by triage_crashes via the afl module.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import time
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any

from . import _seeds

# ── Deep exploitability analysis — bounded re-execution budgets ────────────
_GDB_TIMEOUT = 30
_CTRL_EXEC_TIMEOUT = 10
_CTRL_WALL = 45
_CTRL_BUDGET = 64
_CTRL_ADJACENT = 64

_TRIAGE_ENV = {
    "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=1:print_summary=1",
    "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
}

_EXCERPT_MAX = 1500

# ── Sanitizer report parser regexes ────────────────────────────────────────
_ASAN_TYPE_RE = re.compile(r"AddressSanitizer:\s+([A-Za-z0-9\-]+)")
_UBSAN_RE = re.compile(r"runtime error:\s+([^\n]+)")
_ACCESS_RE = re.compile(r"\b(WRITE|READ) of size (\d+)")
_SEGV_ADDR_RE = re.compile(r"SEGV on unknown address\s+(0x[0-9a-fA-F]+)")
_FRAME_RE = re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)")
_FRAME_RE_MOD = re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+(\([^)]+\))")
_ASAN_OFFSET_RE = re.compile(r"located\s+(\d+)\s+bytes\s+to\s+the\s+(?:right|left)")

# Type alias for the async run function passed from afl.py.
RunFn = Callable[..., Coroutine[Any, Any, tuple[str, str, int]]]


# ── Sanitizer report parser + exploitability rubric (pure; unit-tested) ────

def parse_sanitizer(report: str, top_n: int = 5) -> dict:
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


def classify_exploitability(info: dict) -> str:
    """Benign reach-to-shell rubric: crash summary -> exploitability class.

    LIKELY-EXPLOITABLE — WRITE primitives / lifetime bugs (heap-buffer-overflow
      WRITE, use-after-free, double-free, stack-buffer-overflow, type-confusion).
    BENIGN — DoS only (NULL-deref / SEGV at addr ~0, recursion stack-overflow).
    MEDIUM — READ overflows, non-null SEGV, or an unclassified crash.
    """
    ct = (info.get("crash_type") or "").lower()
    access = info.get("access") or ""
    addr = info.get("addr")

    if ct == "stack-overflow":
        return "BENIGN"
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

    return "MEDIUM"


# ── Deep exploitability analysis (pure parts; unit-tested) ─────────────────

def addr_looks_adjacent(excerpt: str) -> bool:
    """True when the ASan report shows a SMALL offset — an adjacent overflow."""
    m = _ASAN_OFFSET_RE.search(excerpt or "")
    if not m:
        return False
    try:
        return int(m.group(1)) < _CTRL_ADJACENT
    except ValueError:
        return False


def primitive_from_report(parsed: dict) -> dict:
    """Judge the memory-corruption PRIMITIVE from the ASan parse (benign, static).

    WRITE into an overflow/lifetime class => a write primitive: attacker-shaped
    (write-what-where, wxw_potential True) unless the report proves it is a small
    ADJACENT overflow (linear-write). READ => read-oob (info-leak/DoS). Everything
    else => unknown. This does NOT weaponize — it labels reachability of control.
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
        if addr_looks_adjacent(excerpt) and not lifetime:
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


def fault_changed(base: dict, info: dict, rc: int) -> bool:
    """Did a one-byte edit REMOVE or RELOCATE the fault vs the base crash?"""
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


def field_windows(data: bytes, fmt: str) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    """Best-effort (size_windows, offset_windows) byte ranges from structural tokens."""
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


def in_windows(offset: int, windows: list[tuple[int, int]]) -> bool:
    return any(a <= offset < b for a, b in windows)


def refine_class(base_class: str, primitive: dict,
                 controllability: dict, gdb: str | None) -> str:
    """Combine class + primitive + byte-taint + gdb into one benign refined label."""
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


def resolve_crash_inputs(target: str) -> tuple[list[Path], str]:
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


# ── Deep exploitability analysis (async; re-runs the ASan harness) ─────────

async def controllability(harness: Path, crash_input: str, base_parsed: dict,
                          run_fn: RunFn,
                          budget: int = _CTRL_BUDGET,
                          timeout: int = _CTRL_EXEC_TIMEOUT) -> dict:
    """Byte-taint the minimized crash input to measure attacker control.

    `run_fn` is the async subprocess runner (afl._run_afl); passed explicitly
    to avoid circular imports.
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
                _o, _e, rc = await run_fn([str(harness), tmp_path],
                                          timeout=timeout, env=_TRIAGE_ENV)
            except Exception:
                continue
            sampled += 1
            info = parse_sanitizer(_e or _o)
            if fault_changed(base_parsed, info, rc):
                controlling_offsets.append(off)
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    fmt = _seeds.detect_fmt(data)
    size_w, off_w = field_windows(data, fmt) if fmt else ([], [])
    return {
        "controlling_bytes": len(controlling_offsets),
        "sampled": sampled,
        "input_size": n,
        "size_field_controlled": any(in_windows(o, size_w) for o in controlling_offsets),
        "offset_controlled": any(in_windows(o, off_w) for o in controlling_offsets),
        "controlling_offsets": controlling_offsets[:32],
    }


async def gdb_exploitable(harness: Path, crash_input: str,
                          run_fn: RunFn, check_tool_fn: Callable) -> str | None:
    """Run gdb's 'exploitable' plugin on the crash. None when unavailable."""
    if not check_tool_fn("gdb"):
        return None
    cmd = ["gdb", "-batch", "-nx", "-ex", "run", "-ex", "exploitable",
           "--args", str(harness), str(crash_input)]
    try:
        out, err, _rc = await run_fn(cmd, timeout=_GDB_TIMEOUT, env=_TRIAGE_ENV)
    except Exception:
        return None
    blob = (out or "") + "\n" + (err or "")
    if "Undefined command" in blob and "exploitable" in blob:
        return None
    m = re.search(r"Exploitability Classification:\s*([A-Z_]+)", blob)
    return m.group(1) if m else None
