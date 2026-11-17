"""Pickle/model-file safety scan (stdlib pickletools, no execution).

Pickle's RCE surface is GLOBAL (module, name) opcodes that resolve to an
arbitrary callable, invoked by REDUCE at load time. Disassembling with
pickletools.genops never calls __reduce__/__setstate__ — it only reads the
opcode stream, so this is safe to run on an untrusted file.
"""

from __future__ import annotations

import json
import pickletools
import zipfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Modules with no legitimate reason to appear in a data-only pickle stream —
# flagged on module alone. `builtins`/`__builtin__` is NOT here: it also
# carries harmless, extremely common REDUCE targets (list/dict/set/tuple/...)
# used by ordinary object serialization, so it is name-gated below instead.
_DANGEROUS_MODULES = {
    "os", "nt", "posix", "subprocess", "sys", "socket", "shutil", "pty",
    "runpy", "code", "ctypes", "platform", "importlib", "multiprocessing",
    "webbrowser", "pdb", "antigravity",
}
# Names that are dangerous regardless of which module they resolve through
# (mainly builtins/__builtin__, but matched module-independently so an
# aliased import doesn't slip past).
_DANGEROUS_NAMES = {
    "eval", "exec", "system", "popen", "Popen", "call", "check_call",
    "check_output", "execfile", "compile", "__import__", "getattr",
    "setattr", "open",
}


_STRING_PUSH_OPS = {
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING",
}


def _scan_pickle_bytes(data: bytes) -> list[str]:
    """Disassemble (not unpickle) a pickle byte stream; return dangerous
    module.name references found, deduped, in appearance order.

    Protocol 0's GLOBAL opcode carries 'module\\nname' directly in `arg`.
    Protocol >=4's STACK_GLOBAL is stack-based instead: the module and name
    are pushed as two preceding string opcodes and STACK_GLOBAL itself
    carries no arg — so this tracks the last two string pushes and resolves
    STACK_GLOBAL from them, which is how every modern (protocol 2+) pickle
    stream — including every default `pickle.dumps()` / `torch.save()`
    output — actually encodes a REDUCE callable.
    """
    hits: list[str] = []
    last_strings: list[str] = []
    try:
        for opcode, arg, _pos in pickletools.genops(data):
            if opcode.name in _STRING_PUSH_OPS:
                last_strings.append(str(arg))
                last_strings = last_strings[-2:]
                continue
            if opcode.name == "GLOBAL" and arg is not None:
                # pickletools' GLOBAL arg reader joins "module name" with a
                # single space (not the on-wire '\n' — genops already
                # decoded that), so split on the first space.
                module, _, name = str(arg).partition(" ")
            elif opcode.name in ("STACK_GLOBAL", "INST", "OBJ") and len(last_strings) == 2:
                module, name = last_strings[0], last_strings[1]
            else:
                continue
            ref = f"{module}.{name}"
            if module in _DANGEROUS_MODULES or name in _DANGEROUS_NAMES:
                if ref not in hits:
                    hits.append(ref)
    except Exception as e:  # malformed/truncated stream — report, don't crash
        hits.append(f"<scan error: {e}>")
    return hits


def _classify_file(path: Path) -> tuple[str, list[bytes]]:
    """Return (kind, [pickle byte blobs to scan]).

    kind: 'pytorch-zip' (new-format .pt/.pth, a zip with data.pkl inside),
    'raw-pickle' (old-format .pt/.pkl/.joblib, a bare pickle stream),
    'safetensors' (header-only JSON, no scan needed — safe by format), or
    'unknown'.
    """
    head = path.read_bytes()[:16]
    if head[:4] == b"PK\x03\x04":
        blobs = []
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.endswith((".pkl", "data.pkl")) or "/data.pkl" in name:
                    blobs.append(zf.read(name))
        return "pytorch-zip", blobs
    if path.suffix == ".safetensors":
        return "safetensors", []
    return "raw-pickle", [path.read_bytes()]


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def scan_model_artifacts(path: str) -> str:
        """Scan a model file for unsafe pickle deserialization (no execution).

        Closes LLM-SUPPLY-001/002 (Critical) — loading a pickled model can run
        arbitrary code via `__reduce__`; no model-file scanner existed in
        Praetor. Disassembles the pickle opcode stream with stdlib
        `pickletools` (never calls `pickle.load`, so the file is never
        executed) and flags GLOBAL/STACK_GLOBAL references into
        exec-capable modules (os, subprocess, sys, builtins, ...).

        Args:
            path: local file — .pt/.pth/.bin/.pkl/.joblib/.ckpt (PyTorch zip
                or raw pickle) or .safetensors (format has no exec surface;
                reported safe without a scan).

        A hit here is a real finding (Critical, RCE-on-load) — not a lead to
        escalate. Use `confirm_rce`-style evidence only if you then prove the
        file is actually served/loaded by the target; the scan itself is
        conclusive about the file's content.
        """
        p = Path(path)
        if not p.is_file():
            return f"Error: not a file: {path}"
        try:
            kind, blobs = _classify_file(p)
        except (OSError, zipfile.BadZipFile) as e:
            return f"Error reading {path}: {e}"

        if kind == "safetensors":
            try:
                n = int.from_bytes(p.read_bytes()[:8], "little")
                json.loads(p.read_bytes()[8:8 + n])
                return f"scan_model_artifacts {path} [safetensors]: SAFE — header is valid JSON, no exec surface."
            except Exception as e:
                return (f"scan_model_artifacts {path} [safetensors]: HEADER DID NOT PARSE "
                        f"as JSON ({e}) — this file may be mislabeled; re-check its real format.")

        if not blobs:
            return f"scan_model_artifacts {path} [{kind}]: no pickle stream found to scan."

        all_hits: list[str] = []
        for blob in blobs:
            all_hits.extend(_scan_pickle_bytes(blob))
        if not all_hits:
            return f"scan_model_artifacts {path} [{kind}]: no dangerous GLOBAL references found."
        lines = [f"scan_model_artifacts {path} [{kind}]: {len(all_hits)} dangerous reference(s) — UNSAFE DESERIALIZATION"]
        for h in all_hits[:30]:
            lines.append(f"  GLOBAL {h}")
        lines.append("\nImpact: loading this file (torch.load / pickle.load) can execute "
                      "arbitrary code via __reduce__. Severity: Critical (RCE on load).")
        return "\n".join(lines)
