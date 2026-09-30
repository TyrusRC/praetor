"""Persistent cross-run AFL corpus store (Phase 2).

Pure filesystem, no Burp, no external deps. A campaign's queue/crashes are merged
back into a per-(domain, fmt) store so a later run starts from EVERYTHING earlier
runs discovered instead of from a single built-in seed — input-to-state progress
(magic bytes / length fields solved by CmpLog) compounds across runs.

Layout: .burp-intel/<domain>/artifacts/fuzz/corpus/<fmt>/
Files are content-addressed (<sha1>.<ext>) so identical inputs dedup to one file.

NOTE (known ceiling): dedup rehashes the whole store on every seed/merge — O(store)
per call. Fine for the bounded stores here (`_MERGE_CAP` files, each <= 1 MiB); a
very large operator corpus would want a persisted hash index instead.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from praetor.tools.workspace import workspace_paths
from . import _seeds

_MAX_CORPUS_FILE = 1 << 20   # 1 MiB: skip pathological/huge queue entries
_MERGE_CAP = 5000            # bound files copied back into the store per merge


def _sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def _ext_for(fmt: str) -> str:
    f = (fmt or "bin").lower().lstrip(".") or "bin"
    return {"jpeg": "jpg"}.get(f, f)


def corpus_dir(domain: str, fmt: str) -> Path:
    """Persistent corpus dir for (domain, fmt); created if missing."""
    f = (fmt or "bin").lower().lstrip(".") or "bin"
    d = workspace_paths(domain)["artifacts"] / "fuzz" / "corpus" / f
    d.mkdir(parents=True, exist_ok=True)
    return d


def _load_hashes(cdir: Path) -> set[str]:
    """Content hashes already in the store (so we never rewrite a dup)."""
    seen: set[str] = set()
    for p in cdir.iterdir():
        if p.is_file():
            try:
                seen.add(_sha1(p.read_bytes()))
            except OSError:
                pass
    return seen


def _add(cdir: Path, ext: str, data: bytes, seen: set[str]) -> bool:
    """Content-addressed write into the store. False if empty/oversize/dup."""
    if not data or len(data) > _MAX_CORPUS_FILE:
        return False
    h = _sha1(data)
    if h in seen:
        return False
    seen.add(h)
    try:
        (cdir / f"{h}.{ext}").write_bytes(data)
    except OSError:
        return False
    return True


def _iter_files(path: Path):
    """Yield readable regular files from a file or a (shallow) dir path."""
    if path.is_file():
        yield path
    elif path.is_dir():
        for f in sorted(path.iterdir()):
            if f.is_file() and f.name != "README.txt":
                yield f


def seed_corpus(domain: str, fmt: str, extra_seed_paths=None) -> str:
    """Materialize persistent store ∪ generated seed_for(fmt) ∪ caller seeds.

    Adds the built-in valid seed for `fmt` and every caller-supplied seed (file or
    dir) that is not already present, deduped by content sha1. The persistent store
    IS the seed dir returned, so nothing already discovered is lost. Guarantees a
    non-empty dir (falls back to the PNG seed) so afl-fuzz always has an input.
    Returns the corpus dir path.
    """
    cdir = corpus_dir(domain, fmt)
    ext = _ext_for(fmt)
    seen = _load_hashes(cdir)

    try:
        _add(cdir, ext, _seeds.seed_for(fmt), seen)
    except ValueError:
        pass

    for sp in (extra_seed_paths or []):
        for f in _iter_files(Path(str(sp)).expanduser()):
            try:
                _add(cdir, ext, f.read_bytes(), seen)
            except OSError:
                pass

    # AFL needs at least one seed; fall back to a known-valid built-in.
    if not any(cdir.iterdir()):
        try:
            _add(cdir, ext, _seeds.seed_for("png"), seen)
        except ValueError:
            pass
    return str(cdir)


def merge_back(domain: str, fmt: str, afl_out_dir) -> int:
    """Fold an afl-fuzz run's queue + crashes + hangs into the persistent store.

    Copies each new input (deduped by content hash) so the next run seeds from it.
    Bounded by `_MERGE_CAP`. Returns the count of NEW files added.
    """
    cdir = corpus_dir(domain, fmt)
    ext = _ext_for(fmt)
    seen = _load_hashes(cdir)

    out = Path(str(afl_out_dir)).expanduser()
    added = 0
    for base in (out / "default", out):
        for sub in ("queue", "crashes", "hangs"):
            for f in _iter_files(base / sub):
                if added >= _MERGE_CAP:
                    return added
                try:
                    data = f.read_bytes()
                except OSError:
                    continue
                if _add(cdir, ext, data, seen):
                    added += 1
    return added
