"""Structure-aware file-format seeds, dictionaries, and byte mutators.

Pure, deterministic building blocks for `fuzz_upload`. No I/O, no Burp, no
external deps. Everything randomised takes an explicit seeded
``random.Random`` so a given (seed, fmt, n, rng-seed) reproduces the SAME
corpus — the property the design spec and Rule 10a replay both require.

Structure-aware mutation (format-aware seeds + per-format dictionaries + edits
at real chunk/atom/marker boundaries) reaches parser code paths that blind
bitflipping never does. That is the difference between reproducing a real
parser CVE (e.g. CVE-2023-4863, a crafted WebP VP8L lossless chunk) and
emitting noise.

`mutate_payload` (tools/mutate.py) is payload-STRING only; these are raw-byte
mutators, so they are a sibling here rather than an import.
"""

from __future__ import annotations

import random
import struct

# ── Minimal VALID seed bytes, one smallest real file per format ──────────────
# Generated with Pillow (png/jpeg/gif/webp) and hand-built (pdf/zip/svg), each
# validated to decode / open and to carry its format's structural tokens.
# WebP is intentionally a VP8L (lossless) chunk — the CVE-2023-4863 surface.

_PNG = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x03\x01\x01\x00\xc9\xfe\x92\xef\x00\x00\x00\x00IEND\xaeB`\x82'

_JPEG = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00C\x00\x05\x03\x04\x04\x04\x03\x05\x04\x04\x04\x05\x05\x05\x06\x07\x0c\x08\x07\x07\x07\x07\x0f\x0b\x0b\t\x0c\x11\x0f\x12\x12\x11\x0f\x11\x11\x13\x16\x1c\x17\x13\x14\x1a\x15\x11\x11\x18!\x18\x1a\x1d\x1d\x1f\x1f\x1f\x13\x17"$"\x1e$\x1c\x1e\x1f\x1e\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xc4\x00\xb5\x10\x00\x02\x01\x03\x03\x02\x04\x03\x05\x05\x04\x04\x00\x00\x01}\x01\x02\x03\x00\x04\x11\x05\x12!1A\x06\x13Qa\x07"q\x142\x81\x91\xa1\x08#B\xb1\xc1\x15R\xd1\xf0$3br\x82\t\n\x16\x17\x18\x19\x1a%&\'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz\x83\x84\x85\x86\x87\x88\x89\x8a\x92\x93\x94\x95\x96\x97\x98\x99\x9a\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xff\xda\x00\x08\x01\x01\x00\x00?\x00+\xff\xd9'

_GIF = b'GIF87a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x08\x04\x00\x01\x04\x04\x00;'

_WEBP = b'RIFF\x1c\x00\x00\x00WEBPVP8L\x0f\x00\x00\x00/\x00\x00\x00\x00\x07\x10\xfd\x8f\xfe\x07"\xa2\xff\x01\x00'

_PDF = b'%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 3 3]>>endobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000052 00000 n \n0000000101 00000 n \ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n160\n%%EOF\n'

_ZIP = b'PK\x03\x04\x14\x00\x00\x00\x00\x00&\xa4>]\x8b\x9e\xd9\xd3\x01\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00a.txtAPK\x01\x02\x14\x03\x14\x00\x00\x00\x00\x00&\xa4>]\x8b\x9e\xd9\xd3\x01\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x01\x00\x00\x00\x00a.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x003\x00\x00\x00$\x00\x00\x00\x00\x00'

_SVG = b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><rect width="1" height="1"/></svg>'


_SEEDS: dict[str, bytes] = {
    "png": _PNG,
    "jpeg": _JPEG,
    "gif": _GIF,
    "webp": _WEBP,
    "pdf": _PDF,
    "zip": _ZIP,
    "svg": _SVG,
}

# ── Per-format structural dictionaries (real chunk/marker/atom/record tokens) ─
_DICTS: dict[str, list[bytes]] = {
    # chunk types + magic
    "png": [b"IHDR", b"IDAT", b"IEND", b"pHYs", b"PLTE", b"tEXt", b"iTXt",
            b"\x89PNG\r\n\x1a\n"],
    # segment markers: SOI/APP0/DQT/SOF0/SOF2/DHT/SOS/EOI/COM
    "jpeg": [b"\xff\xd8", b"\xff\xe0", b"\xff\xdb", b"\xff\xc0", b"\xff\xc2",
             b"\xff\xc4", b"\xff\xda", b"\xff\xd9", b"\xff\xfe"],
    # header + block introducers: GCE / image-descriptor / app-ext / trailer
    "gif": [b"GIF89a", b"GIF87a", b"\x21\xf9", b"\x2c", b"\x21\xff", b"\x21\xfe",
            b"\x3b"],
    # RIFF container + codec atoms
    "webp": [b"RIFF", b"WEBP", b"VP8L", b"VP8 ", b"VP8X", b"ANIM", b"ANMF",
             b"ALPH", b"ICCP", b"EXIF"],
    # object / stream / xref keywords + a filter that has driven parser CVEs
    "pdf": [b"obj", b"endobj", b"stream", b"endstream", b"xref", b"trailer",
            b"startxref", b"/JBIG2Decode", b"/FlateDecode", b"%%EOF"],
    # local-file / central-directory / EOCD / data-descriptor records
    "zip": [b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06", b"PK\x07\x08",
            b"PK\x06\x06", b"PK\x06\x07"],
    # elements + attributes (SVG is XML text; these are its structure boundaries)
    "svg": [b"<svg", b"</svg>", b"<rect", b"<g", b"<image", b"<script",
            b"xmlns", b"width", b"height", b"onload", b"href"],
}

# NOTE: naive whole-file scan for token offsets is O(n*tokens) per mutant; fine
# for the minimal seeds here (<400 B). A large operator-supplied seed would want
# a single-pass scan — upgrade path if seed sizes grow.

_INT_BOUNDARIES = (0x00000000, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0x00000001)


def seed_for(fmt: str) -> bytes:
    """Minimal valid seed bytes for a format. Raises on unknown format."""
    key = (fmt or "").lower().lstrip(".")
    if key in ("jpg", "jpe"):
        key = "jpeg"
    if key not in _SEEDS:
        raise ValueError(
            f"no built-in seed for {fmt!r}; known: {', '.join(sorted(_SEEDS))}")
    return _SEEDS[key]


def known_formats() -> list[str]:
    return sorted(_SEEDS)


def detect_fmt(filename_or_bytes) -> str:
    """Best-effort format id from a filename/extension or magic bytes.

    Returns "" when nothing matches (caller falls back to an explicit fmt).
    """
    if isinstance(filename_or_bytes, (bytes, bytearray)):
        b = bytes(filename_or_bytes)
        if b.startswith(b"\x89PNG\r\n\x1a\n"):
            return "png"
        if b.startswith(b"\xff\xd8\xff"):
            return "jpeg"
        if b.startswith((b"GIF87a", b"GIF89a")):
            return "gif"
        if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
            return "webp"
        if b.startswith(b"%PDF"):
            return "pdf"
        if b[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
            return "zip"
        head = b[:512].lstrip()
        if head.startswith(b"<?xml") or b"<svg" in head:
            return "svg"
        return ""
    name = str(filename_or_bytes or "").lower()
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    if ext in ("jpg", "jpeg", "jpe"):
        return "jpeg"
    if ext in _SEEDS:
        return ext
    return ""


# ── Byte-level, structure-aware mutators ─────────────────────────────────────
# Every mutator: (seed: bytes, rng: random.Random, fmt: str) -> bytes.
# fmt is accepted by all so the dispatcher can call them uniformly; format-blind
# ones ignore it.

def _token_offsets(seed: bytes, fmt: str) -> list[int]:
    """Offsets of every dictionary-token occurrence in the seed (sorted)."""
    offs: list[int] = []
    for tok in _DICTS.get(fmt, ()):
        start = 0
        while True:
            i = seed.find(tok, start)
            if i < 0:
                break
            offs.append(i)
            start = i + 1
    return sorted(set(offs))


def bitflip(seed: bytes, rng: random.Random, fmt: str = "") -> bytes:
    if not seed:
        return seed
    pos = rng.randrange(len(seed))
    bit = 1 << rng.randrange(8)
    ba = bytearray(seed)
    ba[pos] ^= bit
    return bytes(ba)


def byteflip(seed: bytes, rng: random.Random, fmt: str = "") -> bytes:
    if not seed:
        return seed
    pos = rng.randrange(len(seed))
    ba = bytearray(seed)
    new = rng.randrange(256)
    if new == ba[pos]:
        new ^= 0xFF
    ba[pos] = new
    return bytes(ba)


def _pick_len_window(seed: bytes, rng: random.Random, fmt: str) -> int:
    """Offset of a 4-byte window to treat as a size field, near a boundary.

    Prefers the 4 bytes immediately BEFORE a structural token (PNG-style
    length-before-type); falls back to just after, then to a random aligned
    window. Returns -1 when the seed is too short.
    """
    if len(seed) < 4:
        return -1
    offs = _token_offsets(seed, fmt)
    rng.shuffle(offs)
    for o in offs:
        if o >= 4:
            return o - 4
        if o + 4 <= len(seed) - 4:
            return o + 4
    return rng.randrange(len(seed) - 3)


def length_field_corrupt(seed: bytes, rng: random.Random, fmt: str = "") -> bytes:
    """Grow or shrink a 4-byte size field near a chunk/atom boundary."""
    off = _pick_len_window(seed, rng, fmt)
    if off < 0:
        return byteflip(seed, rng, fmt)
    ba = bytearray(seed)
    cur = struct.unpack_from(">I", ba, off)[0]
    if rng.random() < 0.5:
        new = min(0xFFFFFFFF, (cur + 1) * rng.choice((16, 256, 65536)) + 1)  # grow
    else:
        new = rng.choice((0, 1, max(0, cur // 2)))  # shrink
    struct.pack_into(">I", ba, off, new & 0xFFFFFFFF)
    return bytes(ba)


def integer_boundary(seed: bytes, rng: random.Random, fmt: str = "") -> bytes:
    """Write an integer-boundary value (0 / 1 / INT_MAX / -1 / 0x8000...) into a
    size field near a structural boundary."""
    off = _pick_len_window(seed, rng, fmt)
    if off < 0:
        return byteflip(seed, rng, fmt)
    ba = bytearray(seed)
    struct.pack_into(">I", ba, off, rng.choice(_INT_BOUNDARIES))
    return bytes(ba)


def chunk_duplicate(seed: bytes, rng: random.Random, fmt: str = "") -> bytes:
    """Duplicate the region between two adjacent structural boundaries."""
    offs = _token_offsets(seed, fmt)
    if len(offs) < 2:
        # No boundaries: duplicate a random slice.
        if len(seed) < 2:
            return seed + seed
        a = rng.randrange(len(seed))
        b = rng.randrange(a, len(seed))
        return seed[:b] + seed[a:b] + seed[b:]
    i = rng.randrange(len(offs) - 1)
    a, b = offs[i], offs[i + 1]
    return seed[:b] + seed[a:b] + seed[b:]


def chunk_truncate(seed: bytes, rng: random.Random, fmt: str = "") -> bytes:
    """Cut the file short at a boundary (or random offset) — premature EOF."""
    if len(seed) < 2:
        return seed
    offs = [o for o in _token_offsets(seed, fmt) if 0 < o < len(seed)]
    cut = rng.choice(offs) if offs and rng.random() < 0.7 else rng.randrange(1, len(seed))
    return seed[:cut]


def token_inject(seed: bytes, rng: random.Random, fmt: str = "") -> bytes:
    """Splice an extra dictionary token in at a structural boundary."""
    toks = _DICTS.get(fmt)
    if not toks:
        return byteflip(seed, rng, fmt)
    tok = rng.choice(toks)
    offs = _token_offsets(seed, fmt)
    pos = rng.choice(offs) if offs and rng.random() < 0.7 else (
        rng.randrange(len(seed) + 1) if seed else 0)
    return seed[:pos] + tok + seed[pos:]


_MUTATORS = (
    bitflip,
    byteflip,
    length_field_corrupt,
    integer_boundary,
    chunk_duplicate,
    chunk_truncate,
    token_inject,
)


def mutate(seed: bytes, fmt: str, n: int, rng: random.Random) -> list[bytes]:
    """Return up to ``n`` DISTINCT mutant byte-strings of ``seed``.

    Deterministic: identical (seed, fmt, n, rng-state) -> identical list. Cycles
    the structure-aware mutators (chosen via the seeded rng), deduping on the
    exact bytes and never returning the unchanged seed.
    """
    if n <= 0 or not seed:
        return []
    fmt = (fmt or "").lower()
    out: list[bytes] = []
    seen: set[bytes] = {seed}
    # Bounded attempts: small seeds saturate their mutation space, so cap work.
    max_attempts = max(n * 40, 200)
    for _ in range(max_attempts):
        if len(out) >= n:
            break
        mut = rng.choice(_MUTATORS)
        try:
            cand = mut(seed, rng, fmt)
        except Exception:
            continue
        if not cand or cand in seen:
            continue
        seen.add(cand)
        out.append(cand)
    return out
