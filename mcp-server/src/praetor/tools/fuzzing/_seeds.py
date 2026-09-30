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
import re
import struct
import zlib

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
    # chunk types + magic (incl. ancillary chunks that gate colour/transparency)
    "png": [b"IHDR", b"IDAT", b"IEND", b"pHYs", b"PLTE", b"tEXt", b"iTXt",
            b"\x89PNG\r\n\x1a\n", b"bKGD", b"gAMA", b"cHRM", b"sRGB", b"tRNS",
            b"zTXt", b"iCCP"],
    # segment markers: SOI/APP0/APP1/DQT/DRI/SOF0/SOF1/SOF2/DHT/SOS/EOI/COM
    "jpeg": [b"\xff\xd8", b"\xff\xe0", b"\xff\xdb", b"\xff\xc0", b"\xff\xc2",
             b"\xff\xc4", b"\xff\xda", b"\xff\xd9", b"\xff\xfe", b"\xff\xe1",
             b"\xff\xc1", b"\xff\xdd", b"\xff\xd0"],
    # header + block introducers: GCE / image-descriptor / app-ext / trailer
    "gif": [b"GIF89a", b"GIF87a", b"\x21\xf9", b"\x2c", b"\x21\xff", b"\x21\xfe",
            b"\x21\x01", b"\x3b"],
    # RIFF container + codec atoms
    "webp": [b"RIFF", b"WEBP", b"VP8L", b"VP8 ", b"VP8X", b"ANIM", b"ANMF",
             b"ALPH", b"ICCP", b"EXIF", b"XMP "],
    # object / stream / xref keywords + filters/params that drive parser CVEs
    "pdf": [b"obj", b"endobj", b"stream", b"endstream", b"xref", b"trailer",
            b"startxref", b"/JBIG2Decode", b"/FlateDecode", b"%%EOF",
            b"/Length", b"/Filter", b"/DecodeParms", b"/ObjStm", b"/Prev"],
    # local-file / central-directory / EOCD / data-descriptor / zip64 records
    "zip": [b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06", b"PK\x07\x08",
            b"PK\x06\x06", b"PK\x06\x07"],
    # elements + attributes (SVG is XML text; these are its structure boundaries)
    "svg": [b"<svg", b"</svg>", b"<rect", b"<g", b"<image", b"<script",
            b"xmlns", b"width", b"height", b"onload", b"href", b"<use",
            b"<foreignObject", b"<!DOCTYPE", b"<!ENTITY", b"viewBox"],
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


# ── Grammar / structure-aware mutators: valid-envelope, corrupt-payload ──────
# Unlike the dumb mutators above (blind edits at token boundaries), these PARSE
# the container and mutate DEEP fields while keeping the file valid enough to
# pass early validation — magic, framing, declared lengths, and (PNG) a
# RECOMPUTED chunk CRC. A wrong-CRC / broken-frame mutant is rejected before the
# decoder; these reach the decoder, where the real memory-corruption CVEs live.
# Each ``_gm_<fmt>(seed, rng)`` returns ONE mutant, or None when the seed does
# not parse (caller falls back). All randomness comes from the passed rng.

_U32_PATHO = (0, 1, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0x40000000, 0xFFFF)
_U16_PATHO = (0, 1, 0xFFFF, 0x7FFF, 0x8000, 0xFF)


def _find_all(hay: bytes, needle: bytes) -> list[int]:
    """All offsets of ``needle`` in ``hay`` (overlapping-safe, sorted)."""
    offs: list[int] = []
    i = hay.find(needle)
    while i >= 0:
        offs.append(i)
        i = hay.find(needle, i + 1)
    return offs


# ---- PNG ----
def _png_crc(chunk_type: bytes, data: bytes) -> int:
    """PNG chunk CRC-32 (ISO 3309) over type||data — the gate a mutant must pass
    to reach the decoder. ``zlib.crc32`` is exactly the algorithm PNG specifies."""
    return zlib.crc32(chunk_type + data) & 0xFFFFFFFF


def _png_walk(seed: bytes):
    """[(type, bytearray(data)), ...] for a parseable PNG, else None. Stored CRCs
    are dropped — every mutant is rebuilt with a freshly recomputed CRC."""
    if seed[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    chunks: list[tuple[bytes, bytearray]] = []
    i, n = 8, len(seed)
    while i + 8 <= n:
        length = int.from_bytes(seed[i:i + 4], "big")
        ctype = seed[i + 4:i + 8]
        if i + 12 + length > n:
            return None
        chunks.append((ctype, bytearray(seed[i + 8:i + 8 + length])))
        i += 12 + length
        if ctype == b"IEND":
            break
    return chunks or None


def _png_build(chunks) -> bytes:
    out = bytearray(b"\x89PNG\r\n\x1a\n")
    for ctype, data in chunks:
        out += len(data).to_bytes(4, "big")
        out += ctype
        out += data
        out += _png_crc(ctype, bytes(data)).to_bytes(4, "big")
    return bytes(out)


def _gm_png(seed, rng):
    chunks = _png_walk(seed)
    if not chunks:
        return None
    strat = rng.randrange(4)
    if strat == 0:
        # Pathological IHDR width/height/bit-depth/colour-type; CRC recomputed
        # so it passes the gate and the decoder actually processes the field.
        for k, (ctype, data) in enumerate(chunks):
            if ctype == b"IHDR" and len(data) >= 13:
                d = bytearray(data)
                field = rng.randrange(4)
                if field == 0:
                    struct.pack_into(">I", d, 0, rng.choice(_U32_PATHO))    # width
                elif field == 1:
                    struct.pack_into(">I", d, 4, rng.choice(_U32_PATHO))    # height
                elif field == 2:
                    d[8] = rng.choice((0, 3, 5, 7, 16, 32, 255))            # bit depth
                else:
                    d[9] = rng.choice((1, 5, 7, 8, 99, 255))                # colour type
                chunks[k] = (ctype, d)
                return _png_build(chunks)
        return None
    if strat == 1:
        # Oversize / corrupt a chunk's data body (CRC recomputed to match).
        k = rng.randrange(len(chunks))
        ctype, data = chunks[k]
        d = bytearray(data)
        if rng.random() < 0.5:
            d += bytes(rng.choice((16, 256, 4096)))          # oversize
        elif d:
            d[rng.randrange(len(d))] = rng.randrange(256)    # corrupt body
        else:
            d += bytes([rng.randrange(256)])
        chunks[k] = (ctype, d)
        return _png_build(chunks)
    movable = [k for k, (t, _) in enumerate(chunks) if t not in (b"IHDR", b"IEND")]
    if not movable:
        return None
    if strat == 2:
        # Duplicate a non-critical-position chunk.
        k = rng.choice(movable)
        chunks.insert(k, (chunks[k][0], bytearray(chunks[k][1])))
        return _png_build(chunks)
    # strat 3: reorder — hoist a chunk ahead of IHDR (illegal order a lax
    # decoder may still walk into). Magic stays first, so it passes detection.
    k = rng.choice(movable)
    chunks.insert(0, chunks.pop(k))
    return _png_build(chunks)


# ---- JPEG ----
def _jpeg_walk(seed):
    """[[marker, data|None, declared_len?], ...] or None. ``marker`` is the int
    marker byte, or 'ENTROPY' for post-SOS scan data. ``data`` excludes the FF
    marker and the 2-byte length field; an optional 3rd element lies about the
    declared length on rebuild (keeps framing, corrupts the size field)."""
    if seed[:2] != b"\xff\xd8":
        return None
    segs: list = [[0xD8, None]]   # SOI (consumed by the magic check above)
    i, n = 2, len(seed)
    while i < n:
        if seed[i] != 0xFF:
            return None
        while i < n and seed[i] == 0xFF:
            i += 1
        if i >= n:
            break
        marker = seed[i]
        i += 1
        if marker == 0xD8 or marker == 0x01 or 0xD0 <= marker <= 0xD7:
            segs.append([marker, None])
            continue
        if marker == 0xD9:
            segs.append([marker, None])
            break
        if i + 2 > n:
            return None
        length = int.from_bytes(seed[i:i + 2], "big")
        if length < 2 or i + length > n:
            return None
        segs.append([marker, bytearray(seed[i + 2:i + length])])
        i += length
        if marker == 0xDA:  # SOS -> entropy-coded data until EOI
            start = i
            while i < n - 1 and not (seed[i] == 0xFF and seed[i + 1] == 0xD9):
                i += 1
            segs.append(["ENTROPY", bytearray(seed[start:i])])
    return segs


def _jpeg_build(segs) -> bytes:
    out = bytearray()
    for entry in segs:
        marker, data = entry[0], entry[1]
        override = entry[2] if len(entry) > 2 else None
        if marker == "ENTROPY":
            out += data
            continue
        out += bytes((0xFF, marker))
        if data is not None:
            declared = override if override is not None else len(data) + 2
            out += (declared & 0xFFFF).to_bytes(2, "big")
            out += data
    return bytes(out)


def _gm_jpeg(seed, rng):
    segs = _jpeg_walk(seed)
    if not segs:
        return None
    targets = (0xC0, 0xC1, 0xC2, 0xC4, 0xDB, 0xDA)
    idxs = [k for k, e in enumerate(segs) if isinstance(e[0], int) and e[0] in targets]
    if not idxs:
        return None
    k = rng.choice(idxs)
    marker = segs[k][0]
    data = bytearray(segs[k][1]) if segs[k][1] is not None else bytearray()
    strat = rng.randrange(3)
    if strat == 1 and marker in (0xC0, 0xC1, 0xC2) and len(data) >= 6:
        # SOF: pathological precision / dimensions / component count.
        field = rng.randrange(4)
        if field == 0:
            data[0] = rng.choice((0, 1, 16, 32, 255))               # precision
        elif field == 1:
            struct.pack_into(">H", data, 1, rng.choice(_U16_PATHO))  # height
        elif field == 2:
            struct.pack_into(">H", data, 3, rng.choice(_U16_PATHO))  # width
        else:
            data[5] = rng.choice((0, 1, 4, 255))                     # components
        segs[k] = [marker, data]
        return _jpeg_build(segs)
    if strat == 2 and marker == 0xC4 and len(data) > 1:
        # DHT: corrupt a Huffman code-length count (bytes 1..16 of the segment).
        end = min(17, len(data))
        data[rng.randrange(1, end)] = rng.choice((0, 16, 200, 255))
        segs[k] = [marker, data]
        return _jpeg_build(segs)
    # strat 0 (and fallback): corrupt the segment's declared length; framing
    # (FFD8 ... FFD9) is preserved, only the size field lies.
    segs[k] = [marker, data, rng.choice(_U16_PATHO)]
    return _jpeg_build(segs)


# ---- WebP (CVE-2023-4863 VP8L surface) ----
def _gm_webp(seed, rng):
    if seed[:4] != b"RIFF" or seed[8:12] != b"WEBP":
        return None
    b = bytearray(seed)
    n = len(b)
    vp8l = -1
    i = 12
    while i + 8 <= n:
        fourcc = bytes(b[i:i + 4])
        size = int.from_bytes(b[i + 4:i + 8], "little")
        if fourcc == b"VP8L":
            vp8l = i
            break
        i += 8 + size + (size & 1)
    strat = rng.randrange(3)
    if strat == 0 or vp8l < 0:
        # RIFF envelope size field (RIFF/WEBP magic preserved).
        struct.pack_into("<I", b, 4, rng.choice(_U32_PATHO))
        return bytes(b)
    if strat == 1:
        # VP8L chunk size field.
        struct.pack_into("<I", b, vp8l + 4, rng.choice(_U32_PATHO))
        return bytes(b)
    # strat 2: VP8L bitstream header. After the 0x2f signature byte the next
    # u32 LE packs width-1[0:14], height-1[14:28], alpha[28], version[29:32] —
    # the exact fields behind CVE-2023-4863.
    dstart = vp8l + 8
    if dstart + 5 > n or b[dstart] != 0x2F:
        struct.pack_into("<I", b, vp8l + 4, rng.choice(_U32_PATHO))
        return bytes(b)
    val = int.from_bytes(b[dstart + 1:dstart + 5], "little")
    field = rng.randrange(3)
    if field == 0:
        val = (val & ~0x3FFF) | rng.choice((0, 0x3FFF, 0x2000))              # width-1
    elif field == 1:
        val = (val & ~(0x3FFF << 14)) | (rng.choice((0, 0x3FFF, 0x2000)) << 14)  # height-1
    else:
        val = (val & ~(0x7 << 29)) | (rng.choice((1, 3, 7)) << 29)          # version
    struct.pack_into("<I", b, dstart + 1, val & 0xFFFFFFFF)
    return bytes(b)


# ---- GIF ----
def _gm_gif(seed, rng):
    if seed[:3] != b"GIF" or len(seed) < 13:
        return None
    b = bytearray(seed)
    n = len(b)
    strat = rng.randrange(3)
    if strat == 0:
        # Logical Screen Descriptor width/height (u16 LE at 6 / 8).
        struct.pack_into("<H", b, rng.choice((6, 8)), rng.choice(_U16_PATHO))
        return bytes(b)
    idx = b.find(b"\x2c", 13)  # image descriptor introducer
    if strat == 1 and idx >= 0 and idx + 9 <= n:
        # Image-descriptor width/height (u16 LE at +5 / +7).
        struct.pack_into("<H", b, idx + rng.choice((5, 7)), rng.choice(_U16_PATHO))
        return bytes(b)
    if idx >= 0 and idx + 11 <= n:
        # LZW minimum-code-size byte (follows the 10-byte image descriptor).
        b[idx + 10] = rng.choice((0, 1, 9, 12, 255))
        return bytes(b)
    struct.pack_into("<H", b, rng.choice((6, 8)), rng.choice(_U16_PATHO))
    return bytes(b)


# ---- PDF (object-graph aware, text container) ----
def _gm_pdf(seed, rng):
    if seed[:4] != b"%PDF" or b"%%EOF" not in seed:
        return None
    b = bytes(seed)
    strat = rng.randrange(4)
    if strat == 0:
        ms = list(re.finditer(rb"/Length\s+(\d+)", b))
        if ms:
            m = rng.choice(ms)
            new = str(rng.choice((0, 1, 999999999, 2147483647))).encode()
            return b[:m.start(1)] + new + b[m.end(1):]
        strat = 3
    if strat == 1:
        ms = list(re.finditer(
            rb"/(FlateDecode|JBIG2Decode|DCTDecode|ASCIIHexDecode|LZWDecode)\b", b))
        if ms:
            m = rng.choice(ms)
            new = rng.choice((b"/JBIG2Decode", b"/FlateDecode",
                              b"/CCITTFaxDecode", b"/NoSuchFilter"))
            return b[:m.start()] + new + b[m.end():]
        m = re.search(rb"<<", b)
        if m:
            return b[:m.end()] + b"/Filter/FlateDecode" + b[m.end():]
        strat = 3
    if strat == 2:
        ms = list(re.finditer(rb"\n(\d{10}) (\d{5}) [nf]", b))
        if ms:
            m = rng.choice(ms)
            new = ("%010d" % rng.choice((0, 1, 4294967295))).encode()[:10]
            return b[:m.start(1)] + new + b[m.end(1):]
        strat = 3
    ms = list(re.finditer(rb"(\d+) (\d+) obj", b))
    if ms:
        m = rng.choice(ms)
        new = str(rng.choice((0, 999999, 2147483647))).encode()
        return b[:m.start(1)] + new + b[m.end(1):]
    return None


# ---- ZIP ----
def _gm_zip(seed, rng):
    if seed[:4] != b"PK\x03\x04":
        return None
    b = bytearray(seed)
    n = len(b)
    lfh = _find_all(bytes(b), b"PK\x03\x04")
    cdh = _find_all(bytes(b), b"PK\x01\x02")
    eocd = bytes(b).rfind(b"PK\x05\x06")
    strat = rng.randrange(3)
    if strat == 0 and lfh:
        off = rng.choice(lfh)
        f = rng.choice((18, 22, 26, 28))  # comp/uncomp size, name/extra len
        if f in (18, 22) and off + f + 4 <= n:
            struct.pack_into("<I", b, off + f, rng.choice(_U32_PATHO))
        elif off + f + 2 <= n:
            struct.pack_into("<H", b, off + f, rng.choice(_U16_PATHO))
        return bytes(b)
    if strat == 1 and cdh:
        off = rng.choice(cdh)
        f = rng.choice((20, 24, 42))  # comp/uncomp size, local-header offset
        if off + f + 4 <= n:
            struct.pack_into("<I", b, off + f, rng.choice(_U32_PATHO))
        return bytes(b)
    if eocd >= 0 and eocd + 20 <= n:
        f = rng.choice((10, 12, 16))  # entry count, CD size, CD offset
        if f == 10:
            struct.pack_into("<H", b, eocd + f, rng.choice(_U16_PATHO))
        else:
            struct.pack_into("<I", b, eocd + f, rng.choice(_U32_PATHO))
        return bytes(b)
    if lfh:
        struct.pack_into("<I", b, lfh[0] + 18, rng.choice(_U32_PATHO))
        return bytes(b)
    return None


# ---- SVG (XML text; keep well-formed) ----
_SVG_ENTITIES = (
    b'<!DOCTYPE svg [\n'
    b'<!ENTITY lol "lol">\n'
    b'<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
    b'<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">\n'
    b'<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">\n'
    b']>\n'
)


def _gm_svg(seed, rng):
    b = bytes(seed)
    if b"<svg" not in b:
        return None
    strat = rng.randrange(3)
    if strat == 0:
        huge = str(rng.choice((0, 999999999, 2147483647, 10 ** 30))).encode()
        out = re.sub(rb'width="[^"]*"', b'width="' + huge + b'"', b, count=1)
        out = re.sub(rb'height="[^"]*"', b'height="' + huge + b'"', out, count=1)
        if out != b:
            return out
        strat = 2
    if strat == 1:
        # Billion-laughs-shaped nested entity defs (well-formed XML; the
        # expansion is the payload) + one reference inside the body.
        pos = b.find(b"<svg")
        doc = b[:pos] + _SVG_ENTITIES + b[pos:]
        close = doc.rfind(b"</svg>")
        if close >= 0:
            doc = doc[:close] + b"<text>&lol4;</text>" + doc[close:]
        return doc
    # strat 2: deep balanced element nesting (well-formed).
    depth = rng.choice((256, 1024, 4096))
    pos = b.find(b">")  # end of the <svg ...> open tag
    if pos < 0:
        return None
    return b[:pos + 1] + b"<g>" * depth + b"</g>" * depth + b[pos + 1:]


_GRAMMAR_FMT = {
    "png": _gm_png,
    "jpeg": _gm_jpeg,
    "webp": _gm_webp,
    "gif": _gm_gif,
    "pdf": _gm_pdf,
    "zip": _gm_zip,
    "svg": _gm_svg,
}


def grammar_mutate(seed: bytes, fmt: str, n: int, rng: random.Random) -> list[bytes]:
    """Return up to ``n`` DISTINCT 'valid-envelope, corrupt-payload' mutants.

    Unlike ``mutate`` (blind structure-aware byte edits), each mutant keeps the
    container valid enough to pass early validation — magic, framing, declared
    lengths, and (PNG) a RECOMPUTED chunk CRC — so it reaches the DEEP decoder
    where memory-corruption CVEs live. Deterministic in the passed ``rng``:
    identical (seed, fmt, n, rng-state) -> identical list.

    Unknown/unsupported fmt -> falls back to ``mutate``. When the grammar space
    is smaller than ``n`` (tiny seeds), tops up from ``mutate`` for breadth.
    """
    if n <= 0 or not seed:
        return []
    key = (fmt or "").lower().lstrip(".")
    if key in ("jpg", "jpe"):
        key = "jpeg"
    fn = _GRAMMAR_FMT.get(key)
    if fn is None:
        return mutate(seed, fmt, n, rng)
    out: list[bytes] = []
    seen: set[bytes] = {seed}
    max_attempts = max(n * 40, 200)
    for _ in range(max_attempts):
        if len(out) >= n:
            break
        try:
            cand = fn(seed, rng)
        except Exception:
            cand = None
        if not cand or cand in seen:
            continue
        seen.add(cand)
        out.append(cand)
    if len(out) < n:  # grammar space saturated -> top up with dumb mutants
        for m in mutate(seed, key, n - len(out), rng):
            if m in seen:
                continue
            seen.add(m)
            out.append(m)
            if len(out) >= n:
                break
    return out[:n]
