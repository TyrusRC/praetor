"""Grammar / structure-aware mutators: valid-envelope, corrupt-payload.

Unlike the dumb mutators in _seeds (blind edits at token boundaries), these
PARSE the container and mutate DEEP fields while keeping the file valid enough
to pass early validation — magic, framing, declared lengths, and (PNG) a
RECOMPUTED chunk CRC. A wrong-CRC / broken-frame mutant is rejected before the
decoder; these reach the decoder, where the real memory-corruption CVEs live.

Each ``_gm_<fmt>(seed, rng)`` returns ONE mutant, or None when the seed does
not parse (caller falls back). All randomness comes from the passed rng.
"""

from __future__ import annotations

import random
import re
import struct
import zlib

from ._seeds import _SEEDS, _DICTS, mutate

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
        k = rng.choice(movable)
        chunks.insert(k, (chunks[k][0], bytearray(chunks[k][1])))
        return _png_build(chunks)
    k = rng.choice(movable)
    chunks.insert(0, chunks.pop(k))
    return _png_build(chunks)


# ---- JPEG ----
def _jpeg_walk(seed):
    """[[marker, data|None, declared_len?], ...] or None."""
    if seed[:2] != b"\xff\xd8":
        return None
    segs: list = [[0xD8, None]]
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
        if marker == 0xDA:
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
        field = rng.randrange(4)
        if field == 0:
            data[0] = rng.choice((0, 1, 16, 32, 255))
        elif field == 1:
            struct.pack_into(">H", data, 1, rng.choice(_U16_PATHO))
        elif field == 2:
            struct.pack_into(">H", data, 3, rng.choice(_U16_PATHO))
        else:
            data[5] = rng.choice((0, 1, 4, 255))
        segs[k] = [marker, data]
        return _jpeg_build(segs)
    if strat == 2 and marker == 0xC4 and len(data) > 1:
        end = min(17, len(data))
        data[rng.randrange(1, end)] = rng.choice((0, 16, 200, 255))
        segs[k] = [marker, data]
        return _jpeg_build(segs)
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
        struct.pack_into("<I", b, 4, rng.choice(_U32_PATHO))
        return bytes(b)
    if strat == 1:
        struct.pack_into("<I", b, vp8l + 4, rng.choice(_U32_PATHO))
        return bytes(b)
    dstart = vp8l + 8
    if dstart + 5 > n or b[dstart] != 0x2F:
        struct.pack_into("<I", b, vp8l + 4, rng.choice(_U32_PATHO))
        return bytes(b)
    val = int.from_bytes(b[dstart + 1:dstart + 5], "little")
    field = rng.randrange(3)
    if field == 0:
        val = (val & ~0x3FFF) | rng.choice((0, 0x3FFF, 0x2000))
    elif field == 1:
        val = (val & ~(0x3FFF << 14)) | (rng.choice((0, 0x3FFF, 0x2000)) << 14)
    else:
        val = (val & ~(0x7 << 29)) | (rng.choice((1, 3, 7)) << 29)
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
        struct.pack_into("<H", b, rng.choice((6, 8)), rng.choice(_U16_PATHO))
        return bytes(b)
    idx = b.find(b"\x2c", 13)
    if strat == 1 and idx >= 0 and idx + 9 <= n:
        struct.pack_into("<H", b, idx + rng.choice((5, 7)), rng.choice(_U16_PATHO))
        return bytes(b)
    if idx >= 0 and idx + 11 <= n:
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
        f = rng.choice((18, 22, 26, 28))
        if f in (18, 22) and off + f + 4 <= n:
            struct.pack_into("<I", b, off + f, rng.choice(_U32_PATHO))
        elif off + f + 2 <= n:
            struct.pack_into("<H", b, off + f, rng.choice(_U16_PATHO))
        return bytes(b)
    if strat == 1 and cdh:
        off = rng.choice(cdh)
        f = rng.choice((20, 24, 42))
        if off + f + 4 <= n:
            struct.pack_into("<I", b, off + f, rng.choice(_U32_PATHO))
        return bytes(b)
    if eocd >= 0 and eocd + 20 <= n:
        f = rng.choice((10, 12, 16))
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
        pos = b.find(b"<svg")
        doc = b[:pos] + _SVG_ENTITIES + b[pos:]
        close = doc.rfind(b"</svg>")
        if close >= 0:
            doc = doc[:close] + b"<text>&lol4;</text>" + doc[close:]
        return doc
    depth = rng.choice((256, 1024, 4096))
    pos = b.find(b">")
    if pos < 0:
        return None
    return b[:pos + 1] + b"<g>" * depth + b"</g>" * depth + b[pos + 1:]


# ── Dispatch table ──────────────────────────────────────────────────────────
GRAMMAR_FMT = {
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
    fn = GRAMMAR_FMT.get(key)
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
    if len(out) < n:
        for m in mutate(seed, key, n - len(out), rng):
            if m in seen:
                continue
            seen.add(m)
            out.append(m)
            if len(out) >= n:
                break
    return out[:n]
