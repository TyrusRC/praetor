"""OCR-driven detection of sensitive spans in a screenshot, for auto-redaction.

Runs the free `tesseract` CLI (no Python image/OCR dependency; the project already
shells out to CLI tools) to get word boxes, then flags the ones that are secrets —
by value shape (long hex / base64 / JWT / email) or because an earlier word on the
same line is a sensitive KEY (Cookie, Authorization, PHPSESSID, api_key, ...). The
boxes are merged per line and handed to /api/ui/redact.

`_sensitive_boxes` and `_merge_boxes` are pure and unit-tested; `_ocr_words` shells
out to tesseract.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections import defaultdict

# A key on a line means "redact the rest of this line" (the value is sensitive).
_SENSITIVE_KEYS = (
    "cookie", "set-cookie", "authorization", "proxy-authorization",
    "phpsessid", "jsessionid", "asp.net_sessionid", "sessionid", "session",
    "token", "access_token", "refresh_token", "id_token", "csrf",
    "api_key", "apikey", "x-api-key", "secret", "client_secret",
    "password", "passwd", "pwd", "bearer", "auth", "x-auth-token",
)

# High-precision standalone value shapes (low false-positive). base64 is
# deliberately NOT matched standalone — it false-hits MIME types / header values;
# real base64 secrets sit after a KEY (Authorization/api_key=), which is covered.
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{4,}")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_HEX = re.compile(r"[0-9a-fA-F]{16,}")


def _is_sensitive_value(word: str) -> bool:
    """A token that LOOKS like a secret regardless of context (high precision)."""
    return bool(_JWT.search(word) or _EMAIL.search(word) or _HEX.search(word))


def _has_key(token: str) -> bool:
    low = token.lower()
    return any(k in low for k in _SENSITIVE_KEYS)


def _sensitive_boxes(words: list[dict], y_tol: int = 8) -> list[list[int]]:
    """Pure: from OCR word boxes, the merged [x,y,w,h] boxes to redact.

    Groups words into VISUAL lines by y-coordinate (not OCR's fragile line ids,
    which split one line into pieces). When a sensitive KEY (Cookie /
    Authorization / PHPSESSID / api_key / ...) is on a line, redacts from the
    value to the line's RIGHT edge — covering the whole secret even when OCR
    mangles or splits the token. Otherwise boxes only high-precision value shapes
    (long hex / JWT / email). Over-redacts the safe way; never leaves a keyed
    value uncovered.
    """
    lines: list[list[dict]] = []
    for w in sorted(words, key=lambda w: (w["top"], w["left"])):
        for ln in lines:
            if abs(w["top"] - ln[0]["top"]) <= y_tol:
                ln.append(w)
                break
        else:
            lines.append([w])

    boxes: list[list[int]] = []
    for ln in lines:
        ln.sort(key=lambda w: w["left"])
        key_idx = next((i for i, w in enumerate(ln)
                        if _has_key(str(w.get("text", "")))), None)
        if key_idx is not None:
            key = ln[key_idx]
            kt = str(key.get("text", ""))
            # inline value (`PHPSESSID=25d7…`) -> cover the token; bare label
            # (`Cookie`/`Authorization:`) -> start just after it.
            if re.search(r"[:=]\S", kt):
                x0 = key["left"]
            else:
                x0 = key["left"] + key["width"] + 4
            right = max(w["left"] + w["width"] for w in ln)
            top = min(w["top"] for w in ln)
            bottom = max(w["top"] + w["height"] for w in ln)
            if right - x0 > 0:
                boxes.append([x0, top, right - x0, bottom - top])
        else:
            # No key on the line: only box HIGH-CONFIDENCE value shapes, so
            # low-conf OCR noise doesn't create spurious redactions.
            for w in ln:
                if w.get("conf", 100) >= 40 and _is_sensitive_value(str(w.get("text", ""))):
                    boxes.append([w["left"], w["top"], w["width"], w["height"]])
    return _merge_boxes(boxes)


def _merge_boxes(boxes: list[list[int]], y_tol: int = 8, x_gap: int = 30,
                 pad: int = 2) -> list[list[int]]:
    """Pure: merge boxes on the ~same line that are near in x into one, pad slightly."""
    merged: list[list[int]] = []
    for b in sorted(boxes, key=lambda b: (b[1], b[0])):
        placed = False
        for m in merged:
            same_line = abs(b[1] - m[1]) <= y_tol
            near_x = b[0] <= m[0] + m[2] + x_gap and b[0] + b[2] >= m[0] - x_gap
            if same_line and near_x:
                x0, y0 = min(m[0], b[0]), min(m[1], b[1])
                x1 = max(m[0] + m[2], b[0] + b[2])
                y1 = max(m[1] + m[3], b[1] + b[3])
                m[0], m[1], m[2], m[3] = x0, y0, x1 - x0, y1 - y0
                placed = True
                break
        if not placed:
            merged.append(list(b))
    return [[max(0, x - pad), max(0, y - pad), w + 2 * pad, h + 2 * pad]
            for x, y, w, h in merged]


def tesseract_available() -> bool:
    return shutil.which("tesseract") is not None


def _ocr_words(path: str, min_conf: float = 10.0) -> list[dict]:
    """Word boxes via the tesseract CLI (TSV). Low floor on purpose — a keyed
    line's redaction must extend over GARBLED (low-conf) token words too, or the
    secret leaks; standalone value-matching re-gates on higher confidence. Empty
    list on failure."""
    try:
        proc = subprocess.run(
            ["tesseract", str(path), "stdout", "--psm", "11", "tsv"],
            capture_output=True, text=True, timeout=90,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    words: list[dict] = []
    for line in proc.stdout.splitlines()[1:]:   # skip header row
        f = line.split("\t")
        if len(f) < 12:
            continue
        try:
            level = int(f[0])
            left, top, w, h = int(f[6]), int(f[7]), int(f[8]), int(f[9])
            conf = float(f[10])
        except ValueError:
            continue
        text = f[11]
        if level != 5 or conf < min_conf or not text.strip():
            continue
        words.append({"text": text, "left": left, "top": top, "width": w,
                      "height": h, "conf": conf, "line": f"{f[2]}-{f[3]}-{f[4]}"})
    return words


def _trailing_fraction(boxes: list[list[int]], coverage: float) -> list[list[int]]:
    """Shrink each box to its trailing `coverage` fraction (the value's tail).

    Redact-half convention: keep the label + prefix readable (which header /
    which token), mosaic only the high-entropy tail. `coverage=1.0` covers the
    whole value; `0.5` covers the back half.
    """
    if coverage >= 1.0:
        return boxes
    coverage = max(0.05, min(1.0, coverage))
    out: list[list[int]] = []
    for x, y, w, h in boxes:
        cw = max(1, round(w * coverage))
        out.append([x + (w - cw), y, cw, h])
    return out


def detect_sensitive_boxes(path: str, coverage: float = 0.5) -> list[list[int]]:
    """OCR the image and return the [x,y,w,h] boxes to redact.

    `coverage` is the fraction of each value covered from the RIGHT — default 0.5
    redacts the back half and leaves the label/prefix visible; 1.0 covers all.
    """
    return _trailing_fraction(_sensitive_boxes(_ocr_words(path)), coverage)
