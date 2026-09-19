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

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{4,}")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_HEX = re.compile(r"[0-9a-fA-F]{16,}")
_B64 = re.compile(r"[A-Za-z0-9+/=_-]{20,}")


def _is_sensitive_value(word: str) -> bool:
    """A token that LOOKS like a secret regardless of context."""
    return bool(_JWT.search(word) or _EMAIL.search(word)
                or _HEX.search(word) or _B64.search(word))


def _has_key(token: str) -> bool:
    low = token.lower()
    return any(k in low for k in _SENSITIVE_KEYS)


def _sensitive_boxes(words: list[dict]) -> list[list[int]]:
    """Pure: from OCR word boxes, the merged [x,y,w,h] boxes to redact.

    Each word is {text,left,top,width,height,line}. A word is redacted when it
    matches a secret shape, OR a sensitive KEY appeared earlier on its line (so
    the whole value after `Cookie:` / `Authorization:` is covered).
    """
    lines: dict[str, list[dict]] = defaultdict(list)
    for w in words:
        lines[w.get("line", "")].append(w)

    hits: list[dict] = []
    for _, ws in lines.items():
        ws = sorted(ws, key=lambda w: w["left"])
        redact_rest = False
        for w in ws:
            t = str(w.get("text", "")).strip()
            if not t:
                continue
            if redact_rest:
                hits.append(w)
                continue
            if _has_key(t):
                redact_rest = True
                # Box only if the value is inline (`PHPSESSID=25d7…`), not a bare
                # label like `Cookie:` — the label can stay, the value is covered.
                m = re.search(r"[:=](.+)", t)
                if m and m.group(1).strip():
                    hits.append(w)
                continue
            if _is_sensitive_value(t):
                hits.append(w)
    return _merge_boxes([[w["left"], w["top"], w["width"], w["height"]] for w in hits])


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


def _ocr_words(path: str, min_conf: float = 40.0) -> list[dict]:
    """Word boxes via the tesseract CLI (TSV). Empty list on failure."""
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
                      "height": h, "line": f"{f[2]}-{f[3]}-{f[4]}"})
    return words


def detect_sensitive_boxes(path: str) -> list[list[int]]:
    """OCR the image and return the [x,y,w,h] boxes to redact."""
    return _sensitive_boxes(_ocr_words(path))
