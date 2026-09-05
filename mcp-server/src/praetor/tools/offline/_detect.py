"""Detect what kind of artifact a source path/URL is."""

import os
import re

_REQ_LINE = re.compile(r"^[A-Z]{3,7}\s+\S+\s+HTTP/\d(?:\.\d)?\s*$")
_PROJECT_DIRS = {"recon", "requests", "javascript", "source"}


def is_request_line(line: str) -> bool:
    return bool(_REQ_LINE.match(line.strip()))


def detect_kind(source: str) -> str:
    if source.startswith(("http://", "https://")):
        return "js_url"
    if os.path.isdir(source):
        children = {c.lower() for c in os.listdir(source)}
        if children & _PROJECT_DIRS:
            return "project"
        return "js_dir"
    if source.lower().endswith((".js", ".mjs", ".ts", ".jsx", ".tsx")):
        return "js"
    try:
        with open(source, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    return "raw_request" if is_request_line(line) else "js"
    except OSError:
        pass
    return "js"
