"""Shared helpers for the offline artifact analyzer: redaction, size/path guards,
result-shape normalization. Pure Python, no Burp/client dependency."""

import os

MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB per-file read cap

_RESULT_KEYS = (
    "attack_surface", "api_inventory", "inputs", "id_references",
    "secrets", "sources_sinks", "observations", "hypotheses",
    "priority_test_plan",
)


def redact_secret(value: str) -> str:
    """Return a shape-only fingerprint of a secret — never the value."""
    v = (value or "").strip()
    if len(v) <= 8:
        return "…"
    return f"{v[:4]}…{v[-4:]}"


def confine_path(root: str, candidate: str) -> str | None:
    """Resolve candidate and return it only if it stays under root, else None."""
    root_real = os.path.realpath(root)
    cand_real = os.path.realpath(candidate)
    if cand_real == root_real or cand_real.startswith(root_real + os.sep):
        return cand_real
    return None


def assemble(kind: str, source: str, parts: dict) -> dict:
    """Normalize a partial parts dict into the full, stable result shape."""
    out = {"kind": kind, "source": source}
    for k in _RESULT_KEYS:
        out[k] = parts.get(k, [])
    return out
