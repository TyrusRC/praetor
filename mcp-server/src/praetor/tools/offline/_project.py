"""Correlate a project/ tree (recon + requests + javascript + source) into one
attack-surface model with prioritized manual-test plan. No confirmed findings."""

import os

from . import _js_extract, _raw_request
from ._report import MAX_FILE_BYTES, confine_path


def _read(path: str) -> str | None:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _walk(root: str, subdir: str, exts: tuple[str, ...]):
    base = os.path.join(root, subdir)
    if not os.path.isdir(base):
        return
    for dirpath, _dirs, files in os.walk(base):
        for f in files:
            if exts and not f.lower().endswith(exts):
                continue
            full = confine_path(root, os.path.join(dirpath, f))
            if full:
                yield full


def correlate_project(root: str) -> dict:
    observations, hypotheses, inputs, id_refs = [], [], [], []

    # JavaScript
    js_results = []
    for f in _walk(root, "javascript", (".js", ".mjs", ".ts", ".jsx", ".tsx")):
        text = _read(f)
        if text is not None:
            js_results.append(_js_extract.scan_js(text, os.path.relpath(f, root)))
    js = _js_extract.merge_js_results(js_results)

    # Saved requests
    for f in _walk(root, "requests", (".txt", ".req", ".http")):
        text = _read(f)
        if text is None:
            continue
        parsed = _raw_request.parse_raw_request(text)
        inputs += parsed["inputs"]
        id_refs += parsed["id_references"]
        hypotheses += parsed["hypotheses"]
        observations += parsed["observations"]

    # Recon lists (context only)
    for f in _walk(root, "recon", (".txt",)):
        text = _read(f)
        if text is not None:
            n = len([l for l in text.splitlines() if l.strip()])
            observations.append(f"recon list {os.path.relpath(f, root)}: {n} entries")

    # Prioritized plan: authz/business-logic first (Rule 29), then admin routes
    plan, rank = [], 1
    for h in hypotheses:
        plan.append({"rank": rank, "target": h["claim"][:80], "class": "business_logic/authz",
                     "rationale": h["expected_evidence"]})
        rank += 1
    for a in js["attack_surface"]:
        plan.append({"rank": rank, "target": a["endpoint"], "class": "access_control",
                     "rationale": a["why"]})
        rank += 1

    return {
        "attack_surface": js["attack_surface"],
        "api_inventory": js["api_inventory"],
        "inputs": inputs,
        "id_references": id_refs,
        "secrets": js["secrets"],
        "sources_sinks": js["sources_sinks"],
        "observations": observations,
        "hypotheses": hypotheses,
        "priority_test_plan": plan,
    }
