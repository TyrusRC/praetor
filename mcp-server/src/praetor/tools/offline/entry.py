"""analyze_artifact — Burp-independent offline analysis of a raw-request file,
a JS file/URL/dir, or a project/ tree. Produces an attack-surface map with
observations separated from (non-asserted) hypotheses."""

import json
import os
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from . import _detect, _js_extract, _project, _raw_request, _report


def _read_capped(path: str) -> tuple[str | None, str | None]:
    try:
        if os.path.getsize(path) > _report.MAX_FILE_BYTES:
            return None, f"skipped {os.path.basename(path)}: exceeds size cap"
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(), None
    except OSError as e:
        return None, f"error reading {path}: {e}"


async def analyze_artifact(source: str, kind: str = "auto", domain: str = "") -> dict:
    """Analyze a security artifact offline (no Burp): a saved raw-request .txt,
    a JS file/URL, a directory of JS, or a project/ tree. Returns an
    attack-surface map, API inventory, redacted secrets, and hypotheses
    (labelled, never asserted as vulnerabilities). Set `domain` to persist.
    """
    if kind == "auto":
        if not source.startswith(("http://", "https://")) and not os.path.exists(source):
            return {"error": f"source not found: {source}"}
        kind = _detect.detect_kind(source)

    try:
        if kind == "raw_request":
            text, err = _read_capped(source)
            if text is None:
                return {"error": err}
            parts = _raw_request.parse_raw_request(text)

        elif kind == "js":
            text, err = _read_capped(source)
            if text is None:
                parts = {"observations": [err]}
            else:
                parts = _js_extract.scan_js(text, os.path.basename(source))

        elif kind == "js_dir":
            results, notes = [], []
            for dp, _d, files in os.walk(source):
                for f in files:
                    if f.lower().endswith((".js", ".mjs", ".ts", ".jsx", ".tsx")):
                        full = _report.confine_path(source, os.path.join(dp, f))
                        if not full:
                            continue
                        text, err = _read_capped(full)
                        if text is None:
                            notes.append(err)
                        else:
                            results.append(_js_extract.scan_js(text, os.path.relpath(full, source)))
            parts = _js_extract.merge_js_results(results)
            parts.setdefault("observations", []).extend(notes)

        elif kind == "js_url":
            parts = await _fetch_and_scan(source)

        elif kind == "project":
            parts = _project.correlate_project(source)

        else:
            return {"error": f"unknown kind: {kind}"}
    except Exception as e:  # defensive: never crash the tool loop
        return {"error": f"analysis failed: {e}"}

    result = _report.assemble(kind, source, parts)

    if domain:
        _persist(domain, kind, result)
    return result


async def _fetch_and_scan(url: str) -> dict:
    """Read-only GET of a static JS asset (no payloads), then regex-scan it."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False,
                                     verify=True) as c:
            resp = await c.get(url)
            body = resp.text[: _report.MAX_FILE_BYTES]
    except Exception as e:
        return {"observations": [f"could not fetch {url}: {e}"]}
    parts = _js_extract.scan_js(body, url)
    parts.setdefault("observations", []).append(
        "fetched out-of-Burp (static recon GET, no payloads)")
    return parts


def _persist(domain: str, kind: str, result: dict) -> None:
    safe = "".join(c for c in domain if c.isalnum() or c in ".-_")
    base = os.path.join(".burp-intel", safe, "material", "offline")
    try:
        os.makedirs(base, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = os.path.join(base, f"{kind}-{ts}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        notes = os.path.join(".burp-intel", safe, "notes.md")
        with open(notes, "a", encoding="utf-8") as fh:
            fh.write(f"\n- offline {kind} analysis → {path}\n")
    except OSError:
        pass  # persistence is best-effort; the result is already returned


def register(mcp: FastMCP) -> None:
    mcp.tool()(analyze_artifact)
