"""Bulk scope import from recon-tool output."""
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools import _scope_mode


def _read_subfinder_txt(p: Path) -> list[str]:
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line if line.startswith("http") else f"https://{line}")
    return out


def _read_amass_json(p: Path) -> list[str]:
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = obj.get("name") or obj.get("hostname")
        if name:
            out.append(f"https://{name}")
    return out


def _read_httpx_json(p: Path) -> list[str]:
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = obj.get("url") or obj.get("input")
        if url:
            out.append(url)
    return out


def _read_plain(p: Path) -> list[str]:
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line if line.startswith("http") else f"https://{line}")
    return out


def _read_noir_json(p: Path) -> list[str]:
    """OWASP Noir JSON output.

    Noir emits either a top-level list of endpoints
        [{"method":"GET","url":"...","headers":{},"params":[...]}, ...]
    or an object with `endpoints: [...]`. Each endpoint has a `url`. We pull
    only the host (Burp scope is host-keyed) but persist the full Noir record
    under .burp-intel/<domain>/endpoints.json so auto_probe can read sinks
    and guards later.
    """
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []

    items: list[dict] = []
    if isinstance(raw, list):
        items = [r for r in raw if isinstance(r, dict)]
    elif isinstance(raw, dict):
        if "endpoints" in raw and isinstance(raw["endpoints"], list):
            items = [r for r in raw["endpoints"] if isinstance(r, dict)]
        elif "data" in raw and isinstance(raw["data"], list):
            items = [r for r in raw["data"] if isinstance(r, dict)]

    hosts: list[str] = []
    seen: set[str] = set()
    for item in items:
        url = item.get("url") or item.get("path")
        if not isinstance(url, str):
            continue
        if not url.startswith(("http://", "https://")):
            url = "https://" + url.lstrip("/")
        if url in seen:
            continue
        seen.add(url)
        hosts.append(url)
    return hosts


def _sniff_format(p: Path) -> str:
    sample = p.read_text(errors="ignore")[:4096].strip()
    if not sample:
        return "plain"

    # Noir emits a JSON document (list or object with endpoints) — distinct
    # from httpx jsonl (one object per line). Detect by whole-file parse.
    if sample.startswith(("[", "{")):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(doc, list) and doc and isinstance(doc[0], dict):
                if doc[0].get("method") or doc[0].get("params") is not None:
                    return "noir_json"
            if isinstance(doc, dict) and ("endpoints" in doc or "data" in doc):
                return "noir_json"
        except json.JSONDecodeError:
            pass

    first = sample.splitlines()[0].strip()
    if first.startswith("{"):
        try:
            obj = json.loads(first)
            if "url" in obj or "input" in obj:
                return "httpx_json"
            if "name" in obj or "hostname" in obj:
                return "amass_json"
        except json.JSONDecodeError:
            pass
    return "plain"


_READERS = {
    "subfinder_txt": _read_subfinder_txt,
    "amass_json": _read_amass_json,
    "httpx_json": _read_httpx_json,
    "noir_json": _read_noir_json,
    "plain": _read_plain,
}


def register(mcp: FastMCP):

    @mcp.tool()
    async def import_scope(
        source: str,
        format: str = "auto",
    ) -> str:
        """Bulk-add hosts to Burp scope from a recon-tool output file.

        Args:
            source: Path to file (subfinder.txt, amass.json, httpx.jsonl, or plain newline-separated)
            format: 'subfinder_txt' | 'amass_json' | 'httpx_json' | 'plain' | 'auto'
        """
        p = Path(source).expanduser()
        if not p.exists():
            return f"Error: source not found: {source}"

        fmt = _sniff_format(p) if format == "auto" else format
        reader = _READERS.get(fmt)
        if not reader:
            return f"Error: unknown format {fmt!r}; valid: {sorted(_READERS)} | auto"

        urls = reader(p)
        if not urls:
            return f"Warning: no hosts parsed from {source} (format={fmt})"

        payload = {
            "include": urls,
            "exclude": [],
            "auto_filter": True,
            "replace": False,
            "keep_in_scope": [],
            "mode": _scope_mode.get_mode(),
        }
        data = await client.post("/api/scope/configure", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        return (
            f"import_scope ({fmt}): added: {data.get('included', 0)}, "
            f"total in source: {len(urls)}, format_detected: {fmt}"
        )
