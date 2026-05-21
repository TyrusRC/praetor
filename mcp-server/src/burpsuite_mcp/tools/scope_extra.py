"""Bulk scope import from recon-tool output."""
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


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


def _sniff_format(p: Path) -> str:
    sample = p.read_text(errors="ignore")[:4096].strip()
    if not sample:
        return "plain"
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
            "mode": "operator",
        }
        data = await client.post("/api/scope/configure", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        return (
            f"import_scope ({fmt}): added: {data.get('included', 0)}, "
            f"total in source: {len(urls)}, format_detected: {fmt}"
        )
