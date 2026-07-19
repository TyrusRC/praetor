"""Shared helpers and constants for the recon tool package.

Used by inventory, subdomain, crawling, scanning, network, and pipeline submodules.
Import from here rather than re-declaring in each submodule.
"""

import asyncio
import os
import shutil

from burpsuite_mcp.config import BURP_PROXY_URL  # noqa: F401 — re-exported for submodules

# ProjectDiscovery tools installed via `go install` land in ~/go/bin.
# Prepend it to search path so Go tools are found.
_GO_BIN = os.path.join(os.path.expanduser("~"), "go", "bin")
_SEARCH_PATH = os.pathsep.join([_GO_BIN, os.environ.get("PATH", "")])

# Realistic User-Agent to avoid bot detection on targets
_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def _find_tool(name: str) -> str | None:
    """Find tool binary, preferring ~/go/bin for ProjectDiscovery tools."""
    return shutil.which(name, path=_SEARCH_PATH)


def _check_tool(name: str) -> bool:
    """Check if an external tool is installed."""
    return _find_tool(name) is not None


async def _run_cmd(cmd: list[str], timeout: int = 120, bypass_proxy: bool = False,
                   stdin_input: bytes | None = None) -> tuple[str, str, int]:
    """Run a command safely using create_subprocess_exec (no shell) and return (stdout, stderr, returncode).

    Routes HTTPS_PROXY/HTTP_PROXY env vars to Burp by default (Rule 26a).
    Pass ``bypass_proxy=True`` for tools that intentionally skip Burp
    (passive DB queries — amass / gau / wafw00f).
    """
    # Resolve full path so ~/go/bin tools aren't shadowed by system packages
    resolved = _find_tool(cmd[0])
    if resolved:
        cmd = [resolved] + cmd[1:]

    # Force Go tools to use C resolver — fixes DNS in WSL2 where Go's pure-Go
    # resolver can't reach DNS servers listed in /etc/resolv.conf
    env = os.environ.copy()
    env["GODEBUG"] = "netdns=cgo"

    # Rule 26a: every subprocess that emits target HTTP must route through Burp.
    # Per-tool wrappers also set their own --proxy flag (belt-and-braces) so a
    # future wrapper missing the flag still inherits the contract from env.
    if bypass_proxy:
        env.pop("HTTPS_PROXY", None)
        env.pop("HTTP_PROXY", None)
        env.pop("https_proxy", None)
        env.pop("http_proxy", None)
    else:
        env.setdefault("HTTPS_PROXY", BURP_PROXY_URL)
        env.setdefault("HTTP_PROXY", BURP_PROXY_URL)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            # ProjectDiscovery tools (httpx, nuclei, katana, subfinder, gau,
            # waybackurls) auto-detect piped stdin and read URLs from it,
            # ignoring -u / -list flags. The MCP server's own stdin is the
            # MCP stdio transport pipe — leaving stdin inherited makes those
            # tools hang waiting for input that never comes. DEVNULL forces
            # them to fall through to the explicit -u / -list path. When a caller
            # needs to feed stdin (notify -bulk, peirates script), pass stdin_input
            # and we open a PIPE instead.
            stdin=asyncio.subprocess.PIPE if stdin_input is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_input), timeout=timeout)
        rc = proc.returncode if proc.returncode is not None else 1
        return stdout.decode(errors="replace"), stderr.decode(errors="replace"), rc
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except Exception:
            pass
        return "", f"Command timed out after {timeout}s", 1
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]}", 127


def _sanitize_domain(domain: str) -> str:
    """Sanitize domain input to prevent injection via arguments."""
    import re
    # Must start with alphanumeric (reject leading hyphens to prevent flag injection)
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$', domain):
        raise ValueError(f"Invalid domain: {domain}")
    return domain
