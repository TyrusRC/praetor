"""Shared recon-extended helpers — domain sanitiser + dig wrappers."""

import asyncio
import re

_DIG_MISSING_LOGGED = False


def _sanitize_domain(domain: str) -> str:
    """Sanitize domain input to prevent injection."""
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$', domain):
        raise ValueError(f"Invalid domain: {domain}")
    return domain


async def _dig(domain: str, record_type: str, timeout: int = 10) -> str:
    """Run dig for a specific record type. Returns +short output.

    Empty string when dig is missing (Windows) or the lookup times out.
    Use `_dig_available()` to distinguish "dig missing" from "no records".
    """
    global _DIG_MISSING_LOGGED
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", domain, record_type, "+short",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout_b.decode(errors="replace").strip()
    except asyncio.TimeoutError:
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
        return ""
    except FileNotFoundError:
        _DIG_MISSING_LOGGED = True
        return ""


def _dig_available() -> bool:
    """Return True if `dig` is on PATH."""
    import shutil
    return shutil.which("dig") is not None
