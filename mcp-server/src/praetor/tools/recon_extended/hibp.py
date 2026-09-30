"""hibp_breach_lookup — Have I Been Pwned v3 breach lookup (passive OSINT)."""

import os
from urllib.parse import quote

import httpx
from mcp.server.fastmcp import FastMCP

_BASE = "https://haveibeenpwned.com/api/v3"
# HIBP requires a descriptive, identifying User-Agent on every request.
_USER_AGENT = "Praetor-Recon/1.0"


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def hibp_breach_lookup(
        target: str,
        kind: str = "domain",
        timeout: int = 30,
    ) -> str:
        """Look up breaches for a domain or account via Have I Been Pwned (v3, passive).

        No Burp routing — passive third-party OSINT. Account lookups require the
        HIBP_API_KEY environment variable (subscription key); domain lookups query
        the public breach list.

        Args:
            target: Domain (kind='domain') or email/username (kind='account')
            kind: 'domain' or 'account' (default 'domain')
            timeout: Max seconds to wait (default 30)
        """
        kind = kind.strip().lower()
        if kind not in ("domain", "account"):
            return f"Error: invalid kind '{kind}' (expected 'domain' or 'account')"
        if not target.strip():
            return "Error: target is required"

        api_key = os.environ.get("HIBP_API_KEY", "")
        headers = {"User-Agent": _USER_AGENT}
        if api_key:
            headers["hibp-api-key"] = api_key

        if kind == "account":
            if not api_key:
                return "Error: HIBP_API_KEY not set (required for account lookups)"
            url = f"{_BASE}/breachedaccount/{quote(target.strip(), safe='')}?truncateResponse=false"
        else:
            url = f"{_BASE}/breaches?domain={quote(target.strip(), safe='')}"

        try:
            async with httpx.AsyncClient(timeout=timeout) as http:
                resp = await http.get(url, headers=headers)
        except httpx.TimeoutException:
            return f"Error: HIBP request timed out ({timeout}s)"
        except Exception as e:
            return f"Error querying HIBP: {e}"

        if resp.status_code == 404:
            return f"No breaches found for {target}"
        if resp.status_code == 401:
            return "Error: HIBP rejected the API key (HTTP 401 — check HIBP_API_KEY)"
        if resp.status_code == 429:
            retry = resp.headers.get("retry-after", "?")
            return f"Error: HIBP rate limit hit (HTTP 429, retry-after {retry}s)"
        if resp.status_code != 200:
            return f"Error: HIBP returned HTTP {resp.status_code}"

        try:
            breaches = resp.json()
        except Exception as e:
            return f"Error: could not parse HIBP response: {e}"

        if not breaches:
            return f"No breaches found for {target}"

        lines = [f"HIBP breaches for {target} ({len(breaches)}):", ""]
        for b in breaches:
            name = b.get("Name") or b.get("Title") or "?"
            date = b.get("BreachDate", "")
            pwned = b.get("PwnCount")
            suffix = f" — {pwned:,} accounts" if isinstance(pwned, int) else ""
            when = f" ({date})" if date else ""
            lines.append(f"  {name}{when}{suffix}")
        return "\n".join(lines)
