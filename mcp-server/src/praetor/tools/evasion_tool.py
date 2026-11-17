"""set_evasion_profile / get_evasion_profile — control the request evasion
layer (_request_evasion) that randomizes outbound traffic patterns to avoid
blue-team fingerprinting (WAF, IDS, SIEM correlation, bot-detection).

Default: light. Profiles: off / light / moderate / full."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from praetor.tools import _request_evasion


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    def set_evasion_profile(profile: str) -> str:
        """Set the session's request evasion profile to avoid blue-team detection.

        Evasion randomizes outbound traffic patterns so requests do not look
        like uniform tool output. Real browsers vary UA, header order,
        Accept-Language, Sec-Fetch values, and occasionally send cache/referer
        headers — this layer reproduces that variation.

        Args:
            profile: 'light' (default — fingerprint
                rotation + accept-language variation), 'moderate' (+ header
                order shuffling + decoy injection + sec-fetch variation),
                or 'full' (+ referer injection + cache-control randomization).

        Applies to every request that passes through apply_realistic_headers
        (curl_request, session_request, concurrent_requests, auth tools, etc.)
        for the rest of the session. Does not affect send_raw_request (bare
        by definition) or bare_headers=True calls.
        """
        try:
            applied = _request_evasion.set_profile(profile)
        except ValueError as e:
            return f"Error: {e}"
        if applied == "off":
            return "Evasion profile: off — no traffic randomization."
        return (
            f"Evasion profile: {applied} — outbound requests now vary "
            f"fingerprint, headers, and timing patterns per host."
        )

    @mcp.tool()
    def get_evasion_profile() -> str:
        """Show the active evasion profile and per-host request counts."""
        s = _request_evasion.stats()
        lines = [f"profile: {s['profile']}"]
        lines.append(f"fingerprint rotation interval: every {s['rotation_interval']} requests per host")
        if s["hosts"]:
            lines.append("evasion-processed requests per host:")
            for host, n in sorted(s["hosts"].items()):
                lines.append(f"  {host}: {n}")
        else:
            lines.append("no evasion-processed requests yet this session.")
        return "\n".join(lines)


__all__ = ["register"]
