"""set_noise_profile / get_noise_profile — control the per-host outbound
noise governor (praetor._noise_governor), wired into every target-dispatching
client.post() call. Off by default; see that module's docstring for the
gap this closes (ARTEX's egress/pace.go had no Praetor equivalent: Rule 6a
bounds ONE call's volume, nothing throttled the WHOLE session's request
rate per host)."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from praetor import _noise_governor


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    def set_noise_profile(profile: str) -> str:
        """Set the session's per-host outbound request pacing profile.

        Args:
            profile: 'off' (default, no pacing), 'quiet' (~0.5 req/s per
                host, burst 2 — stays well under most WAF rate thresholds),
                'balanced' (~2 req/s, burst 5), or 'aggressive' (~10 req/s,
                burst 20 — light pacing, doesn't slow down hunting much).

        Applies to every curl_request/session_request/concurrent_requests/
        resend_with_modification/send_to_repeater call for the rest of the
        process — set it once per engagement, not per call. Does not affect
        Burp-state-only calls (get_proxy_history, annotate_request, etc.) —
        those never touch the target, so there is nothing to pace.
        """
        try:
            applied = _noise_governor.set_profile(profile)
        except ValueError as e:
            return f"Error: {e}"
        if applied == "off":
            return "Noise profile: off — no pacing (Praetor's default)."
        return f"Noise profile: {applied} — every target-dispatching call is now paced per host."

    @mcp.tool()
    def get_noise_profile() -> str:
        """Show the active noise profile and per-host request counts paced so far."""
        s = _noise_governor.stats()
        lines = [f"profile: {s['profile']}"]
        if s["hosts"]:
            lines.append("paced requests per host:")
            for host, n in sorted(s["hosts"].items()):
                lines.append(f"  {host}: {n}")
        else:
            lines.append("no requests paced yet this session.")
        return "\n".join(lines)


__all__ = ["register"]
