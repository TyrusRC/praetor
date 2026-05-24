"""Per-engagement cost cap. Tokens + USD ceiling, persisted under .burp-intel/.

pentest-ai ships a $10 default cap. Praetor's equivalent — operators set a
ceiling per domain, tools call check_cost_budget() to early-exit before
burning more budget on a session that's already past its limit.

Persisted at .burp-intel/<domain>/cost.json:
    {
        "max_usd": 25.0,
        "max_tokens": 5000000,
        "spent_usd": 4.21,
        "spent_tokens": 812345,
        "warn_threshold": 0.8,
        "updated_at": "2026-05-24T..."
    }

Spent counters are advisory — Claude Code reports cost to the operator, and
the operator updates the counter when material work happens. No automatic
token accounting (the MCP server can't see Claude's billing).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP


_REPO_ROOT = Path(__file__).resolve().parents[5]
_INTEL_ROOT = _REPO_ROOT / ".burp-intel"


def _cost_path(domain: str) -> Path:
    sanitized = "".join(c for c in domain if c.isalnum() or c in ".-_")
    if not sanitized:
        raise ValueError("domain required")
    d = _INTEL_ROOT / sanitized
    d.mkdir(parents=True, exist_ok=True)
    return d / "cost.json"


def _read(domain: str) -> dict:
    p = _cost_path(domain)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write(domain: str, data: dict) -> None:
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    _cost_path(domain).write_text(json.dumps(data, indent=2), encoding="utf-8")


def register(mcp: FastMCP):

    @mcp.tool()
    async def set_engagement_cost_cap(
        domain: str,
        max_usd: float = 25.0,
        max_tokens: int = 5_000_000,
        warn_threshold: float = 0.8,
    ) -> str:
        """Set engagement cost ceiling for a target domain.

        Tools that consume significant tokens (concurrent_requests, auto_probe,
        run_recon_pipeline, browser_crawl) should call check_cost_budget()
        beforehand and early-exit if spent >= max.

        Args:
            domain: Target domain (eg. example.com)
            max_usd: USD ceiling for this engagement
            max_tokens: Token ceiling
            warn_threshold: Fraction of cap that triggers warning (default 0.8)
        """
        if max_usd <= 0 or max_tokens <= 0:
            return "Error: max_usd and max_tokens must be > 0"
        if not 0.5 <= warn_threshold <= 0.99:
            return "Error: warn_threshold must be in [0.5, 0.99]"

        data = _read(domain)
        data.update(
            {
                "max_usd": float(max_usd),
                "max_tokens": int(max_tokens),
                "warn_threshold": float(warn_threshold),
                "spent_usd": float(data.get("spent_usd", 0.0)),
                "spent_tokens": int(data.get("spent_tokens", 0)),
            }
        )
        _write(domain, data)
        return (
            f"Cost cap set for {domain}: ${max_usd:.2f} / {max_tokens:,} tokens "
            f"(warn at {warn_threshold:.0%})."
        )

    @mcp.tool()
    async def record_engagement_cost(
        domain: str,
        usd: float = 0.0,
        tokens: int = 0,
    ) -> str:
        """Operator advisory — record consumed cost against a cap.

        Args:
            domain: Target domain
            usd: USD spent since last record (added, not replaced)
            tokens: Tokens spent since last record (added, not replaced)
        """
        data = _read(domain)
        if not data:
            return f"Error: no cost cap set for {domain}. Run set_engagement_cost_cap first."
        data["spent_usd"] = float(data.get("spent_usd", 0.0)) + max(0.0, float(usd))
        data["spent_tokens"] = int(data.get("spent_tokens", 0)) + max(0, int(tokens))
        _write(domain, data)
        return await _budget_summary(domain, data)

    @mcp.tool()
    async def check_cost_budget(domain: str) -> str:
        """Report current cost / token spend vs cap for a target domain.

        Use at session start and before any high-volume tool call.
        Returns OK / WARN / EXCEEDED + actionable detail.

        Args:
            domain: Target domain
        """
        data = _read(domain)
        if not data:
            return f"No cap set for {domain}. Returning OK (unbounded engagement)."
        return await _budget_summary(domain, data)


async def _budget_summary(domain: str, data: dict) -> str:
    max_usd = float(data.get("max_usd", 0) or 0)
    max_tokens = int(data.get("max_tokens", 0) or 0)
    spent_usd = float(data.get("spent_usd", 0) or 0)
    spent_tokens = int(data.get("spent_tokens", 0) or 0)
    warn = float(data.get("warn_threshold", 0.8) or 0.8)

    usd_pct = (spent_usd / max_usd) if max_usd else 0.0
    tok_pct = (spent_tokens / max_tokens) if max_tokens else 0.0
    worst = max(usd_pct, tok_pct)

    state = "OK"
    if worst >= 1.0:
        state = "EXCEEDED"
    elif worst >= warn:
        state = "WARN"

    return (
        f"[{state}] {domain} budget: "
        f"${spent_usd:.2f} / ${max_usd:.2f} ({usd_pct:.0%}), "
        f"{spent_tokens:,} / {max_tokens:,} tokens ({tok_pct:.0%})"
    )
