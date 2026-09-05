"""route_signals — signal->tool router. Selects and ranks; never executes."""

from mcp.server.fastmcp import FastMCP

from . import _engine, _signals


async def route_signals(domain: str = "", signals: list[dict] | None = None,
                        targets: list[str] | None = None) -> dict:
    """Given target signals (tech, errors, reflections, live services, creds),
    return a ranked action plan: `auto` (fire now), `ask` (approve first),
    `dropped` (unsafe). Red-team/AD/cloud/exploit and expensive scans are always
    `ask`; HARD-denylisted args are dropped. Selects only — the caller fires.
    """
    sigs = _signals.collect_signals(domain) if domain else []
    sigs += _signals.normalize_signals(signals or [])
    plan = _engine.match(sigs)
    plan["signals_seen"] = sorted({s["type"] for s in sigs})
    return plan


def register(mcp: FastMCP) -> None:
    mcp.tool()(route_signals)
