"""probe_a2a_agent_card — Linux Foundation A2A v1.0.

Agent-to-Agent (A2A) v1.0 lets agents advertise capabilities via a
well-known agent card (commonly `/.well-known/agent.json` or
`/.well-known/a2a-card`). Peers consume the card to discover delegation
targets, capability scopes, and signing keys.

Risks:
  - Missing signature → anyone can forge a card that overstates capability
  - Capability over-claim (`*` or `any:any`) → peer accepts arbitrary tool calls
  - Recursive delegation enabled without `max_depth` → DoS / fan-out abuse
  - Missing `accepted_callers` allowlist → world-callable
  - URL fields point to localhost / metadata IPs → SSRF chain
  - Expired or mismatching `version` field → downgrade attack surface

CONFIRMED on missing signature with recursive delegation enabled, OR
capability over-claim combined with no caller allowlist.

Returns VerdictResult.
"""

from __future__ import annotations

import json
import re

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import make_verdict, error_verdict


_WELL_KNOWN_PATHS = (
    "/.well-known/agent.json",
    "/.well-known/a2a-card",
    "/.well-known/a2a/card",
    "/.well-known/agent-card",
    "/a2a/card",
    "/agent-card",
)

_LOCAL_URL_RE = re.compile(
    r"https?://(?:127\.|169\.254\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|localhost|metadata\.|kubernetes\.default)",
    re.IGNORECASE,
)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_a2a_agent_card(
        target_url: str,
        card_path: str = "",
        session: str = "",
        timeout: int = 15,
    ) -> dict:
        """Probe an A2A v1.0 agent card for security defects.

        Fetches the agent card from a well-known location, parses JSON,
        audits 6 risk classes. CONFIRMED on high-risk combinations.

        Args:
            target_url: target base URL (scheme + host[:port]).
            card_path: optional explicit card path (skips well-known
                discovery). When empty, tries 6 canonical paths.
            session: optional session name.
            timeout: per-fetch timeout (s).

        Returns: VerdictResult.
        """
        if not target_url:
            return error_verdict("target_url required", vuln_type="a2a_agent_card")

        base = target_url.rstrip("/")
        paths = [card_path] if card_path else list(_WELL_KNOWN_PATHS)

        card_found: dict | None = None
        card_path_found: str = ""
        logger_indices: list[int] = []
        reproductions: list[dict] = []

        for p in paths:
            url = f"{base}{p}"
            resp = await _send(url, session, timeout)
            li = resp.get("logger_index", -1)
            if isinstance(li, int) and li >= 0:
                logger_indices.append(li)
            status = resp.get("status_code") or resp.get("status")
            body = resp.get("response_body") or ""
            reproductions.append({
                "path": p, "status_code": status, "logger_index": li,
            })
            if status == 200 and body:
                try:
                    obj = json.loads(body)
                    if isinstance(obj, dict) and _looks_like_card(obj):
                        card_found = obj
                        card_path_found = p
                        break
                except json.JSONDecodeError:
                    continue

        if not card_found:
            return make_verdict(
                "FAILED", 0.10,
                f"No A2A agent card found across {len(paths)} well-known path(s). "
                f"Target likely doesn't expose A2A v1.0.",
                vuln_type="a2a_agent_card",
                logger_indices=logger_indices,
                reproductions=reproductions,
                summary=f"FAILED — no A2A card on {base}",
            )

        defects = _audit_card(card_found)
        crit = [d for d in defects if d["severity"] == "critical"]
        high = [d for d in defects if d["severity"] == "high"]

        if crit:
            return make_verdict(
                "CONFIRMED", 0.88,
                f"A2A agent card has critical defects — "
                f"{len(crit)} critical, {len(high)} high. "
                f"First: {crit[0]['category']} ({crit[0]['detail']}).",
                vuln_type="a2a_agent_card",
                logger_indices=logger_indices,
                reproductions=reproductions,
                details={
                    "card_path": card_path_found,
                    "card_excerpt": _card_excerpt(card_found),
                    "defects": defects,
                },
                summary=f"CONFIRMED A2A agent-card defects on {base}{card_path_found}",
            )

        if high:
            return make_verdict(
                "SUSPECTED", 0.60,
                f"A2A agent card has high-risk defects ({len(high)}). "
                "Manual chain review recommended.",
                vuln_type="a2a_agent_card",
                logger_indices=logger_indices,
                reproductions=reproductions,
                details={"card_path": card_path_found,
                         "defects": defects,
                         "card_excerpt": _card_excerpt(card_found)},
                summary=f"SUSPECTED A2A card weaknesses on {base}{card_path_found}",
            )

        return make_verdict(
            "FAILED", 0.20,
            f"A2A agent card found at {card_path_found} but no high-severity "
            "defects in audited fields.",
            vuln_type="a2a_agent_card",
            logger_indices=logger_indices,
            reproductions=reproductions,
            details={"card_path": card_path_found,
                     "defects": defects,
                     "card_excerpt": _card_excerpt(card_found)},
            summary=f"FAILED — A2A card on {base}{card_path_found} looks tight",
        )


# ----- Helpers --------------------------------------------------------------


def _looks_like_card(obj: dict) -> bool:
    """Heuristic: an A2A card carries at least one of these keys."""
    keys = set(k.lower() for k in obj.keys())
    expected = {"agent_id", "agentid", "name", "capabilities", "tools",
                "delegation", "endpoints", "version", "signature"}
    return len(keys & expected) >= 2


def _audit_card(card: dict) -> list[dict]:
    """Walk a card and emit risk findings."""
    defects: list[dict] = []

    # Defect 1: missing signature
    sig = card.get("signature") or card.get("sig") or card.get("jws")
    if not sig:
        defects.append({
            "severity": "high",
            "category": "missing_signature",
            "detail": "card has no `signature` / `jws` field — anyone can forge",
        })

    # Defect 2: capability over-claim
    caps = card.get("capabilities") or card.get("scopes") or []
    if isinstance(caps, dict):
        caps = list(caps.keys())
    if isinstance(caps, list):
        flat = [str(c).lower() for c in caps]
        if "*" in flat or "any" in flat or "any:any" in flat or "all" in flat:
            defects.append({
                "severity": "critical",
                "category": "capability_overclaim",
                "detail": f"card declares wildcard/any capability: {flat[:5]}",
            })

    # Defect 3: recursive delegation without max_depth
    deleg = card.get("delegation") or {}
    if isinstance(deleg, dict):
        recursive = deleg.get("recursive") or deleg.get("allow_recursive")
        max_depth = deleg.get("max_depth") or deleg.get("depth_limit")
        if recursive and not max_depth:
            defects.append({
                "severity": "critical",
                "category": "recursive_delegation_unbounded",
                "detail": "delegation.recursive=true with no max_depth — "
                          "DoS / fan-out abuse primitive",
            })
        elif recursive and isinstance(max_depth, int) and max_depth > 10:
            defects.append({
                "severity": "high",
                "category": "recursive_delegation_deep",
                "detail": f"delegation.max_depth={max_depth} (unusually deep)",
            })

    # Defect 4: missing caller allowlist
    callers = (card.get("accepted_callers") or card.get("allowed_peers")
               or card.get("allowed_callers"))
    if callers is None or callers == [] or callers == "*":
        defects.append({
            "severity": "high",
            "category": "missing_caller_allowlist",
            "detail": "no accepted_callers / allowed_peers list — world-callable",
        })

    # Defect 5: URLs pointing to local / metadata IPs
    for k, v in _walk_strings(card):
        if isinstance(v, str) and _LOCAL_URL_RE.match(v):
            defects.append({
                "severity": "critical",
                "category": "internal_url_in_card",
                "detail": f"`{k}` references internal URL `{v}` — SSRF chain",
            })

    # Defect 6: version field missing / suspicious
    ver = card.get("version") or card.get("schema_version")
    if not ver:
        defects.append({
            "severity": "high",
            "category": "missing_version",
            "detail": "no `version` field — peers cannot validate compatibility "
                      "or detect downgrade",
        })

    # Defect 7: tools list with unsafe descriptors
    tools = card.get("tools") or []
    if isinstance(tools, list):
        for t in tools:
            if not isinstance(t, dict):
                continue
            tname = t.get("name", "")
            tdesc = (t.get("description") or "").lower()
            risky = ("execute", "run shell", "ignore prior", "system",
                     "credential", "private key")
            if any(r in tdesc for r in risky):
                defects.append({
                    "severity": "high",
                    "category": "risky_tool_description",
                    "detail": f"tool `{tname}` description contains risky terms",
                })

    return defects


def _walk_strings(obj, prefix: str = ""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            yield from _walk_strings(v, path)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:30]):
            yield from _walk_strings(v, f"{prefix}.{i}")
    elif isinstance(obj, str):
        yield (prefix, obj)


def _card_excerpt(card: dict) -> dict:
    return {
        "name": card.get("name", ""),
        "version": card.get("version", ""),
        "capabilities": str(card.get("capabilities", ""))[:200],
        "delegation": str(card.get("delegation", ""))[:200],
        "tools_count": len(card.get("tools") or []),
    }


async def _send(url: str, session: str, timeout: int) -> dict:
    headers = [{"name": "Accept", "value": "application/json"}]
    if session:
        return await client.post("/api/session/request", json={
            "session": session, "method": "GET", "url": url, "headers": headers,
        })
    return await client.post("/api/http/curl", json={
        "url": url, "method": "GET", "headers": headers, "timeout": timeout,
    })
