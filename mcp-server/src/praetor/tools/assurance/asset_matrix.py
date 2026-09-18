"""asset_role_matrix — auto asset/feature map + role x feature authorization matrix.

Two artefacts the operator asked to be generated automatically:

- **Feature/asset map** — endpoints grouped into features (resource groups), with
  the methods each exposes and whether any are state-changing. This is the "what
  does the app expose" inventory that focuses authz/logic testing.
- **Role x feature matrix** — every role (from business_context.user_roles) against
  every feature. Each cell is the authorization test-plan state: `allow` / `deny`
  once an access test observed it, else `untested`. Untested cells are the Rule 29
  authorization plan (IDOR/BFLA is the highest-value class), NOT a silent N/A.

Pure cores (`build_feature_map`, `build_role_matrix`, `render_asset_role_matrix`)
take already-loaded data for cheap testing; `asset_role_matrix` does the disk I/O.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from ..report.lifecycle import load_intel

_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


def _path_of(url: str) -> str:
    if "://" in url:
        try:
            return urlparse(url).path or "/"
        except ValueError:
            return url
    return url or "/"


def _looks_like_id(seg: str) -> bool:
    """A path segment that is an object id, not a feature name."""
    if seg.isdigit():
        return True
    if len(seg) >= 16 and any(c.isdigit() for c in seg):  # uuid / hash-ish
        return True
    return False


def _feature_of(url: str) -> str:
    """First non-id path segment = the feature/resource group."""
    segs = [s for s in _path_of(url).split("/") if s and not _looks_like_id(s)]
    if not segs:
        return "(root)"
    # /api/<resource>/... -> use the resource, not the "api" prefix
    if segs[0] in ("api", "v1", "v2", "rest") and len(segs) > 1:
        return f"{segs[0]}/{segs[1]}"
    return segs[0]


def build_feature_map(endpoints: list[dict]) -> dict[str, dict[str, Any]]:
    """Group endpoints into features. Pure.

    Each feature: {endpoints, methods[], state_changing(bool), sample_paths[]}.
    """
    feats: dict[str, dict[str, Any]] = {}
    for ep in endpoints:
        url = ep.get("url") or ep.get("endpoint") or ep.get("path") or ""
        if not url:
            continue
        feat = _feature_of(url)
        row = feats.setdefault(
            feat, {"endpoints": 0, "_methods": set(), "_paths": set()})
        row["endpoints"] += 1
        row["_methods"].add((ep.get("method") or "GET").upper())
        row["_paths"].add(_path_of(url))
    out: dict[str, dict[str, Any]] = {}
    for feat, row in sorted(feats.items()):
        methods = sorted(row["_methods"])
        out[feat] = {
            "endpoints": row["endpoints"],
            "methods": methods,
            "state_changing": any(m in _STATE_CHANGING for m in methods),
            "sample_paths": sorted(row["_paths"])[:8],
        }
    return out


def build_role_matrix(
    roles: list[str],
    features: list[str],
    observed: dict[tuple[str, str], str] | None = None,
) -> dict[str, dict[str, str]]:
    """role -> {feature -> allow|deny|untested}. Pure.

    `observed` maps (role, feature) -> "allow"/"deny" from an access test
    (e.g. test_auth_matrix); every unobserved cell is "untested" — the authz
    plan to run, never assumed.
    """
    obs = observed or {}
    matrix: dict[str, dict[str, str]] = {}
    for role in roles:
        matrix[role] = {feat: obs.get((role, feat), "untested") for feat in features}
    return matrix


_CELL = {"allow": "A", "deny": "D", "untested": "·"}


def render_asset_role_matrix(
    domain: str,
    feature_map: dict[str, dict[str, Any]],
    role_matrix: dict[str, dict[str, str]],
) -> str:
    """Readable feature map + role x feature grid. Pure."""
    lines = [f"# Asset / feature map + role matrix — {domain}", ""]
    if not feature_map:
        lines.append("No endpoints recorded yet — run recon first "
                     "(browser_crawl -> discover_attack_surface).")
        return "\n".join(lines)

    lines.append(f"## Features ({len(feature_map)})")
    for feat, r in feature_map.items():
        flag = " [state-changing]" if r["state_changing"] else ""
        lines.append(f"  {feat}  — {r['endpoints']} endpoint(s), "
                     f"{', '.join(r['methods'])}{flag}")
    lines.append("")

    roles = list(role_matrix.keys())
    if not roles:
        lines.append("No roles known — set business_context.user_roles to build the "
                     "role x feature authorization matrix (Rule 29: authz is the "
                     "highest-value class).")
        return "\n".join(lines)

    feats = list(feature_map.keys())
    lines.append(f"## Role x feature authorization matrix  (A=allow D=deny ·=UNTESTED)")
    header = "  role \\ feature   " + " ".join(f[:6].rjust(6) for f in feats)
    lines.append(header)
    todo = 0
    for role in roles:
        cells = []
        for feat in feats:
            state = role_matrix[role].get(feat, "untested")
            if state == "untested":
                todo += 1
            cells.append(_CELL.get(state, "?").rjust(6))
        lines.append(f"  {role[:16].ljust(16)} " + " ".join(cells))
    lines.append("")
    lines.append(f"UNTESTED authz cells: {todo} of {len(roles) * len(feats)} "
                 f"— test each (role x feature) for access; untested is a gap, not N/A "
                 f"(Rules 19a / 29). Prioritise state-changing features.")
    return "\n".join(lines)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def asset_role_matrix(domain: str) -> str:
        """Auto-build the asset/feature map + role x feature authorization matrix.

        Groups recorded endpoints into features and crosses every business-context
        role against every feature, so the operator sees the app's attack surface
        and the authorization test plan (which role x feature cells are still
        UNTESTED) in one view. Surface this after recon and before authz testing.

        Args:
            domain: target in .burp-intel/<domain>/.
        """
        endpoints = load_intel(domain, "endpoints").get("endpoints", []) or []
        feature_map = build_feature_map(endpoints)
        bc = load_intel(domain, "business_context")
        roles = bc.get("user_roles") or bc.get("business_context", {}).get("user_roles") or []
        role_matrix = build_role_matrix(roles, list(feature_map.keys()))
        return render_asset_role_matrix(domain, feature_map, role_matrix)
