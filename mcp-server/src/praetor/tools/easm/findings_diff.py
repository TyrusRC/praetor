"""findings_diff — scan-vs-scan delta over findings.json snapshots. Helpers in _diff_helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor.tools.notes._helpers import _load_findings_file, _safe_findings_path

from ._diff_helpers import (  # noqa: F401
    _snapshot_dir, _archive_current, _list_snapshots, _findings_list,
    _index_by_dedup_key, _load_endpoints, _ep_path, _ep_params, _norm_path, _path_matches,
)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def findings_diff(
        domain: str,
        baseline: str = "",
        current: str = "",
        archive_now: bool = True,
    ) -> str:
        """Emit new / resolved / persisting delta between two findings snapshots.

        Args:
            domain: target domain (slug).
            baseline: ISO snapshot timestamp (or 'previous' for second-most-recent).
                Defaults to second-most-recent.
            current: ISO snapshot timestamp (or 'live' for live findings.json).
                Defaults to live.
            archive_now: archive live findings.json into _snapshots/ first
                (so 'live' becomes a permanent snapshot). Default True.
        """
        if archive_now:
            _archive_current(domain)

        snaps = _list_snapshots(domain)
        if not snaps and current != "live":
            return f"No snapshots in .burp-intel/{domain}/_snapshots/."

        def _resolve(key: str, default_idx: int) -> tuple[str, list[dict]]:
            if key in ("live", "", "current"):
                p = _safe_findings_path(domain)
                if not p.exists():
                    return ("live(empty)", [])
                return ("live", _findings_list(_load_findings_file(p)))
            if key == "previous":
                if len(snaps) < 2:
                    return ("previous(unavailable)", [])
                p = snaps[-2]
                return (p.stem.replace("findings-", ""), _findings_list(_load_findings_file(p)))
            for p in snaps:
                if key in p.name:
                    return (p.stem.replace("findings-", ""), _findings_list(_load_findings_file(p)))
            if 0 <= default_idx < len(snaps):
                p = snaps[default_idx]
                return (p.stem.replace("findings-", ""), _findings_list(_load_findings_file(p)))
            return (f"{key}(missing)", [])

        base_label, base_list = _resolve(baseline or "previous", default_idx=-2 if len(snaps) >= 2 else 0)
        cur_label, cur_list = _resolve(current or "live", default_idx=-1)

        base_idx = _index_by_dedup_key(base_list)
        cur_idx = _index_by_dedup_key(cur_list)

        new = [cur_idx[k] for k in cur_idx if k not in base_idx]
        resolved = [base_idx[k] for k in base_idx if k not in cur_idx]
        persisting = [cur_idx[k] for k in cur_idx if k in base_idx]

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        new.sort(key=lambda f: sev_order.get((f.get("severity") or "INFO").upper(), 9))
        resolved.sort(key=lambda f: sev_order.get((f.get("severity") or "INFO").upper(), 9))

        lines = [
            f"# findings_diff — {domain}",
            f"Baseline: {base_label}  ({len(base_list)} findings)",
            f"Current:  {cur_label}   ({len(cur_list)} findings)",
            "",
            f"NEW (regressions): {len(new)}",
        ]
        for f in new[:25]:
            lines.append(
                f"  + [{(f.get('severity') or 'INFO').upper():<8}] {f.get('vuln_type','?')} "
                f"@ {f.get('endpoint','')}  ({f.get('id','')})"
            )
        lines.append("")
        lines.append(f"RESOLVED: {len(resolved)}")
        for f in resolved[:25]:
            lines.append(
                f"  - [{(f.get('severity') or 'INFO').upper():<8}] {f.get('vuln_type','?')} "
                f"@ {f.get('endpoint','')}  ({f.get('id','')})"
            )
        lines.append("")
        lines.append(f"PERSISTING: {len(persisting)}")
        return "\n".join(lines)

    @mcp.tool()
    async def scope_targets_to_diff(
        domain: str,
        changed_paths: list[str],
        include_unmatched: bool = True,
    ) -> dict:
        """Intersect PR/git-diff changed paths with discovered endpoints → a
        fire-ready (endpoint, parameter) target list for auto_probe. A CI run
        probes only what the diff touched instead of a full re-crawl.

        Args:
            domain: target domain (slug) — reads .burp-intel/<domain>/endpoints.json.
            changed_paths: URL paths/params touched by the diff. Each entry may be
                a path ('/api/users'), a glob ('/api/users/*', '/api/*/settings'),
                a segment prefix ('/api/'), or a path+param
                ('/api/users?id' or '/api/users?id=1') to scope to specific params.
            include_unmatched: also report changed paths that hit no known endpoint.

        Returns:
            {matched_targets: [{endpoint, method, parameter, changed_path}, ...],
             unmatched_changed: [...], note: str}
        """
        if not changed_paths:
            return {"matched_targets": [], "unmatched_changed": [], "note": "changed_paths empty"}

        eps, ep_path_file = _load_endpoints(domain)
        if not eps:
            return {
                "matched_targets": [],
                "unmatched_changed": list(changed_paths),
                "note": (
                    f"no endpoints.json at {ep_path_file} — run discover_attack_surface "
                    "+ save_target_intel(category='endpoints') first"
                ),
            }

        matched: list[dict] = []
        seen: set = set()
        unmatched: list[str] = []

        for raw in changed_paths:
            entry = (raw or "").strip()
            if not entry:
                continue

            # split off a param spec: ?a=1&b=2  or  #fragment  or a full URL query
            param_filter: set[str] = set()
            core = entry
            if "://" in core:
                parsed = urlparse(core)
                core = parsed.path or "/"
                if parsed.query:
                    param_filter |= {kv.split("=", 1)[0] for kv in parsed.query.split("&") if kv}
            elif "?" in core:
                core, q = core.split("?", 1)
                param_filter |= {kv.split("=", 1)[0] for kv in q.split("&") if kv}
            elif "#" in core:
                core, frag = core.split("#", 1)
                if frag:
                    param_filter.add(frag)
            pattern = core.strip() or "/"

            hit = False
            for ep in eps:
                ep_path = _norm_path(_ep_path(ep))
                if not _path_matches(pattern, ep_path):
                    continue
                hit = True
                method = (ep.get("method") or "GET").upper()
                all_params = _ep_params(ep)
                if param_filter:
                    use = [p for p in all_params if p in param_filter]
                    # param named in the diff but not (yet) known on this endpoint —
                    # still surface it so CI probes the changed input
                    if not use:
                        use = sorted(param_filter)
                else:
                    use = all_params

                if not use:
                    key = (ep_path, method, "")
                    if key not in seen:
                        seen.add(key)
                        matched.append({
                            "endpoint": _ep_path(ep), "method": method,
                            "parameter": None, "changed_path": entry,
                        })
                    continue

                for pname in use:
                    key = (ep_path, method, pname)
                    if key not in seen:
                        seen.add(key)
                        matched.append({
                            "endpoint": _ep_path(ep), "method": method,
                            "parameter": pname, "changed_path": entry,
                        })

            if not hit:
                unmatched.append(entry)

        out = {
            "matched_targets": matched,
            "note": (
                f"{len(matched)} (endpoint, param) targets from {len(changed_paths)} "
                f"changed paths vs {len(eps)} known endpoints"
            ),
        }
        out["unmatched_changed"] = unmatched if include_unmatched else []
        return out

    @mcp.tool()
    async def list_findings_snapshots(domain: str) -> str:
        """List archived findings snapshots for a domain."""
        snaps = _list_snapshots(domain)
        if not snaps:
            return f"No snapshots in .burp-intel/{domain}/_snapshots/."
        lines = [f"Snapshots for {domain}:"]
        for p in snaps:
            data = _findings_list(_load_findings_file(p))
            ts = p.stem.replace("findings-", "")
            lines.append(f"  {ts}  ({len(data)} findings)")
        return "\n".join(lines)

    @mcp.tool()
    async def archive_findings_snapshot(domain: str) -> str:
        """Archive current findings.json into _snapshots/findings-<iso>.json."""
        p = _archive_current(domain)
        if p is None:
            return f"No findings.json in .burp-intel/{domain}/ to archive."
        return f"Archived: {p}"
