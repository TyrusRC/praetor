"""coverage_summary + next_untested_targets"""

import json
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from praetor.tools.workspace import ensure_workspace
from ._internals import (
    VALID_CATEGORIES,
    _atomic_write_json,
    _deduplicate_finding,
    _empty_structure,
    _ensure_dir,
    _intel_path,
    _knowledge_version,
    _utcnow_iso,
)


def register(mcp: FastMCP):
    @mcp.tool()
    async def coverage_summary(
        domain: str,
        vuln_classes: str = "",
    ) -> str:
        """Coverage gap dashboard — "N endpoints untested for SQLi" breakdown.

        Cross-references endpoints.json (discovered URLs+params) against
        coverage.json (tested tuples) and reports per-vuln-class gaps. The
        default vuln class list is the top 10 reportable web classes; pass
        a comma-separated list to narrow.

        Args:
            domain: Target domain
            vuln_classes: Comma-separated vuln classes to check. Empty = sqli,xss,
                ssrf,idor,ssti,command_injection,path_traversal,xxe,open_redirect,
                auth_bypass.
        """
        dir_path = _intel_path(domain)
        endpoints_path = dir_path / "endpoints.json"
        coverage_path = dir_path / "coverage.json"

        if not endpoints_path.exists():
            return (
                f"No endpoints recorded for {domain}. "
                "Run discover_attack_surface or full_recon first."
            )

        try:
            endpoints_data = json.loads(endpoints_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            return f"endpoints.json unreadable: {e}"

        endpoints = endpoints_data.get("endpoints", []) or []
        if not endpoints:
            return f"endpoints.json present but empty for {domain}."

        coverage_entries: list[dict] = []
        kv_recorded = None
        if coverage_path.exists():
            try:
                cov = json.loads(coverage_path.read_text(encoding="utf-8"))
                coverage_entries = cov.get("entries", []) or []
                kv_recorded = cov.get("knowledge_version")
            except (json.JSONDecodeError, OSError):
                pass

        if vuln_classes.strip():
            classes = [c.strip() for c in vuln_classes.split(",") if c.strip()]
        else:
            classes = [
                "sqli", "xss", "ssrf", "idor", "ssti",
                "command_injection", "path_traversal", "xxe",
                "open_redirect", "auth_bypass",
            ]

        # Build (endpoint, parameter) -> set(tested_classes)
        tested: dict[tuple[str, str], set[str]] = {}
        for e in coverage_entries:
            key = (e.get("endpoint", ""), e.get("parameter", ""))
            cls = e.get("vuln_class") or e.get("class") or ""
            if cls:
                tested.setdefault(key, set()).add(cls)

        # Enumerate (endpoint, parameter) tuples from endpoints.json
        tuples: list[tuple[str, str]] = []
        for ep in endpoints:
            url = ep.get("url") or ep.get("endpoint") or ""
            params = ep.get("parameters") or ep.get("params") or []
            if not params:
                tuples.append((url, ""))
                continue
            for p in params:
                pname = p if isinstance(p, str) else (p.get("name") or "")
                tuples.append((url, pname))

        total_tuples = len(tuples)
        lines = [
            f"Coverage summary for {domain}",
            f"  total (endpoint, param) tuples: {total_tuples}",
            f"  tuples with any test recorded: {len(tested)}",
        ]
        if kv_recorded is not None:
            current_kv = _knowledge_version()
            drift = " (DRIFT — re-run auto_probe(skip_already_covered=False))" if kv_recorded != current_kv else ""
            lines.append(f"  knowledge_version recorded: {kv_recorded} / current: {current_kv}{drift}")
        lines.append("")
        lines.append("Per-class untested counts:")
        for cls in classes:
            untested = sum(1 for key in tuples if cls not in tested.get(key, set()))
            pct = (1 - untested / total_tuples) * 100 if total_tuples else 0
            lines.append(f"  {cls:20} {untested:4} untested  ({pct:5.1f}% covered)")

        return "\n".join(lines)

    @mcp.tool()
    async def next_untested_targets(
        domain: str,
        vuln_classes: str = "",
        top_n: int = 10,
    ) -> str:
        """Rank the highest-value UNTESTED (endpoint, param, class) tuples as fire-ready next moves.

        Where coverage_summary reports per-class counts, this surfaces the
        specific tuples to hit next — ranked by parameter-name risk signal and
        by how many classes remain untested — each with a ready auto_probe call.
        Prevents rework and points the operator (or grow-agent) straight at the
        gaps. Reads the same endpoints.json / coverage.json as coverage_summary.

        Args:
            domain: Target domain
            vuln_classes: Comma-separated classes to consider (empty = default top-10 web classes)
            top_n: Max tuples to return (default 10)
        """
        dir_path = _intel_path(domain)
        endpoints_path = dir_path / "endpoints.json"
        coverage_path = dir_path / "coverage.json"
        if not endpoints_path.exists():
            return f"No endpoints recorded for {domain}. Run discover_attack_surface or full_recon first."
        try:
            endpoints = (json.loads(endpoints_path.read_text(encoding="utf-8")).get("endpoints", []) or [])
        except (json.JSONDecodeError, OSError) as e:
            return f"endpoints.json unreadable: {e}"
        if not endpoints:
            return f"endpoints.json present but empty for {domain}."

        tested: dict[tuple[str, str], set[str]] = {}
        if coverage_path.exists():
            try:
                for e in json.loads(coverage_path.read_text(encoding="utf-8")).get("entries", []) or []:
                    cls = e.get("vuln_class") or e.get("class") or ""
                    if cls:
                        tested.setdefault((e.get("endpoint", ""), e.get("parameter", "")), set()).add(cls)
            except (json.JSONDecodeError, OSError):
                pass

        if vuln_classes.strip():
            classes = [c.strip() for c in vuln_classes.split(",") if c.strip()]
        else:
            classes = ["sqli", "xss", "ssrf", "idor", "ssti",
                       "command_injection", "path_traversal", "xxe",
                       "open_redirect", "auth_bypass"]

        # Param-name → likely-class signal, reused from the scan risk map.
        from praetor.tools.scan._constants import _PARAM_RISK_MAP
        param_signals: dict[str, set[str]] = {}
        for risk_key, names in _PARAM_RISK_MAP.items():
            for n in names:
                param_signals.setdefault(n.lower(), set()).update(risk_key.split("_"))

        ranked = []
        for ep in endpoints:
            url = ep.get("url") or ep.get("endpoint") or ""
            params = ep.get("parameters") or ep.get("params") or [""]
            for p in params:
                pname = p if isinstance(p, str) else (p.get("name") or "")
                done = tested.get((url, pname), set())
                untested = [c for c in classes if c not in done]
                if not untested:
                    continue
                signals = param_signals.get(pname.lower(), set())
                # Score: param-name signal for an untested class is highest-value;
                # break ties by breadth of untested surface.
                signal_hit = sum(1 for c in untested if any(s in c for s in signals))
                score = signal_hit * 100 + len(untested)
                ranked.append((score, url, pname, untested, signal_hit))

        if not ranked:
            return f"All ({len(classes)}) classes covered for every known tuple on {domain}. Expand endpoints or classes."
        ranked.sort(key=lambda r: r[0], reverse=True)

        lines = [f"Next untested targets for {domain} (top {min(top_n, len(ranked))} of {len(ranked)}):", ""]
        for score, url, pname, untested, signal_hit in ranked[:top_n]:
            flag = " ⚑ param-name signal" if signal_hit else ""
            top_classes = untested[:3]
            lines.append(f"  {url}  param={pname or '(none)'}{flag}")
            lines.append(f"      untested: {', '.join(untested[:6])}{' …' if len(untested) > 6 else ''}")
            lines.append(f"      → auto_probe(session='hunt', domain='{domain}', "
                         f"targets=[{{'endpoint':'{url}','parameter':'{pname}'}}], categories={top_classes})")
        return "\n".join(lines)

