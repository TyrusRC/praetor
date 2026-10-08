"""import_scan_results / merge_scan — consolidate external + Burp scanner output.

Turns Praetor into a consolidation hub (PlexTrac/Dradis-style): parse a scanner
export (or run assay and pull Burp Pro's live findings), normalize to Praetor
finding dicts, and merge into findings.json with the SAME dedup key the native
pipeline uses (_dedupe_finding: endpoint+vuln_type+title+parameter).

Imported findings enter as status='suspected' with a `source` tag — they are
leads from a scanner, not Praetor-verified, so the true-positives-only report
rule (Rule 16) still holds until they pass verify/assess.

Format parsers live in _parsers.py; the merge/store logic in _store.py. Both are
re-exported here so callers and tests keep importing them from this module.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from praetor import client

from ..recon._common import BURP_PROXY_URL, _check_tool, _run_cmd
from ._parsers import (  # noqa: F401  (re-exported for callers/tests)
    _PARSERS,
    _REAL_SEV,
    _detect_format,
    _finding,
    _slug_to_vuln_type,
    parse_assay,
    parse_burp_xml,
    parse_nessus,
    parse_nuclei,
    parse_openvas,
    parse_sarif,
    parse_zap,
)
from ._store import (  # noqa: F401  (re-exported for callers/tests)
    _apply_rows,
    _burp_rows,
    merge_imported,
)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def import_scan_results(
        source: str, domain: str, fmt: str = "auto"
    ) -> dict:
        """Import a scanner export into a domain's findings (dedup-merged).

        Supported fmt: assay (JSON), nuclei (JSONL), nessus (.nessus XML),
        sarif (JSON), burp (issues XML), openvas (GVM XML), zap (JSON), or 'auto'.
        Imported findings enter as status='suspected' with a `source` tag —
        verify before reporting. Returns {parsed, created, updated, by_severity}.
        """
        p = Path(source)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return {"error": f"cannot read '{source}': {e}"}

        chosen = fmt if fmt != "auto" else _detect_format(source, text)
        parser = _PARSERS.get(chosen)
        if parser is None:
            return {"error": f"unsupported format '{chosen or fmt}'", "valid": sorted(_PARSERS)}

        try:
            rows = parser(text)
        except Exception as e:  # defusedxml raises on XXE; surface, don't crash
            return {"error": f"parse failed ({type(e).__name__}): {e}"}

        result = _apply_rows(domain, rows)
        result["source_format"] = chosen
        return result

    @mcp.tool()
    async def merge_scan(
        domain: str,
        target: str = "",
        profile: str = "normal",
        include_burp: bool = True,
        use_proxy: bool = True,
        timeout: int = 600,
    ) -> dict:
        """Run assay AND pull Burp Pro's scanner findings into ONE deduped stream.

        Both engines normalize to the same finding shape and merge by the native
        key (endpoint + vuln_type + title + parameter) into
        .burp-intel/<domain>/findings.json as status='suspected'. This is the
        combined web-scan: assay's context-aware detectors + Burp Pro's active
        scanner, deduplicated so the same bug from both engines is one finding.
        Verify before reporting.

        Args:
            domain: Target workspace under .burp-intel/
            target: URL to scan with assay (omit to merge Burp findings only)
            profile: assay profile — quick | normal | thorough | passive
            include_burp: Also pull Burp Pro /api/scanner/findings (default True)
            use_proxy: Route assay through Burp proxy (default True)
            timeout: assay max seconds (default 600)
        """
        rows: list[dict] = []
        sources: dict = {}

        if target:
            if not _check_tool("assay"):
                return {"error": "assay not installed. Build: go build -o ~/go/bin/assay ./cmd/assay"}
            cmd = ["assay", "scan", target, "--json", "--profile", profile,
                   "--timeout", f"{timeout}s"]
            if use_proxy:
                cmd.extend(["--proxy", BURP_PROXY_URL, "-k"])
            stdout, stderr, code = await _run_cmd(cmd, timeout + 30, bypass_proxy=not use_proxy)
            if stdout.strip():
                arows = parse_assay(stdout)
                rows.extend(arows)
                sources["assay"] = len(arows)
            else:
                sources["assay_error"] = (stderr or f"exit {code}")[:200]

        if include_burp:
            params = {"limit": 500}
            if target:
                host = urlparse(target).hostname
                if host:
                    params["host"] = host  # narrow Burp's project-wide findings
            data = await client.get("/api/scanner/findings", params=params)
            if isinstance(data, dict) and "error" not in data:
                brows = _burp_rows(data.get("items", []))
                rows.extend(brows)
                sources["burp"] = len(brows)
            elif isinstance(data, dict):
                sources["burp_error"] = str(data.get("error"))[:200]

        if not rows:
            return {"merged": 0, "sources": sources,
                    "note": "no findings from either engine"}

        result = _apply_rows(domain, rows)
        result["sources"] = sources
        return result
