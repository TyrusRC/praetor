"""test_journal — structured test-execution log for full traceability.

Answers: "for endpoint X, parameter Y, what did we test and what was the result?"
Merges coverage.json (tested tuples + verdicts), findings.json (confirmed findings),
and test_journal.jsonl (per-test structured log) into a single view.

This is the operator's proof that every testcase ran and nothing was missed.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ._internals import _intel_path


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def test_journal(
        domain: str,
        endpoint: str = "",
        vuln_class: str = "",
        verdict_filter: str = "",
        limit: int = 100,
    ) -> str:
        """Structured test-execution log — every test run with its result.

        Shows exactly which (endpoint, parameter, vuln_class) tuples were
        tested, by which tool, with what verdict, and when. The single view
        for "did we test X on Y, and what happened?"

        Args:
            domain: Target domain.
            endpoint: Filter to a specific endpoint (substring match).
            vuln_class: Filter to a specific vuln class.
            verdict_filter: Filter by verdict (CONFIRMED/FAILED/all).
            limit: Max entries to return (default 100, newest first).
        """
        base = _intel_path(domain)
        journal_path = base / "test_journal.jsonl"
        cov_path = base / "coverage.json"
        findings_path = base / "findings.json"

        entries: list[dict] = []

        # 1. Read test_journal.jsonl (structured per-test log)
        if journal_path.exists():
            try:
                for line in journal_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
            except OSError:
                pass

        # 2. Supplement with coverage.json entries that have no journal entry
        #    (from auto_probe which writes coverage but not journal)
        journal_keys: set[tuple] = set()
        for e in entries:
            journal_keys.add((
                e.get("endpoint", ""),
                e.get("parameter", ""),
                e.get("vuln_class", ""),
            ))

        if cov_path.exists():
            try:
                cov = json.loads(cov_path.read_text(encoding="utf-8"))
                for ce in cov.get("entries", []):
                    key = (ce.get("endpoint", ""), ce.get("parameter", ""), ce.get("category", ""))
                    if key not in journal_keys:
                        entries.append({
                            "ts": ce.get("tested_at", ""),
                            "endpoint": ce.get("endpoint", ""),
                            "parameter": ce.get("parameter", ""),
                            "vuln_class": ce.get("category", ""),
                            "verdict": ce.get("verdict", "covered"),
                            "tool": ce.get("source", "auto_probe"),
                            "proxy_index": None,
                        })
            except (OSError, json.JSONDecodeError):
                pass

        # 3. Mark entries that produced findings
        finding_keys: set[tuple] = set()
        if findings_path.exists():
            try:
                fdata = json.loads(findings_path.read_text(encoding="utf-8"))
                for f in fdata if isinstance(fdata, list) else fdata.get("findings", []):
                    ep = f.get("endpoint", "")
                    vt = f.get("vuln_type", "")
                    param = f.get("parameter", "")
                    finding_keys.add((ep, param, vt))
            except (OSError, json.JSONDecodeError):
                pass

        for e in entries:
            key = (e.get("endpoint", ""), e.get("parameter", ""), e.get("vuln_class", ""))
            if key in finding_keys:
                e["has_finding"] = True

        # 4. Apply filters
        if endpoint:
            entries = [e for e in entries if endpoint in e.get("endpoint", "")]
        if vuln_class:
            vc = vuln_class.lower()
            entries = [e for e in entries if vc in e.get("vuln_class", "").lower()]
        if verdict_filter:
            vf = verdict_filter.upper()
            entries = [e for e in entries if vf in (e.get("verdict", "").upper())]

        # 5. Sort newest first, apply limit
        entries.sort(key=lambda x: x.get("ts", ""), reverse=True)
        entries = entries[:limit]

        if not entries:
            return f"No test journal entries for {domain}" + (
                f" matching endpoint={endpoint!r}" if endpoint else ""
            ) + (f" class={vuln_class}" if vuln_class else "") + "."

        # 6. Render
        lines = [f"# Test Journal — {domain}"]
        lines.append(f"{len(entries)} entries" + (
            f" (filtered: endpoint={endpoint!r})" if endpoint else ""
        ) + (f" (class={vuln_class})" if vuln_class else ""))
        lines.append("")
        lines.append(f"{'Timestamp':<24} {'Verdict':<12} {'Vuln Class':<24} {'Endpoint':<50} {'Param':<15} {'Tool':<25} {'Idx':>5} {'Finding':>7}")
        lines.append("-" * 165)
        for e in entries:
            ts = (e.get("ts") or "")[:19]
            verdict = e.get("verdict", "?")[:11]
            vc = e.get("vuln_class", "")[:23]
            ep = e.get("endpoint", "")[:49]
            param = e.get("parameter", "")[:14]
            tool = e.get("tool", "")[:24]
            idx = str(e.get("proxy_index", "")) if e.get("proxy_index") else ""
            finding = "YES" if e.get("has_finding") else ""
            lines.append(f"{ts:<24} {verdict:<12} {vc:<24} {ep:<50} {param:<15} {tool:<25} {idx:>5} {finding:>7}")

        # 7. Gap summary
        tested_classes = set(e.get("vuln_class", "") for e in entries if e.get("endpoint"))
        all_endpoints = set(e.get("endpoint", "") for e in entries if e.get("endpoint"))
        lines.append("")
        lines.append(f"Tested {len(tested_classes)} vuln classes across {len(all_endpoints)} endpoints.")
        confirmed = sum(1 for e in entries if e.get("verdict", "").upper() == "CONFIRMED")
        failed = sum(1 for e in entries if e.get("verdict", "").upper() == "FAILED")
        other = len(entries) - confirmed - failed
        lines.append(f"Results: {confirmed} CONFIRMED, {failed} FAILED (clean), {other} other.")

        return "\n".join(lines)
