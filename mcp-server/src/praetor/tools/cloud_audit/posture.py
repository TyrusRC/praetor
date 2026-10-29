"""Read-only multi-cloud config-posture audit CLIs: prowler, ScoutSuite, CloudSploit.

All three read provider state and report misconfigurations; none mutate the account.
"""

from __future__ import annotations

import csv
import json
import os
import tempfile

from mcp.server.fastmcp import FastMCP

import praetor.tools.cloud_audit as _c  # resolve _check_tool / _run_cmd / _hint at call time


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_prowler(
        provider: str = "aws",
        checks: str = "",
        severity: str = "high,critical",
        timeout: int = 1200,
    ) -> str:
        """Run prowler multi-cloud config audit (AWS/Azure/GCP/Kubernetes).

        Args:
            provider: aws | azure | gcp | kubernetes.
            checks: comma list of check IDs (empty = all).
            severity: comma list (low,medium,high,critical).
            timeout: seconds.
        """
        if not _c._check_tool("prowler"):
            return _c._hint("prowler",
                            "pipx install prowler  |  https://github.com/prowler-cloud/prowler")
        if provider not in {"aws", "azure", "gcp", "kubernetes"}:
            return f"Error: provider must be aws|azure|gcp|kubernetes (got {provider!r})."
        cmd = ["prowler", provider, "--output-formats", "json-ocsf",
               "--severity", severity, "--no-banner"]
        if checks:
            cmd += ["--checks", checks]
        out, err, rc = await _c._run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        rows: list[dict] = []
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            status = d.get("status_code") or d.get("Status") or ""
            if str(status).upper() in {"PASS", "MANUAL"}:
                continue
            rows.append({
                "id": d.get("event_code") or d.get("CheckID") or "?",
                "sev": d.get("severity") or d.get("Severity") or "?",
                "service": d.get("service_name") or d.get("ServiceName") or "?",
                "title": (d.get("finding_info", {}) or {}).get("title")
                         or d.get("CheckTitle") or "",
                "resource": (d.get("resources", [{}])[0]
                             if d.get("resources") else {}).get("name", ""),
            })
        lines = [f"prowler [{provider}]: {len(rows)} failed checks (severity={severity})"]
        for r in rows[:50]:
            lines.append(f"  [{r['sev']:<8}] {r['id']}  {r['service']}  {r['title'][:80]}"
                         + (f"  ({r['resource']})" if r['resource'] else ""))
        if rc != 0 and not rows:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_scout_suite(provider: str = "aws", timeout: int = 1800) -> str:
        """Run ScoutSuite cloud config audit. Read-only. Writes HTML+JSON report.

        Args:
            provider: aws | azure | gcp | aliyun | oci.
            timeout: seconds.
        """
        if not _c._check_tool("scout"):
            return _c._hint("scout",
                            "pipx install scoutsuite  |  https://github.com/nccgroup/ScoutSuite")
        if provider not in {"aws", "azure", "gcp", "aliyun", "oci"}:
            return f"Error: provider must be aws|azure|gcp|aliyun|oci (got {provider!r})."
        cmd = ["scout", provider, "--no-browser", "--force"]
        out, err, rc = await _c._run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        tail = "\n".join(out.splitlines()[-30:])
        lines = [f"scoutsuite [{provider}] rc={rc}", tail]
        if rc != 0:
            lines.append(f"[stderr] {err[:200]}")
        lines.append("Report written to scoutsuite-report/ (open scoutsuite-report.html).")
        return "\n".join(lines)

    @mcp.tool()
    async def run_cloudsploit(
        config_path: str = "",
        cloud: str = "aws",
        timeout: int = 1200,
    ) -> str:
        """Run CloudSploit (Aqua) AWS/Azure/GCP/Oracle audit.

        Args:
            config_path: path to cloudsploit config.js (provider creds + opts).
                The provider (aws/azure/gcp/oracle) is selected by this config,
                not by a flag.
            cloud: label for the report header only; CloudSploit infers the
                provider from the config/credentials, it has no --cloud flag.
            timeout: seconds.
        """
        # npm ships the binary as `cloudsploitscan`; some installs symlink it to
        # `cloudsploit`. Accept whichever is on PATH.
        cs_bin = next((b for b in ("cloudsploit", "cloudsploitscan") if _c._check_tool(b)), None)
        if cs_bin is None:
            return _c._hint("cloudsploit",
                            "npm i -g cloudsploit  |  https://github.com/aquasecurity/cloudsploit")
        # This CloudSploit has no JSON output; CSV to a file is the only machine
        # -readable format (console output is human text). Columns:
        # category, title, resource, region, statusWord, message.
        fd, csv_path = tempfile.mkstemp(suffix=".csv", prefix="cloudsploit-")
        os.close(fd)
        try:
            cmd = [cs_bin, "--console=none", f"--csv={csv_path}"]
            if config_path:
                cmd.append(f"--config={config_path}")
            out, err, rc = await _c._run_cmd(cmd, timeout=timeout, bypass_proxy=True)
            rows: list[dict] = []
            try:
                with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
                    for rec in csv.reader(fh):
                        if len(rec) < 6:
                            continue
                        category, title, resource, region, status, _message = rec[:6]
                        if status.upper() not in {"WARN", "FAIL", "UNKNOWN"}:
                            continue  # skip OK results and any header row
                        rows.append({
                            "sev": status.upper(),
                            "title": (f"{category}: {title}".strip(": "))[:80],
                            "region": region or "Global",
                            "resource": resource or "N/A",
                        })
            except OSError:
                pass
        finally:
            try:
                os.unlink(csv_path)
            except OSError:
                pass
        rows.sort(key=lambda r: {"FAIL": 0, "WARN": 1, "UNKNOWN": 2}.get(r["sev"], 3))
        lines = [f"cloudsploit [{cloud}]: {len(rows)} non-pass findings"]
        for r in rows[:50]:
            lines.append(f"  [{r['sev']:<7}] {r['title']}  ({r['region']})  {r['resource']}")
        if len(rows) > 50:
            lines.append(f"  … {len(rows) - 50} more")
        if rc != 0 and not rows:
            lines.append(f"[rc={rc}] {(err or out)[:200]}")
        return "\n".join(lines)
