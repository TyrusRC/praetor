"""Multi-cloud config posture + AWS post-exploit wrappers.

- prowler / scout_suite / cloudsploit — read-only config audit (multi-cloud).
- pacu — AWS post-exploitation framework (Rhino Security Labs). Active. Run
  ONLY against accounts the operator owns / has authorization for. Rule 5
  destructive denylist enforced at tool layer.

All OSS (Apache-2.0 / MIT / BSD).
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd


def _hint(tool: str, hint: str) -> str:
    return f"Error: {tool} not installed.\nInstall: {hint}"


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
        if not _check_tool("prowler"):
            return _hint("prowler",
                         "pipx install prowler  |  https://github.com/prowler-cloud/prowler")
        if provider not in {"aws", "azure", "gcp", "kubernetes"}:
            return f"Error: provider must be aws|azure|gcp|kubernetes (got {provider!r})."
        cmd = ["prowler", provider, "--output-formats", "json-ocsf",
               "--severity", severity, "--no-banner"]
        if checks:
            cmd += ["--checks", checks]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
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
        if not _check_tool("scout"):
            return _hint("scout",
                         "pipx install scoutsuite  |  https://github.com/nccgroup/ScoutSuite")
        if provider not in {"aws", "azure", "gcp", "aliyun", "oci"}:
            return f"Error: provider must be aws|azure|gcp|aliyun|oci (got {provider!r})."
        cmd = ["scout", provider, "--no-browser", "--force"]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
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
            cloud: aws | azure | gcp | oracle | github.
            timeout: seconds.
        """
        if not _check_tool("cloudsploit"):
            return _hint("cloudsploit",
                         "npm i -g cloudsploit  |  https://github.com/aquasecurity/cloudsploit")
        cmd = ["cloudsploit", "scan", "--cloud", cloud, "--json-only"]
        if config_path:
            cmd += ["--config", config_path]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        rows: list[dict] = []
        try:
            data = json.loads(out) if out.strip().startswith("[") else {}
            if isinstance(data, list):
                for f in data:
                    if (f.get("status") or "").upper() in {"OK", "WARN_NA"}:
                        continue
                    rows.append({
                        "id": f.get("plugin") or "?",
                        "sev": f.get("status") or "?",
                        "title": (f.get("description") or "")[:80],
                        "region": f.get("region") or "global",
                    })
        except json.JSONDecodeError:
            pass
        lines = [f"cloudsploit [{cloud}]: {len(rows)} non-pass findings"]
        for r in rows[:50]:
            lines.append(f"  [{r['sev']:<8}] {r['id']}  ({r['region']})  {r['title']}")
        if rc != 0 and not rows:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_pacu(
        session_name: str,
        modules: list[str],
        regions: list[str] | None = None,
        data_path: str = "",
        timeout: int = 1800,
    ) -> str:
        """Run pacu AWS post-exploit modules (Rhino Security Labs).

        Requires AWS creds in pacu session (operator pre-loads). Active —
        operator must have written authorization for the target account.
        Destructive modules (anything matching Rule 5 denylist) are
        warn-and-log only; never auto-run.

        Args:
            session_name: pacu session label (created via `pacu -n NAME`).
            modules: pacu module list (e.g. ['iam__enum_users',
                'ec2__enum', 's3__enum_buckets']). Multiple run sequentially.
            regions: AWS regions to target (None -> all enabled).
            data_path: optional path to pacu data dir (--data DIR).
            timeout: seconds across all modules.
        """
        if not _check_tool("pacu"):
            return _hint("pacu",
                         "pipx install pacu  |  https://github.com/RhinoSecurityLabs/pacu")
        if not modules:
            return "run_pacu: at least one module required."
        # Rule 5 denylist — match common destructive pacu module names.
        destructive = {"iam__backdoor_users_keys", "iam__backdoor_users_password",
                       "iam__privesc_scan", "ec2__startup_shell_script",
                       "cloudtrail__delete", "guardduty__list_ip_sets",
                       "s3__bucket_finder", "lambda__backdoor_new_users"}
        blocked = [m for m in modules if m in destructive]
        if blocked:
            return (f"BLOCKED (Rule 5 denylist): {blocked}\n"
                    "These modules persist backdoors / delete audit trails / "
                    "destabilise the target. Operator must run manually with "
                    "explicit acknowledgement.")
        all_out: list[str] = []
        for mod in modules:
            cmd = ["pacu", "--session", session_name, "--module-name", mod]
            if regions:
                cmd += ["--regions", ",".join(regions)]
            if data_path:
                cmd += ["--data", data_path]
            out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
            tail = "\n".join(out.splitlines()[-40:])
            all_out.append(f"# pacu [{mod}] rc={rc}\n{tail}")
            if rc != 0 and err.strip():
                all_out.append(f"[stderr] {err[:200]}")
        return "\n\n".join(all_out)
