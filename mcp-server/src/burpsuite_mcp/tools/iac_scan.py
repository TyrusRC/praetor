"""IaC + container policy wrappers — checkov, tfsec, terrascan, hadolint.

All OSS (Apache-2.0/MPL/MIT). Static analysis only — never deploys.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd


def _hint(tool: str, hint: str) -> str:
    return f"Error: {tool} not installed.\nInstall: {hint}"


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_checkov(
        path: str,
        framework: str = "all",
        severity: str = "",
        timeout: int = 900,
    ) -> str:
        """Run Checkov IaC policy scan.

        Args:
            path: directory / file (Terraform, K8s, Helm, CloudFormation, ARM, Dockerfile, etc.).
            framework: all | terraform | kubernetes | helm | cloudformation | dockerfile | ...
            severity: HIGH | CRITICAL (empty = all).
            timeout: seconds.
        """
        if not _check_tool("checkov"):
            return _hint("checkov",
                         "pipx install checkov  |  https://github.com/bridgecrewio/checkov")
        cmd = ["checkov", "-d", path, "-o", "json", "--quiet",
               "--framework", framework]
        if severity:
            cmd += ["--check", f"severity:{severity}"]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            data = {}
        if isinstance(data, list):
            results = []
            for d in data:
                results.extend((d.get("results") or {}).get("failed_checks") or [])
        else:
            results = (data.get("results") or {}).get("failed_checks") or []
        lines = [f"checkov [{framework}]: {len(results)} failed checks in {path}"]
        for f in results[:50]:
            sev = (f.get("severity") or "?")
            lines.append(f"  [{sev:<8}] {f.get('check_id','?')}  "
                         f"{f.get('resource','?')}  -- {(f.get('check_name') or '')[:80]}")
        if rc != 0 and not results:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_tfsec(path: str, severity: str = "HIGH,CRITICAL", timeout: int = 600) -> str:
        """Run tfsec Terraform security scan.

        Args:
            path: Terraform directory.
            severity: comma list (LOW,MEDIUM,HIGH,CRITICAL).
            timeout: seconds.
        """
        if not _check_tool("tfsec"):
            return _hint("tfsec",
                         "brew install tfsec  |  "
                         "https://github.com/aquasecurity/tfsec/releases")
        cmd = ["tfsec", path, "--format", "json", "--soft-fail",
               "--minimum-severity", severity.split(",")[0]]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            data = {}
        results = data.get("results") or []
        lines = [f"tfsec: {len(results)} findings in {path} (min={severity})"]
        for f in results[:50]:
            lines.append(f"  [{f.get('severity','?'):<8}] {f.get('rule_id','?')}  "
                         f"{f.get('resource','?')}  -- {(f.get('description') or '')[:80]}")
        if rc != 0 and not results:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_terrascan(
        path: str,
        iac_type: str = "terraform",
        timeout: int = 600,
    ) -> str:
        """Run Terrascan IaC policy scan (CIS / NIST / GDPR / HIPAA / PCI).

        Args:
            path: directory.
            iac_type: terraform | k8s | helm | dockerfile | arm | kustomize.
            timeout: seconds.
        """
        if not _check_tool("terrascan"):
            return _hint("terrascan",
                         "brew install terrascan  |  "
                         "https://github.com/tenable/terrascan/releases")
        cmd = ["terrascan", "scan", "-d", path, "-i", iac_type, "-o", "json"]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            data = {}
        violations = ((data.get("results") or {}).get("violations") or [])
        lines = [f"terrascan [{iac_type}]: {len(violations)} violations in {path}"]
        for v in violations[:50]:
            lines.append(f"  [{v.get('severity','?'):<8}] {v.get('rule_id','?')}  "
                         f"{v.get('resource_name','?')}  -- {(v.get('description') or '')[:80]}")
        if rc != 0 and not violations:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_hadolint(dockerfile: str, timeout: int = 60) -> str:
        """Lint a Dockerfile with hadolint (CIS + best-practice).

        Args:
            dockerfile: path to Dockerfile.
            timeout: seconds.
        """
        if not _check_tool("hadolint"):
            return _hint("hadolint",
                         "brew install hadolint  |  "
                         "https://github.com/hadolint/hadolint/releases")
        out, err, rc = await _run_cmd(
            ["hadolint", "--format", "json", dockerfile],
            timeout=timeout, bypass_proxy=True,
        )
        try:
            data = json.loads(out) if out.strip().startswith("[") else []
        except json.JSONDecodeError:
            data = []
        lines = [f"hadolint: {len(data)} issues in {dockerfile}"]
        for d in data[:50]:
            lines.append(f"  [{d.get('level','?'):<7}] {d.get('code','?')} "
                         f"(line {d.get('line','?')})  {(d.get('message') or '')[:90]}")
        if rc not in (0, 1) and not data:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)
