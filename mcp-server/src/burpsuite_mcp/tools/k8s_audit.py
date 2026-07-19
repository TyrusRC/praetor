"""K8s active audit wrappers — kubescape + kube-hunter.

Kubescape: posture (NSA/MITRE/CIS), supports cluster + manifest mode.
Kube-hunter: active reconnaissance + exploitation of K8s clusters.
Both OSS (Apache).
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd


def _hint(tool: str, hint: str) -> str:
    return f"Error: {tool} not installed.\nInstall: {hint}"


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_kubescape(
        target: str = "",
        framework: str = "nsa",
        mode: str = "cluster",
        timeout: int = 900,
    ) -> str:
        """Posture scan via kubescape.

        Args:
            target: '' for current cluster; or path to manifests / Helm chart.
            framework: nsa | mitre | cis-eks | cis-aks | cis-v1.23 | armobest | devopsbest | allcontrols.
            mode: cluster | manifest.
            timeout: seconds.
        """
        if not _check_tool("kubescape"):
            return _hint("kubescape",
                         "curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash")
        cmd = ["kubescape", "scan", "framework", framework, "--format", "json"]
        if mode == "manifest" and target:
            cmd.append(target)
        elif mode == "cluster":
            pass
        else:
            return f"Error: mode must be 'cluster' or 'manifest' (got {mode!r})."
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            data = {}
        summary = data.get("summaryDetails", {}) or {}
        rows = []
        for ctrl_id, ctrl in (summary.get("controls") or {}).items():
            status = (ctrl.get("status") or {}).get("status", "?")
            if status.lower() == "failed":
                rows.append({
                    "id": ctrl_id,
                    "name": ctrl.get("name") or "?",
                    "severity": ctrl.get("scoreFactor") or "?",
                    "failed_resources": (ctrl.get("ResourceCounters") or {}).get("failedResources", 0),
                })
        lines = [f"kubescape [{framework}/{mode}]: {len(rows)} failed controls"]
        for r in sorted(rows, key=lambda r: -float(r['severity']) if isinstance(r['severity'], (int, float, str)) else 0)[:50]:
            lines.append(f"  {r['id']} [{r['severity']}]  {r['name']}  ({r['failed_resources']} resources)")
        if rc != 0 and not rows:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_kube_hunter(
        target: str = "",
        mode: str = "remote",
        active: bool = False,
        timeout: int = 600,
    ) -> str:
        """Active K8s recon / exploit via kube-hunter.

        Args:
            target: IP / hostname / CIDR for remote mode (empty = local interfaces).
            mode: remote | internal | network.
            active: true to run active checks (Rule 5 destructive denylist enforced upstream).
            timeout: seconds.
        """
        if not _check_tool("kube-hunter"):
            return _hint("kube-hunter",
                         "pip install kube-hunter  |  https://github.com/aquasecurity/kube-hunter")
        cmd = ["kube-hunter", "--report", "json"]
        if mode == "remote":
            cmd += ["--remote", target] if target else ["--remote", "127.0.0.1"]
        elif mode == "internal":
            cmd += ["--internal"]
        elif mode == "network":
            cmd += ["--cidr", target] if target else ["--cidr", "10.0.0.0/24"]
        else:
            return f"Error: mode must be remote|internal|network (got {mode!r})."
        if active:
            cmd += ["--active"]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            data = {}
        vulns = data.get("vulnerabilities") or []
        lines = [f"kube-hunter [{mode}, active={active}]: {len(vulns)} findings"]
        for v in vulns[:30]:
            sev = v.get("severity", "?")
            cat = v.get("category", "?")
            desc = (v.get("description") or "")[:120]
            lines.append(f"  [{sev}] {cat}: {desc}")
        if rc != 0 and not vulns:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_peirates(
        commands: list[str] | None = None,
        timeout: int = 300,
    ) -> str:
        """Run peirates K8s post-exploit / privesc (interactive menu via stdin).

        Args:
            commands: peirates menu commands (e.g. ['1', '99']).
                Empty -> autocheck (option 1) then exit.
            timeout: seconds.
        """
        if not _check_tool("peirates"):
            return _hint("peirates",
                         "go install github.com/inguardians/peirates@latest  |  "
                         "https://github.com/inguardians/peirates")
        from burpsuite_mcp.tools.recon._common import _run_cmd
        stdin_input = ("\n".join(commands or ["1", "exit"]) + "\n").encode()
        # peirates is an interactive K8s attack tool — never proxy it through Burp.
        out_s, err_s, rc = await _run_cmd(
            ["peirates"], timeout=timeout, bypass_proxy=True, stdin_input=stdin_input)
        tail = "\n".join(out_s.splitlines()[-80:])
        lines = [f"peirates rc={rc}", tail]
        if rc != 0:
            lines.append(f"[stderr] {err_s[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_kdigger(
        command: str = "all",
        timeout: int = 180,
    ) -> str:
        """Run kdigger pod-context discovery (admission/syscalls/usernsmode/etc.).

        Args:
            command: all | admission | apiresources | aws | authz | capabilities |
                     cgroups | gcp | mount | node | pidnamespace | processes |
                     runtime | services | syscalls | token | userid | usernsmode.
            timeout: seconds.
        """
        if not _check_tool("kdigger"):
            return _hint("kdigger",
                         "brew install mtardy/tap/kdigger  |  "
                         "https://github.com/quarkslab/kdigger/releases")
        out, err, rc = await _run_cmd(
            ["kdigger", "dig", command, "--output", "json"],
            timeout=timeout, bypass_proxy=True,
        )
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            data = {}
        buckets = data.get("buckets") or data.get("Results") or []
        lines = [f"kdigger [{command}]: {len(buckets)} buckets"]
        for b in buckets[:20]:
            name = b.get("name") or b.get("Name") or "?"
            result_keys = list((b.get("results") or b.get("Results") or {}).keys())[:6]
            lines.append(f"  {name}: keys={result_keys}")
        if rc != 0 and not buckets:
            tail = "\n".join(out.splitlines()[:40])
            lines.append(tail)
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_kubeletctl(
        target: str,
        action: str = "pods",
        port: int = 10250,
        timeout: int = 60,
    ) -> str:
        """Probe a kubelet API endpoint via kubeletctl.

        Args:
            target: kubelet host (IP / FQDN).
            action: pods | scan | runningpods | scanner-pods | metrics | configz |
                    healthz | stats.
            port: kubelet port (10250 secure / 10255 read-only).
            timeout: seconds.
        """
        if not _check_tool("kubeletctl"):
            return _hint("kubeletctl",
                         "go install github.com/cyberark/kubeletctl/cmd/kubeletctl@latest  |  "
                         "https://github.com/cyberark/kubeletctl")
        if action == "scan":
            cmd = ["kubeletctl", "scan", "rce", "--cidr", target]
        else:
            cmd = ["kubeletctl", action, "--server", target, "--port", str(port)]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        tail = "\n".join(out.splitlines()[:80])
        lines = [f"kubeletctl [{action}] target={target}:{port} rc={rc}", tail]
        if rc != 0:
            lines.append(f"[stderr] {err[:200]}")
        return "\n".join(lines)
