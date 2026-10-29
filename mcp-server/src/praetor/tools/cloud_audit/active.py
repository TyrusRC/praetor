"""Credentialed / post-exploit cloud collectors: azurehound, pacu, gcp_scanner.

These act with operator-supplied credentials against accounts the operator is
authorized for. Credentials are passed to the child process only and never echoed
back. pacu's destructive modules are gated by a Rule 5 denylist at this layer.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

import praetor.tools.cloud_audit as _c  # resolve _check_tool / _run_cmd / _hint at call time


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_azurehound(
        tenant: str = "",
        refresh_token: str = "",
        username: str = "",
        password: str = "",
        jwt: str = "",
        output: str = "azurehound-output.json",
        timeout: int = 1800,
    ) -> str:
        """Collect Azure AD / Entra ID graph data with azurehound (BloodHound ingest).

        Provide EXACTLY ONE auth method: refresh_token, jwt, or username+password.
        Credentials are passed to the process only — never echoed back.

        Args:
            tenant: Azure tenant ID (GUID) or domain.
            refresh_token / jwt / username+password: one auth method.
            output: file azurehound writes the collected JSON to.
            timeout: seconds.
        """
        if not _c._check_tool("azurehound"):
            return _c._hint("azurehound",
                            "go install github.com/bloodhoundad/azurehound@latest  |  "
                            "https://github.com/BloodHoundAD/AzureHound")
        if not tenant:
            return "Error: tenant (GUID or domain) is required."
        auth: list[str] = []
        if refresh_token:
            auth = ["-r", refresh_token]
        elif jwt:
            auth = ["--jwt", jwt]
        elif username and password:
            auth = ["-u", username, "-p", password]
        else:
            return ("Error: provide one auth method — refresh_token, jwt, or "
                    "username+password. azurehound needs Azure credentials the "
                    "operator is authorized to use.")
        cmd = ["azurehound", *auth, "list", "--tenant", tenant, "-o", output]
        out, err, rc = await _c._run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        # Never surface credentials; report only outcome + counts.
        n = out.count('"kind"') or out.count('"data"')
        lines = [f"azurehound [tenant={tenant}]: rc={rc}, output -> {output}"]
        if n:
            lines.append(f"  collected ~{n} graph objects (ingest {output} into BloodHound)")
        if rc != 0:
            safe_err = err.replace(refresh_token or "\x00", "***").replace(password or "\x00", "***")
            lines.append(f"  [rc={rc}] {safe_err[:200]}")
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
        if not _c._check_tool("pacu"):
            return _c._hint("pacu",
                            "pipx install pacu  |  https://github.com/RhinoSecurityLabs/pacu")
        if not modules:
            return "run_pacu: at least one module required."
        # Rule 5 denylist — only modules that PERSIST a backdoor, delete audit
        # trails, or run code on the target. Read-only enumeration is NOT
        # destructive: iam__privesc_scan (analyses permissions, writes nothing),
        # s3__bucket_finder (discovery) and guardduty__list_ip_sets (a list_ API)
        # were mislabeled and are the highest-value AWS recon — they stay allowed.
        destructive = {"iam__backdoor_users_keys", "iam__backdoor_users_password",
                       "ec2__startup_shell_script", "cloudtrail__delete",
                       "lambda__backdoor_new_users"}
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
            out, err, rc = await _c._run_cmd(cmd, timeout=timeout, bypass_proxy=True)
            tail = "\n".join(out.splitlines()[-40:])
            all_out.append(f"# pacu [{mod}] rc={rc}\n{tail}")
            if rc != 0 and err.strip():
                all_out.append(f"[stderr] {err[:200]}")
        return "\n\n".join(all_out)

    @mcp.tool()
    async def run_gcp_scanner(
        target: str = "",
        access_token: str = "",
        key_path: str = "",
        output_dir: str = "gcp-scan",
        timeout: int = 1200,
    ) -> str:
        """Enumerate GCP access + privilege-escalation surface with gcp_scanner.

        Fills the GCP active-recon gap (AWS has pacu, Azure has azurehound). From
        an OAuth access token OR a service-account key, gcp_scanner walks what the
        identity can reach — projects, IAM bindings, service accounts (impersonation
        / actAs privesc), GCS buckets, GCE, GKE, Cloud Functions, secrets — the
        read-only inventory a GCP attack path is built from. Credentials are passed
        to the process only, never echoed.

        Args:
            target: optional project/org id to scope to (blank = everything reachable).
            access_token: a GCP OAuth access token (ya29....) — one auth method.
            key_path: path to a service-account JSON key — the other auth method.
            output_dir: directory gcp_scanner writes results to.
            timeout: seconds.
        """
        if not _c._check_tool("gcp_scanner") and not _c._check_tool("gcp-scanner"):
            return _c._hint("gcp_scanner",
                            "pipx install gcp-scanner  |  "
                            "https://github.com/google/gcp_scanner")
        tool = "gcp_scanner" if _c._check_tool("gcp_scanner") else "gcp-scanner"
        if not access_token and not key_path:
            return ("Error: provide one auth method — access_token (ya29....) or "
                    "key_path (service-account JSON). gcp_scanner needs GCP "
                    "credentials the operator is authorized to use.")
        cmd = [tool, "-o", output_dir]
        if access_token:
            cmd += ["-at", access_token]
        elif key_path:
            cmd += ["-k", key_path]
        if target:
            cmd += ["-p", target]
        out, err, rc = await _c._run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        safe_err = err.replace(access_token or "\x00", "***")
        lines = [f"gcp_scanner [{target or 'all reachable'}]: rc={rc}, output -> {output_dir}/"]
        tail = "\n".join(out.splitlines()[-40:])
        if tail.strip():
            lines.append(tail)
        if rc != 0 and safe_err.strip():
            lines.append(f"[rc={rc}] {safe_err[:200]}")
        lines.append("Next: from what the identity can reach, find the privesc edge "
                     "(SA impersonation / actAs / setIamPolicy) — plan_attack_paths.")
        return "\n".join(lines)
