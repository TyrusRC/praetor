"""CI/CD pipeline audit wrappers — poutine, octoscan.

Both OSS. Detect GitHub Actions injection, pwn-request, untrusted-checkout,
secret leakage, third-party-action pinning, ARTIFACT poisoning patterns.

Also: audit_github_org_settings / audit_github_repo_settings — a GitHub REST
API settings reader. poutine/octoscan read workflow FILES (injection,
pwn-request, pinning); nothing read the platform's own org/repo SETTINGS
(branch protection, 2FA requirement, environment approval gates, secrets/
deploy-key inventory). GitLab/Jenkins equivalents are not built — GitHub
only, for now.
"""

from __future__ import annotations

import json

import httpx
from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _check_tool, _run_cmd

_GH_API = "https://api.github.com"


def _hint(tool: str, hint: str) -> str:
    return f"Error: {tool} not installed.\nInstall: {hint}"


def _gh_headers(token: str) -> dict:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


async def _gh_get(client: httpx.AsyncClient, path: str) -> tuple[int, object]:
    """GET one GitHub API path. Returns (status_code, json-or-text)."""
    try:
        resp = await client.get(f"{_GH_API}{path}")
    except httpx.RequestError as e:
        return 0, str(e)
    try:
        return resp.status_code, resp.json()
    except ValueError:
        return resp.status_code, resp.text[:300]


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_poutine(
        target: str,
        mode: str = "local",
        platform: str = "github",
        timeout: int = 600,
    ) -> str:
        """Run poutine CI/CD security analyzer (Boost Security).

        Args:
            target: local repo path | org/repo (GH) | namespace/project (GL).
            mode: local | analyze_repo | analyze_org.
            platform: github | gitlab.
            timeout: seconds.
        """
        if not _check_tool("poutine"):
            return _hint("poutine",
                         "brew install boostsecurityio/tap/poutine  |  "
                         "https://github.com/boostsecurityio/poutine/releases")
        if mode == "local":
            cmd = ["poutine", "analyze_local", "--path", target,
                   "--format", "json"]
        elif mode == "analyze_repo":
            cmd = ["poutine", "analyze_repo", target, "--format", "json",
                   "--scm", platform]
        elif mode == "analyze_org":
            cmd = ["poutine", "analyze_org", target, "--format", "json",
                   "--scm", platform]
        else:
            return f"Error: mode must be local|analyze_repo|analyze_org (got {mode!r})."
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            data = {}
        findings = data.get("findings") or data.get("Findings") or []
        lines = [f"poutine [{mode}/{platform}]: {len(findings)} findings on {target}"]
        for f in findings[:50]:
            rid = f.get("rule_id") or f.get("RuleID") or "?"
            sev = f.get("level") or f.get("Severity") or "?"
            path = f.get("meta", {}).get("path") or f.get("Path") or "?"
            lines.append(f"  [{sev:<8}] {rid}  {path}")
        if rc != 0 and not findings:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_octoscan(repo_path: str, timeout: int = 300) -> str:
        """Run octoscan GitHub Actions static analyzer (Synacktiv).

        Args:
            repo_path: local clone path (looks for .github/workflows/).
            timeout: seconds.
        """
        if not _check_tool("octoscan"):
            return _hint("octoscan",
                         "go install github.com/synacktiv/octoscan@latest  |  "
                         "https://github.com/synacktiv/octoscan")
        out, err, rc = await _run_cmd(
            ["octoscan", "scan", repo_path, "--json"],
            timeout=timeout, bypass_proxy=True,
        )
        try:
            data = json.loads(out) if out.strip() else []
        except json.JSONDecodeError:
            data = []
        if not isinstance(data, list):
            data = data.get("findings") or []
        lines = [f"octoscan: {len(data)} findings in {repo_path}"]
        for f in data[:50]:
            sev = f.get("severity") or "?"
            rule = f.get("rule") or f.get("rule_id") or "?"
            file = f.get("file") or "?"
            msg = (f.get("message") or "")[:80]
            lines.append(f"  [{sev:<8}] {rule}  {file}  -- {msg}")
        if rc != 0 and not data:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def audit_github_org_settings(org: str, token: str = "", timeout: int = 30) -> str:
        """Read a GitHub organization's platform settings via the REST API.

        Closes the org/IAM half of the CICD gap (branch-protection and
        environment checks live in audit_github_repo_settings) — SSO/2FA
        enforcement, default repo permission, Actions allowlist, outside
        collaborators, owner count. Needs a token with `read:org` scope
        (a fine-grained PAT or classic token — operator-supplied, never
        logged).

        Args:
            org: organization login (e.g. 'octocat-inc').
            token: GitHub PAT with read:org (and admin:org for members).
                Blank works for a public org's unauthenticated-visible fields
                only — most of these checks need it.
            timeout: seconds per API call.

        Maps to: CICD-IAM (2FA requirement, owner count, outside
        collaborators), CICD-CFG (default permission, Actions allowlist).
        """
        async with httpx.AsyncClient(timeout=timeout, headers=_gh_headers(token)) as client:
            sc, org_data = await _gh_get(client, f"/orgs/{org}")
            if sc == 404:
                return f"Error: org {org!r} not found or token lacks access."
            if sc not in (200,) or not isinstance(org_data, dict):
                return f"Error: GET /orgs/{org} -> {sc}: {org_data}"

            sc2, actions_perm = await _gh_get(client, f"/orgs/{org}/actions/permissions")
            sc3, admins = await _gh_get(client, f"/orgs/{org}/members?role=admin&per_page=100")
            sc4, outside = await _gh_get(client, f"/orgs/{org}/outside_collaborators?per_page=100")

        lines = [f"audit_github_org_settings {org}:"]
        lines.append(f"  two_factor_requirement_enabled: {org_data.get('two_factor_requirement_enabled', 'unknown (needs admin:org token)')}")
        lines.append(f"  default_repository_permission: {org_data.get('default_repository_permission', 'unknown')}")
        lines.append(f"  members_can_create_repositories: {org_data.get('members_can_create_repositories', 'unknown')}")
        lines.append(f"  members_allowed_repository_creation_type: {org_data.get('members_allowed_repository_creation_type', 'unknown')}")
        if isinstance(actions_perm, dict):
            lines.append(f"  actions allowed_actions: {actions_perm.get('allowed_actions', f'HTTP {sc2}')}")
        else:
            lines.append(f"  actions permissions: HTTP {sc2} (needs admin:org token)")
        if isinstance(admins, list):
            lines.append(f"  org owners/admins: {len(admins)} -- {', '.join(a.get('login','?') for a in admins[:20])}")
        else:
            lines.append(f"  org owners/admins: HTTP {sc3} (needs admin:org token)")
        if isinstance(outside, list):
            lines.append(f"  outside collaborators: {len(outside)} -- {', '.join(a.get('login','?') for a in outside[:20])}")
        else:
            lines.append(f"  outside collaborators: HTTP {sc4} (needs admin:org token)")
        lines.append("\nVerdicts are not auto-scored (Rule 13b) — read each field against "
                      "the control (e.g. 2FA requirement should be True for a program with "
                      "sensitive repos) and record the verdict yourself.")
        return "\n".join(lines)

    @mcp.tool()
    async def audit_github_repo_settings(repo: str, token: str = "", timeout: int = 30) -> str:
        """Read one GitHub repository's security-relevant settings via the REST API.

        Closes the repo-config half of the CICD gap: branch protection on the
        default branch, environment approval gates, Actions secret/
        deploy-key inventory (names only — the API never returns secret
        values), vulnerability-alert status, webhook endpoints.

        Args:
            repo: 'owner/name' (e.g. 'octocat-inc/payments-api').
            token: GitHub PAT — `repo` scope for private repos, admin rights
                on the repo for branch-protection and secrets-list endpoints.
            timeout: seconds per API call.

        Maps to: CICD-CFG (branch protection, environment gates),
        CICD-ART (secrets/deploy-key inventory), CICD-LOG (webhooks).
        Third-party GitHub App inventory (CICD-TPS) is NOT covered — that
        needs a separate GitHub App-authenticated call this tool does not
        make; note it as a follow-up, don't claim it as tested.
        """
        async with httpx.AsyncClient(timeout=timeout, headers=_gh_headers(token)) as client:
            sc, repo_data = await _gh_get(client, f"/repos/{repo}")
            if sc == 404:
                return f"Error: repo {repo!r} not found or token lacks access."
            if sc != 200 or not isinstance(repo_data, dict):
                return f"Error: GET /repos/{repo} -> {sc}: {repo_data}"
            default_branch = repo_data.get("default_branch", "main")

            sc_bp, branch_prot = await _gh_get(client, f"/repos/{repo}/branches/{default_branch}/protection")
            sc_env, envs = await _gh_get(client, f"/repos/{repo}/environments")
            sc_sec, secrets = await _gh_get(client, f"/repos/{repo}/actions/secrets")
            sc_keys, deploy_keys = await _gh_get(client, f"/repos/{repo}/keys")
            sc_vuln, _vuln = await _gh_get(client, f"/repos/{repo}/vulnerability-alerts")
            sc_hooks, hooks = await _gh_get(client, f"/repos/{repo}/hooks")

        lines = [f"audit_github_repo_settings {repo} (default branch: {default_branch}):"]
        lines.append(f"  visibility: {repo_data.get('visibility', 'unknown')}  "
                      f"archived: {repo_data.get('archived')}")

        if sc_bp == 200 and isinstance(branch_prot, dict):
            rr = branch_prot.get("required_pull_request_reviews", {}) or {}
            lines.append("  branch_protection: ENABLED")
            lines.append(f"    required_approving_review_count: {rr.get('required_approving_review_count', 0)}")
            lines.append(f"    require_code_owner_reviews: {rr.get('require_code_owner_reviews', False)}")
            lines.append(f"    enforce_admins: {(branch_prot.get('enforce_admins') or {}).get('enabled', False)}")
            lines.append(f"    required_status_checks: {(branch_prot.get('required_status_checks') or {}).get('contexts', [])}")
            lines.append(f"    allow_force_pushes: {(branch_prot.get('allow_force_pushes') or {}).get('enabled', False)}")
            lines.append(f"    allow_deletions: {(branch_prot.get('allow_deletions') or {}).get('enabled', False)}")
        elif sc_bp == 404:
            lines.append("  branch_protection: NOT CONFIGURED on the default branch")
        else:
            lines.append(f"  branch_protection: HTTP {sc_bp} (needs admin rights on the repo)")

        if sc_env == 200 and isinstance(envs, dict):
            for e in envs.get("environments", []):
                rules = e.get("protection_rules", [])
                lines.append(f"  environment {e.get('name')}: protection_rules={[r.get('type') for r in rules]}")
            if not envs.get("environments"):
                lines.append("  environments: none configured")
        else:
            lines.append(f"  environments: HTTP {sc_env}")

        if sc_sec == 200 and isinstance(secrets, dict):
            names = [s.get("name") for s in secrets.get("secrets", [])]
            lines.append(f"  actions secrets ({len(names)}, names only): {names[:30]}")
        else:
            lines.append(f"  actions secrets: HTTP {sc_sec} (needs admin rights)")

        if isinstance(deploy_keys, list):
            lines.append(f"  deploy keys: {len(deploy_keys)} -- "
                          f"{[k.get('title') for k in deploy_keys[:10]]}  "
                          f"(read_only flags: {[k.get('read_only') for k in deploy_keys[:10]]})")
        else:
            lines.append(f"  deploy keys: HTTP {sc_keys}")

        if sc_vuln in (204, 404):
            lines.append(f"  vulnerability_alerts enabled: {sc_vuln == 204}")
        else:
            lines.append(f"  vulnerability_alerts enabled: unknown (HTTP {sc_vuln}, needs a token with repo access)")

        if isinstance(hooks, list):
            lines.append(f"  webhooks: {len(hooks)} -- {[h.get('config',{}).get('url','?') for h in hooks[:10]]}")
        else:
            lines.append(f"  webhooks: HTTP {sc_hooks} (needs admin rights)")

        lines.append("\nThird-party GitHub App inventory (CICD-TPS) is NOT covered by this "
                      "call — see the tool docstring. Verdicts are not auto-scored (Rule "
                      "13b) — read each field against the control and record it yourself.")
        return "\n".join(lines)
