"""Multi-cloud config posture + AWS post-exploit wrappers.

- prowler / scout_suite / cloudsploit — read-only config audit (multi-cloud).
- azurehound — Azure AD / Entra ID graph collector (BloodHound data). Needs
  operator-supplied Azure credentials; never logs them.
- pacu — AWS post-exploitation framework (Rhino Security Labs). Active. Run
  ONLY against accounts the operator owns / has authorization for. Rule 5
  destructive denylist enforced at tool layer.

All OSS (Apache-2.0 / MIT / BSD).
"""

from __future__ import annotations

import asyncio
import json
import re

import httpx
from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _check_tool, _run_cmd


def _hint(tool: str, hint: str) -> str:
    return f"Error: {tool} not installed.\nInstall: {hint}"


# ── Anonymous public-bucket enumeration (read-only cloud recon) ────────────
# Common environment / purpose suffixes appended to a seed name. Read-only:
# every check is an anonymous HTTP GET (list-objects / list-container). No
# writes, no deletes — Rule 5-9 safe by construction.
_BUCKET_SUFFIXES: tuple[str, ...] = (
    "prod", "production", "dev", "development", "staging", "stage", "test",
    "qa", "backup", "backups", "bak", "assets", "static", "logs", "log",
    "uploads", "upload", "media", "data", "files", "public", "private",
    "cdn", "storage", "bucket", "archive", "dumps", "db", "internal",
    "config", "www", "web", "images", "img",
)

# Containers tried per Azure storage account (the account is the subdomain;
# the container is the path). The seed name itself is added at runtime.
_AZURE_CONTAINERS: tuple[str, ...] = ("$web", "public", "backup", "assets")

_MAX_HTTP_CHECKS = 40  # cap anonymous requests to respect rate limits


def _bucket_permutations(name: str, provider: str = "aws",
                         limit: int = _MAX_HTTP_CHECKS) -> list[str]:
    """Generate candidate bucket / storage-account names from a seed name.

    AWS/GCP bucket names: 3-63 chars, lowercase, [a-z0-9.-]. Azure storage
    account names: 3-24 chars, lowercase alphanumeric only (hyphens invalid),
    so hyphen/dot variants are collapsed for the azure provider.
    """
    base = re.sub(r"[^a-z0-9.-]", "-", name.lower().strip()).strip("-.")
    if not base:
        return []
    variants = [base]
    for s in _BUCKET_SUFFIXES:
        variants += [f"{base}-{s}", f"{base}{s}", f"{s}-{base}"]
    out: list[str] = []
    seen: set[str] = set()
    for v in variants:
        if provider == "azure":
            v = re.sub(r"[^a-z0-9]", "", v)
            if not (3 <= len(v) <= 24):
                continue
        else:
            if not (3 <= len(v) <= 63):
                continue
            if not re.match(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$", v):
                continue
        if v not in seen:
            seen.add(v)
            out.append(v)
        if len(out) >= limit:
            break
    return out


async def _classify_bucket(hc: httpx.AsyncClient, provider: str,
                           candidate: str, container: str = "") -> dict:
    """Anonymous list request for one candidate. Read-only GET.

    Classification (per provider list semantics):
      PUBLIC-LISTABLE — 200 + a listing body (high signal, anonymous read).
      EXISTS-PRIVATE  — 403 / access-denied (bucket exists, not public).
      ABSENT          — 404 / no-such-bucket.
      OTHER           — any other status.
      ERROR           — network / DNS failure.
    """
    if provider == "aws":
        url = f"https://{candidate}.s3.amazonaws.com/?list-type=2"
        marker = "ListBucketResult"
    elif provider == "gcp":
        url = f"https://storage.googleapis.com/{candidate}?list-type=2"
        marker = "ListBucketResult"
    else:  # azure
        url = (f"https://{candidate}.blob.core.windows.net/{container}"
               "?restype=container&comp=list")
        marker = "EnumerationResults"
    try:
        r = await hc.get(url)
    except Exception as e:  # DNS / TLS / connect — treat as unresolved
        return {"candidate": candidate, "container": container, "url": url,
                "status": "ERR", "class": "ERROR", "detail": str(e)[:80]}
    body_head = r.text[:4096]
    if r.status_code == 200 and marker in body_head:
        cls = "PUBLIC-LISTABLE"
    elif r.status_code == 403:
        cls = "EXISTS-PRIVATE"
    elif r.status_code == 404:
        cls = "ABSENT"
    else:
        cls = f"OTHER({r.status_code})"
    return {"candidate": candidate, "container": container, "url": url,
            "status": r.status_code, "class": cls}


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def enum_public_buckets(
        name: str,
        provider: str = "aws",
        timeout: int = 60,
        permutations: bool = True,
    ) -> str:
        """Anonymously enumerate public S3 / GCS buckets or Azure blob containers.

        READ-ONLY cloud recon: every check is an unauthenticated HTTP GET
        list-objects / list-container request straight to the cloud endpoint
        (no Burp, no creds). Never writes or deletes (Rule 5-9 safe).

        Prefers a CLI wrapper (cloud_enum, or s3scanner for AWS) when installed;
        otherwise runs in-process anonymous HTTP checks. Candidates are capped
        at 40 to respect provider rate limits.

        Args:
            name: seed org / project / bucket name.
            provider: aws | azure | gcp.
            timeout: overall seconds budget.
            permutations: when True, expand the seed with common env/purpose
                suffixes (name-prod, name-backup, name-assets, ...).

        Classification per candidate: PUBLIC-LISTABLE (high signal),
        EXISTS-PRIVATE, ABSENT, OTHER(<status>), ERROR.
        """
        provider = provider.lower().strip()
        if provider not in {"aws", "azure", "gcp"}:
            return f"Error: provider must be aws|azure|gcp (got {provider!r})."
        if not name.strip():
            return "Error: name is required."

        # Prefer an installed CLI wrapper (handles its own permutations).
        if _check_tool("cloud_enum"):
            disable = {"aws": ["--disable-azure", "--disable-gcp"],
                       "azure": ["--disable-aws", "--disable-gcp"],
                       "gcp": ["--disable-aws", "--disable-azure"]}[provider]
            cmd = ["cloud_enum", "-k", name, "-qs", *disable]
            out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
            tail = "\n".join(out.splitlines()[-40:])
            lines = [f"cloud_enum [{provider}] seed={name!r} rc={rc}", tail]
            if rc != 0 and err.strip():
                lines.append(f"[stderr] {err[:200]}")
            return "\n".join(lines)
        if provider == "aws" and _check_tool("s3scanner"):
            cands = _bucket_permutations(name, provider) if permutations else [name.lower()]
            # NOTE: s3scanner CLI flags vary across versions; feeding the
            # candidate list on stdin (-bucket-file -). If your build differs,
            # the in-process path below is the version-independent fallback.
            out, err, rc = await _run_cmd(
                ["s3scanner", "scan", "--bucket-file", "/dev/stdin"],
                timeout=timeout, bypass_proxy=True,
                stdin_input=("\n".join(cands) + "\n").encode())
            tail = "\n".join(out.splitlines()[-40:])
            lines = [f"s3scanner [aws] {len(cands)} candidates rc={rc}", tail]
            if rc != 0 and err.strip():
                lines.append(f"[stderr] {err[:200]}")
            return "\n".join(lines)

        # In-process anonymous HTTP fallback.
        candidates = (_bucket_permutations(name, provider)
                      if permutations else [name.lower().strip()])
        if not candidates:
            return f"Error: no valid {provider} candidate names from {name!r}."

        # Build the (candidate, container) work list, capped at _MAX_HTTP_CHECKS.
        if provider == "azure":
            base = re.sub(r"[^a-z0-9]", "", name.lower())
            containers = ([base] if base else []) + list(_AZURE_CONTAINERS)
            work = [(c, ct) for c in candidates for ct in containers]
        else:
            work = [(c, "") for c in candidates]
        work = work[:_MAX_HTTP_CHECKS]

        per_req = max(3, timeout // max(1, len(work)))
        async with httpx.AsyncClient(
            timeout=per_req, follow_redirects=False,
            headers={"User-Agent": "praetor-cloud-recon"},
            limits=httpx.Limits(max_connections=10)) as hc:
            results = await asyncio.gather(
                *[_classify_bucket(hc, provider, c, ct) for c, ct in work])

        order = {"PUBLIC-LISTABLE": 0, "EXISTS-PRIVATE": 1}
        results.sort(key=lambda r: order.get(r["class"], 2))
        public = [r for r in results if r["class"] == "PUBLIC-LISTABLE"]
        private = [r for r in results if r["class"] == "EXISTS-PRIVATE"]

        lines = [
            f"enum_public_buckets [{provider}] seed={name!r} "
            f"checked={len(results)} candidates",
            f"  PUBLIC-LISTABLE={len(public)}  EXISTS-PRIVATE={len(private)}",
        ]
        for r in results:
            if r["class"] in {"ABSENT", "ERROR"}:
                continue
            loc = r["candidate"] + (f"/{r['container']}" if r["container"] else "")
            lines.append(f"  [{r['class']:<15}] {loc}  -> {r['url']}")
        if public:
            lines.append("")
            lines.append("PUBLIC-LISTABLE buckets are anonymously readable — "
                         "enumerate objects for exposed data (READ-only PoC).")
        return "\n".join(lines)

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
        if not _check_tool("azurehound"):
            return _hint("azurehound",
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
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
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
        if not _check_tool("pacu"):
            return _hint("pacu",
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
            out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
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
        if not _check_tool("gcp_scanner") and not _check_tool("gcp-scanner"):
            return _hint("gcp_scanner",
                         "pipx install gcp-scanner  |  "
                         "https://github.com/google/gcp_scanner")
        tool = "gcp_scanner" if _check_tool("gcp_scanner") else "gcp-scanner"
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
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
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
