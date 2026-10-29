"""Anonymous, read-only cloud recon: public S3/GCS bucket + Azure blob enumeration.

Every check is an unauthenticated HTTP GET (list-objects / list-container) straight
to the cloud endpoint — no writes, no deletes (Rule 5-9 safe by construction).
"""

from __future__ import annotations

import asyncio
import re

import httpx
from mcp.server.fastmcp import FastMCP

import praetor.tools.cloud_audit as _c  # resolve _check_tool / _run_cmd at call time


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
        if _c._check_tool("cloud_enum"):
            disable = {"aws": ["--disable-azure", "--disable-gcp"],
                       "azure": ["--disable-aws", "--disable-gcp"],
                       "gcp": ["--disable-aws", "--disable-azure"]}[provider]
            cmd = ["cloud_enum", "-k", name, "-qs", *disable]
            out, err, rc = await _c._run_cmd(cmd, timeout=timeout, bypass_proxy=True)
            tail = "\n".join(out.splitlines()[-40:])
            lines = [f"cloud_enum [{provider}] seed={name!r} rc={rc}", tail]
            if rc != 0 and err.strip():
                lines.append(f"[stderr] {err[:200]}")
            return "\n".join(lines)
        if provider == "aws" and _c._check_tool("s3scanner"):
            cands = _bucket_permutations(name, provider) if permutations else [name.lower()]
            # NOTE: s3scanner CLI flags vary across versions; feeding the
            # candidate list on stdin (-bucket-file -). If your build differs,
            # the in-process path below is the version-independent fallback.
            out, err, rc = await _c._run_cmd(
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
