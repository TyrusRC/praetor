"""run_credshound — local-host credential-surface scanner (Go, Apache-2.0,
haxxm0nkey/credshound, LOLCreds-template-driven — nuclei for credential
artifacts rather than web vulns).

Scans the host it runs on (plus any extra root paths given) for exposed
secrets: environment variables, Git credentials, Docker/K8s configs, shell
history, `.netrc`/`.pgpass`, private keys, and AI/MCP config files (Claude,
Copilot CLI, Hugging Face, OpenAI). A post-foothold tool — point it at a
captured shell on a network-lane target the same way any other sanctioned
binary runs there, or run it locally to audit the operator's own box.

NOT wired into `ingest_bloodhound`: that parser expects the classic
SharpHound/bloodhound-python AD schema (Users/Groups/Computers + ACL edges).
credshound's `-bloodhound` flag writes a different graph — custom OpenGraph
node kinds (CHHost/CHLocalUser/CHExposure/CHCredential/CHService) describing
local credential blast radius, not AD relationships. Praetor does not push
that file to a live BloodHound CE instance (no tested API client exists
here) — it is written to disk for the operator to import by hand via
BloodHound CE's own Upload Files UI (after a one-time
`credshound -bh-setup -server <bhce-url>` to register the icons/queries).
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from praetor.tools.recon._common import _check_tool, _run_cmd

from ._oplog import record_action

_TEMPLATE_CACHE = Path.home() / ".cache" / "credshound" / "templates"


def _ingested_path(domain: str) -> Path:
    from praetor.tools.workspace import ensure_workspace
    return ensure_workspace(domain)["network"] / "_credshound_ingested.json"


def _load_ingested(domain: str) -> dict:
    p = _ingested_path(domain)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_ingested(domain: str, m: dict) -> None:
    p = _ingested_path(domain)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(m), encoding="utf-8")


def _parse_jsonl(out: str) -> list[dict]:
    rows = []
    for line in out.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_credshound(
        roots: str = ".",
        domain: str = "",
        source_host: str = "",
        sources: str = "",
        severity: str = "",
        recursive: bool = False,
        bloodhound_output: str = "",
        auto_update_templates: bool = True,
        timeout: int = 180,
    ) -> str:
        """Scan for exposed credentials with credshound (env/files/proc + LOLCreds).

        Args:
            roots: space-separated scan roots (default '.'). credshound also
                checks host-level default locations (home dir, shell history,
                cloud/Git/Docker/K8s config paths) regardless of roots.
            domain: engagement key for operator-log evidence (defaults to
                source_host or 'credshound').
            source_host: host this scan ran on (recorded as the operator-log
                source — set it when this is a post-foothold scan on a
                captured shell, not the operator's own box).
            sources: comma list to restrict to — 'env', 'file', 'proc'. Blank
                = tool default (env + file).
            severity: comma list to include — 'info', 'medium', 'high'.
                Blank = all.
            recursive: also search roots for bare config filenames like
                `.env` or `values.yaml` (slower, more file-walk).
            bloodhound_output: path to also write the OpenGraph JSON for a
                manual BloodHound CE import (see module docstring — Praetor
                does not push this to a live BHCE API itself). Blank skips it.
            auto_update_templates: fetch LOLCreds templates on first use if
                the cache is empty (default True — a one-time ~180-file
                download, same pattern as nuclei-templates auto-fetch).
            timeout: seconds.

        Findings are recorded to the operator log (ATT&CK-tagged, idempotent
        by secret fingerprint) the same way ingest_bloodhound records AD
        edges. Evidence values stay redacted (credshound's own default,
        e.g. "AKIA****MPLE") — this tool never requests `-show-secrets`.
        """
        if not _check_tool("credshound"):
            return ("Error: credshound not installed.\n"
                    "Install: go install github.com/haxxm0nkey/credshound/cmd/credshound@latest")

        if auto_update_templates and not _TEMPLATE_CACHE.exists():
            out, err, rc = await _run_cmd(["credshound", "-ut"], timeout=timeout, bypass_proxy=True)
            if rc != 0 or not _TEMPLATE_CACHE.exists():
                return (f"Error: LOLCreds template fetch failed (rc={rc}): {(err or out)[:300]}\n"
                         "Retry with auto_update_templates=True once network access is confirmed, "
                         "or point -t at a downloaded lolcreds-data zip manually.")

        cmd = ["credshound", "-silent", "-j", "-nc"]
        if sources:
            cmd += ["-sources", sources]
        if severity:
            cmd += ["-severity", severity]
        if recursive:
            cmd += ["-recursive"]
        if bloodhound_output:
            cmd += ["-bloodhound", "-o", bloodhound_output]
        cmd += shlex.split(roots)

        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        if rc not in (0, 1):  # credshound exits 1 when findings exist, by nuclei convention
            return f"Error: credshound exited rc={rc}: {(err or out)[:400]}"

        findings = [] if bloodhound_output else _parse_jsonl(out)
        resolved = domain or source_host or "credshound"
        recorded = _load_ingested(resolved)
        new_op_ids: list[str] = []
        for f in findings:
            fp = f.get("secret_fingerprint", "")
            if not fp or fp in recorded:
                continue
            op_id = record_action(
                resolved, "credshound", f.get("credential_id", ""),
                description=f"{f.get('product','?')} — {f.get('credential','?')}",
                source=source_host, target=f.get("location", ""),
                output=f.get("evidence", ""), tactic="TA0006", technique="T1552",
                tags=[f"ch:{f.get('category','')}", f"sev:{f.get('confidence','')}",
                      f"src:{f.get('source','')}"],
            )
            recorded[fp] = op_id
            new_op_ids.append(op_id)
        if new_op_ids:
            _save_ingested(resolved, recorded)

        lines = [f"run_credshound [{roots}] domain={resolved}: "
                 f"{len(findings)} finding(s), {len(new_op_ids)} new -> operator log"]
        if bloodhound_output:
            lines.append(f"  OpenGraph written to {bloodhound_output} — import it into a running "
                         "BloodHound CE by hand (Upload Files UI); Praetor does not push it automatically.")
        by_conf: dict[str, int] = {}
        for f in findings:
            by_conf[f.get("confidence", "?")] = by_conf.get(f.get("confidence", "?"), 0) + 1
        if by_conf:
            lines.append(f"  confidence: {', '.join(f'{k}={v}' for k, v in sorted(by_conf.items()))}")
        for f in [x for x in findings if x.get("confidence") == "high"][:15]:
            lines.append(f"    [{f.get('confidence')}] {f.get('product','?')} {f.get('credential','?')} "
                         f"-- {f.get('location','?')} ({f.get('evidence','')})")
        if not findings and not bloodhound_output:
            lines.append("  no credential exposure matched (templates + builtins ran clean)")
        return "\n".join(lines)

    @mcp.tool()
    async def run_credshound_update_templates(timeout: int = 60) -> str:
        """Force-refresh the LOLCreds template cache credshound uses.

        Run this on its own when `run_credshound`'s auto-update is disabled,
        or to pick up new templates between engagements.
        """
        if not _check_tool("credshound"):
            return ("Error: credshound not installed.\n"
                    "Install: go install github.com/haxxm0nkey/credshound/cmd/credshound@latest")
        out, err, rc = await _run_cmd(["credshound", "-ut"], timeout=timeout, bypass_proxy=True)
        if rc != 0:
            return f"Error: template update failed (rc={rc}): {(err or out)[:300]}"
        return f"LOLCreds templates updated at {_TEMPLATE_CACHE}:\n{out.strip()[-400:]}"


__all__ = ["register"]
