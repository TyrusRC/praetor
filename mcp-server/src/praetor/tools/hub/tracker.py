"""push_finding_to_tracker — file a Praetor finding as a tracker issue.

Consolidation-hub egress: turn a stored finding into a GitHub / GitLab / Jira
issue so remediation owners work it in their own system. The outbound call goes
to the OPERATOR'S OWN tracker (not a pentest target), so it bypasses Burp.

Credentials are NEVER hardcoded — every value is read from an environment
variable by name:

  github  -> GITHUB_TOKEN
  gitlab  -> GITLAB_TOKEN ; GITLAB_URL (optional, default https://gitlab.com)
  jira    -> JIRA_USER + JIRA_TOKEN ; JIRA_URL (required to send)

`_issue_from_finding` is pure; the @mcp.tool does the network I/O.
"""

from __future__ import annotations

import base64
import os
from urllib.parse import quote

import httpx
from mcp.server.fastmcp import FastMCP

from ..notes._helpers import _safe_findings_path, _load_findings_file, _find_by_id

_TRACKERS = {"github", "gitlab", "jira"}


def _issue_from_finding(f: dict) -> tuple[str, str]:
    """Compose an issue title + markdown body from a finding. Pure."""
    sev = str(f.get("severity", "") or "LOW").upper()
    title = f"[{sev}] {f.get('title', 'Untitled finding')}"
    cvss = f.get("cvss4_vector") or f.get("cvss_vector") or ""

    meta = [
        f"**Severity:** {sev}",
        f"**Endpoint:** {f.get('endpoint', '') or 'n/a'}",
    ]
    if f.get("parameter"):
        meta.append(f"**Parameter:** {f['parameter']}")
    if f.get("vuln_type"):
        meta.append(f"**Class:** {f['vuln_type']}")
    if f.get("cwe"):
        meta.append(f"**CWE:** {f['cwe']}")
    if cvss:
        meta.append(f"**CVSS:** {cvss}")

    body = "\n".join(meta)
    body += f"\n\n## Impact\n\n{f.get('impact', '') or '_Not supplied._'}"
    body += f"\n\n## Remediation\n\n{f.get('remediation', '') or '_Not supplied._'}"
    steps = f.get("reproduction_steps") or ""
    if steps:
        body += f"\n\n## Reproduction\n\n{steps}"
    body += f"\n\n---\n_Filed by Praetor · finding {f.get('id', '')}_"
    return title, body


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def push_finding_to_tracker(
        domain: str,
        finding_id: str,
        tracker: str = "github",
        repo: str = "",
        project: str = "",
        dry_run: bool = False,
    ) -> dict:
        """File a stored finding as an issue in an external tracker.

        tracker: github | gitlab | jira. `repo` is owner/name (github);
        `project` is the numeric/path project id (gitlab) or the project KEY
        (jira). Credentials come from environment variables — never hardcoded:
        GITHUB_TOKEN; GITLAB_TOKEN + optional GITLAB_URL; JIRA_USER + JIRA_TOKEN
        + JIRA_URL. dry_run=True returns the composed payload WITHOUT sending
        (works with no creds). Returns {tracker, issue_url|dry_run, finding_id}.
        """
        if tracker not in _TRACKERS:
            return {"error": f"tracker must be one of {sorted(_TRACKERS)}"}

        data = _load_findings_file(_safe_findings_path(domain))
        _, finding = _find_by_id(data.get("findings", []), finding_id)
        if finding is None:
            return {"error": f"finding '{finding_id}' not found in '{domain}'"}

        title, body = _issue_from_finding(finding)

        if tracker == "github":
            if not repo:
                return {"error": "github requires repo='owner/name'"}
            url = f"https://api.github.com/repos/{repo}/issues"
            payload = {"title": title, "body": body}
            if dry_run:
                return {"tracker": tracker, "dry_run": {"url": url, "payload": payload},
                        "finding_id": finding_id}
            token = os.environ.get("GITHUB_TOKEN")
            if not token:
                return {"error": "GITHUB_TOKEN not set in environment"}
            headers = {"Authorization": f"Bearer {token}",
                       "Accept": "application/vnd.github+json"}
            url_key = "html_url"

        elif tracker == "gitlab":
            if not project:
                return {"error": "gitlab requires project=<id or url-encoded path>"}
            base = os.environ.get("GITLAB_URL", "https://gitlab.com").rstrip("/")
            url = f"{base}/api/v4/projects/{quote(str(project), safe='')}/issues"
            payload = {"title": title, "description": body}
            if dry_run:
                return {"tracker": tracker, "dry_run": {"url": url, "payload": payload},
                        "finding_id": finding_id}
            token = os.environ.get("GITLAB_TOKEN")
            if not token:
                return {"error": "GITLAB_TOKEN not set in environment"}
            headers = {"PRIVATE-TOKEN": token}
            url_key = "web_url"

        else:  # jira
            if not project:
                return {"error": "jira requires project=<PROJECT KEY>"}
            base = os.environ.get("JIRA_URL", "").rstrip("/")
            url = f"{base}/rest/api/2/issue"
            payload = {"fields": {
                "project": {"key": project},
                "summary": title,
                "description": body,
                "issuetype": {"name": "Bug"},
            }}
            if dry_run:
                return {"tracker": tracker, "dry_run": {"url": url, "payload": payload},
                        "finding_id": finding_id}
            if not base:
                return {"error": "JIRA_URL not set in environment"}
            user = os.environ.get("JIRA_USER")
            if not user:
                return {"error": "JIRA_USER not set in environment"}
            token = os.environ.get("JIRA_TOKEN")
            if not token:
                return {"error": "JIRA_TOKEN not set in environment"}
            basic = base64.b64encode(f"{user}:{token}".encode()).decode()
            headers = {"Authorization": f"Basic {basic}",
                       "Content-Type": "application/json"}
            url_key = None  # jira returns a key, not a URL

        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.post(url, headers=headers, json=payload)
        except httpx.HTTPError as e:
            return {"error": f"{type(e).__name__}: {e}"}
        if r.status_code >= 300:
            return {"error": f"{tracker} HTTP {r.status_code}: {r.text[:300]}"}

        try:
            resp = r.json()
        except ValueError:
            resp = {}
        if tracker == "jira":
            key = resp.get("key", "")
            issue_url = f"{base}/browse/{key}" if key else resp.get("self", "")
        else:
            issue_url = resp.get(url_key, "")
        return {"tracker": tracker, "issue_url": issue_url, "finding_id": finding_id}
