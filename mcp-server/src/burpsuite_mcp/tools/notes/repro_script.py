"""Auto-PoC repro.sh generator from a saved finding's logger_index.

Triager handoff quality: every confirmed finding gets a runnable shell script
that reproduces the request through Burp's proxy. Closes the visible
delta vs XBOW/Strix who ship reproducible PoCs by default.

Pipeline:
    1. Look up the finding by id.
    2. Pull logger_index / proxy_history_index from finding.evidence.
    3. Fetch the captured request via /api/proxy/<index>.
    4. Render a single-file bash script: env + curl invocation that reproduces.
       Operator runs `bash repro.sh` and sees the expected anomaly (status /
       length / latency delta vs baseline already recorded with the finding).
"""

from __future__ import annotations

import shlex
from typing import Any

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def _curl_for_request(req: dict[str, Any]) -> str:
    method = (req.get("method") or "GET").upper()
    url = req.get("url") or ""
    headers = req.get("headers") or {}
    body = req.get("body") or ""

    parts: list[str] = ["curl -sk -i"]
    if method != "GET":
        parts.append(f"-X {shlex.quote(method)}")

    skip = {"host", "content-length", "accept-encoding"}
    for name, value in headers.items():
        if not name or name.lower() in skip:
            continue
        parts.append("-H " + shlex.quote(f"{name}: {value}"))

    if body:
        parts.append("--data-binary " + shlex.quote(body))

    parts.append(shlex.quote(url))
    return " \\\n  ".join(parts)


def _render_repro(finding: dict, req: dict) -> str:
    fid = finding.get("id") or "?"
    title = finding.get("title") or finding.get("vuln_type") or "finding"
    sev = str(finding.get("severity") or "INFO").upper()
    vuln = finding.get("vuln_type") or "unknown"
    endpoint = finding.get("endpoint") or req.get("url") or "?"
    evidence_text = finding.get("evidence_text") or ""

    lines: list[str] = [
        "#!/usr/bin/env bash",
        f"# Praetor reproduction script for finding #{fid}",
        f"# {sev} | {vuln} | {title}",
        f"# Endpoint: {endpoint}",
        "#",
        "# Routes through Burp proxy (127.0.0.1:8080) so the replay lands in",
        "# Logger / Proxy history. Drop --proxy if running outside an engagement box.",
        "",
        "set -eo pipefail",
        "",
        'export HTTPS_PROXY="${HTTPS_PROXY:-http://127.0.0.1:8080}"',
        'export HTTP_PROXY="${HTTP_PROXY:-http://127.0.0.1:8080}"',
        "",
        _curl_for_request(req),
        "",
    ]

    if evidence_text:
        lines += [
            "# Expected anomaly vs baseline (captured at save time):",
            "# " + evidence_text.replace("\n", "\n# "),
            "",
        ]

    return "\n".join(lines)


def register(mcp: FastMCP):

    @mcp.tool()
    async def generate_repro_script(finding_id: str) -> str:
        """Render a runnable bash repro script for a saved finding.

        Reads finding.evidence.logger_index (or proxy_history_index) and emits
        a self-contained curl-through-Burp script. Output is the script text —
        operator pipes to `> repro.sh && bash repro.sh`.

        Args:
            finding_id: Saved-finding ID (string or int)
        """
        flist = await client.get("/api/notes/findings", params={})
        if "error" in flist:
            return f"Error: {flist['error']}"

        target = None
        for f in flist.get("findings", []) or []:
            if str(f.get("id")) == str(finding_id):
                target = f
                break
        if not target:
            return f"Error: finding {finding_id} not found"

        evidence = target.get("evidence") or {}
        idx = (
            evidence.get("logger_index")
            if isinstance(evidence, dict)
            else None
        )
        if idx is None and isinstance(evidence, dict):
            idx = evidence.get("proxy_history_index")
        if idx is None or int(idx) < 0:
            return (
                f"Error: finding {finding_id} has no logger_index / "
                "proxy_history_index — cannot reproduce"
            )

        req = await client.get(f"/api/proxy/{int(idx)}", params={"include_body": "true"})
        if "error" in req:
            return f"Error fetching proxy entry {idx}: {req['error']}"

        return _render_repro(target, req)
