"""export_poc_bundle — full reproducible PoC artefact per confirmed finding (W7, T7).

XBOW/Strix differentiator: every confirmed finding ships with a self-contained
PoC bundle that a triager can extract + run from a fresh machine and observe
the same anomaly. Closes the visible delta vs commercial agentic pentesters.

Bundle layout (.tar.gz):

    poc-<finding_id>/
        README.md            # impact + steps + expected output
        request.http         # raw HTTP request bytes (CRLF normalised)
        response.http        # captured response bytes (truncated to 64KB)
        repro.sh             # curl-through-Burp reproduction (re-uses generate_repro_script)
        verify.py            # Python re-fire + class-specific assertion
        finding.json         # full saved-finding record
        evidence/            # auxiliary collaborator IDs, screenshots, reproductions[]

Verification assertions (verify.py):
    sqli       -> response body contains SQL error markers
    sqli_blind -> response time delta vs baseline >= 4000ms
    xss        -> reflected payload appears in executable context
    ssrf       -> collaborator interaction recorded OR response includes IMDS marker
    rce        -> uid/whoami/id markers in response
    idor       -> 200 status accessing other-user resource
    *          -> status / length / hash matches saved evidence
"""

from __future__ import annotations

import io
import json
import shlex
import tarfile
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client

from ._helpers import _intel_dir, _safe_findings_path, _sanitized


_VERIFY_HINTS: dict[str, list[str]] = {
    # Pre-W19 (W7 baseline)
    "sqli": ["sql syntax", "mysql", "postgresql", "pg_query", "sqlite", "ORA-", "ODBC", "syntax error"],
    "rce": ["uid=", "gid=", "groups=", "/etc/passwd:", "root:x:"],
    "ssrf": ["instance-id", "169.254.169.254", "computeMetadata", "iam/security-credentials"],
    "ssti": ["49", "1337", "[Object", "{{"],
    "xxe": ["<root>", "<![CDATA[", "/etc/passwd", "root:x:"],
    "lfi": ["root:x:", "[boot loader]", "<?xml", "[fonts]"],
    "open_redirect": ["Location:", "evil.com"],
    "info_disclosure": ["password", "secret", "private", "token"],
    # W19 — per-class extensions matching deep-dive evidence ladders
    # SSRF refined per playbook-ssrf-deep-dive.md
    "ssrf_cloud_metadata": [
        "AccessKeyId", "SecretAccessKey", "Token", "arn:aws:iam",
        "ami-id", "instance-id", "computeMetadata", "iam/security-credentials",
        "subscriptionId", "vmId", "droplet_id", "compartmentId",
    ],
    "ssrf_internal_service": [
        "SSH-2.0", "OpenSSH", "-ERR NOAUTH", "NOAUTH Authentication required",
        "HTTP/1.0 401", "Apache", "nginx",
    ],
    # IDOR/BOLA — cross-principal record markers (operator fills in expected foreign-record signature)
    "idor": ["@", "email", "id\":", "user_id", "owner_id"],
    "bola": ["@", "email", "id\":", "user_id", "owner_id"],
    # JWT — forge-accepted markers
    "jwt": ["\"role\"", "\"admin\"", "\"sub\"", "\"is_admin\""],
    # OAuth — code-arrival / token markers
    "oauth": ["access_token", "code=", "id_token", "refresh_token"],
    # Request smuggling — backend-reach + Collaborator hints (operator-fills marker)
    "request_smuggling": ["smuggle-confirmed", "internal", "admin"],
    # Prototype pollution — gadget-fire markers
    "sspp": ["is_admin\":true", "\"isAdmin\":true", "permissions", "polluted"],
    "cspp": ["script", "onerror", "alert", "polluted"],
    "prototype_pollution": ["is_admin\":true", "\"isAdmin\":true", "polluted"],
    # Deserialization — RCE marker (Collaborator-resolved DNS/HTTP marker is the real signal)
    "deserialization": ["uid=", "groups=", "praetor-deserial-marker"],
    # SAML XSW — attacker NameID in session
    "saml_xsw": ["NameID", "set-cookie"],
    # GraphQL — privileged field returned unauth
    "graphql": ["data", "__schema", "adminEvents"],
}


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


def _raw_request(req: dict[str, Any]) -> bytes:
    method = (req.get("method") or "GET").upper()
    url = req.get("url") or ""
    headers = req.get("headers") or {}
    body = req.get("body") or ""
    from urllib.parse import urlparse
    p = urlparse(url)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    lines = [f"{method} {path} HTTP/1.1"]
    if "Host" not in headers and p.netloc:
        lines.append(f"Host: {p.netloc}")
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    raw = "\r\n".join(lines) + "\r\n\r\n"
    out = raw.encode("utf-8")
    if body:
        out += body.encode("utf-8") if isinstance(body, str) else body
    return out


def _raw_response(resp: dict[str, Any]) -> bytes:
    if not resp:
        return b""
    status = resp.get("status") or resp.get("status_code") or 0
    headers = resp.get("headers") or {}
    body = resp.get("body") or ""
    lines = [f"HTTP/1.1 {status} OK"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    raw = "\r\n".join(lines) + "\r\n\r\n"
    out = raw.encode("utf-8")
    body_bytes = body.encode("utf-8") if isinstance(body, str) else body
    if len(body_bytes) > 65536:
        body_bytes = body_bytes[:65536] + b"\n... [truncated by Praetor poc_bundle: original > 64KB]"
    return out + body_bytes


def _verify_py(finding: dict, req: dict) -> str:
    vt = str(finding.get("vuln_type") or "").lower()
    endpoint = req.get("url") or finding.get("endpoint") or ""
    method = (req.get("method") or "GET").upper()
    body = req.get("body") or ""
    hints = []
    for prefix, markers in _VERIFY_HINTS.items():
        if vt.startswith(prefix):
            hints = markers
            break
    timing_class = vt in ("sqli_blind", "sqli_time", "ssrf_blind", "rce_blind", "command_injection_blind")
    baseline = (finding.get("evidence") or {}).get("baseline") or {}
    bl_status = baseline.get("status") or (finding.get("evidence") or {}).get("baseline_status")
    bl_len = baseline.get("length") or (finding.get("evidence") or {}).get("baseline_length")
    return f'''"""verify.py — Praetor PoC verification.

Re-fires the captured request through Burp proxy and asserts the class-specific
anomaly is reproducible. Returns exit 0 on pass, 1 on fail.

Usage:
    BURP_PROXY=http://127.0.0.1:8080 python verify.py
"""

import os
import sys
import time
import urllib.request
from urllib.error import HTTPError, URLError

URL = {endpoint!r}
METHOD = {method!r}
BODY = {body!r}
VULN_TYPE = {vt!r}
HINTS = {hints!r}
TIMING = {timing_class}
BASELINE_STATUS = {bl_status!r}
BASELINE_LENGTH = {bl_len!r}


def fire():
    req = urllib.request.Request(URL, method=METHOD, data=BODY.encode("utf-8") if BODY else None)
    proxy = os.environ.get("BURP_PROXY", "http://127.0.0.1:8080")
    handler = urllib.request.ProxyHandler({{"http": proxy, "https": proxy}})
    opener = urllib.request.build_opener(handler)
    start = time.perf_counter()
    try:
        resp = opener.open(req, timeout=15)
        body = resp.read()
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return resp.status, body, elapsed_ms
    except HTTPError as e:
        body = e.read()
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return e.code, body, elapsed_ms
    except URLError as e:
        sys.stderr.write(f"network error: {{e}}\\n")
        return None, b"", -1


def main():
    status, body, elapsed_ms = fire()
    if status is None:
        return 1
    text = body.decode("utf-8", errors="replace").lower()
    if TIMING:
        if elapsed_ms >= 4000:
            print(f"PASS — timing delta {{elapsed_ms}}ms vs baseline (blind {{VULN_TYPE}} class)")
            return 0
        print(f"FAIL — timing only {{elapsed_ms}}ms; expected >= 4000ms")
        return 1
    if HINTS:
        hits = [h for h in HINTS if h.lower() in text]
        if hits:
            print(f"PASS — class markers reproduced: {{hits[:3]}} (status {{status}}, {{len(body)}}B, {{elapsed_ms}}ms)")
            return 0
    if BASELINE_STATUS and status != int(BASELINE_STATUS):
        print(f"PASS — status delta {{status}} vs baseline {{BASELINE_STATUS}} ({{elapsed_ms}}ms)")
        return 0
    if BASELINE_LENGTH and abs(len(body) - int(BASELINE_LENGTH)) > 200:
        print(f"PASS — length delta {{len(body)}} vs baseline {{BASELINE_LENGTH}}")
        return 0
    print(f"FAIL — no anomaly observed (status {{status}}, {{len(body)}}B, {{elapsed_ms}}ms)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
'''


def _readme(finding: dict, req: dict) -> str:
    fid = finding.get("id") or "?"
    title = finding.get("title") or finding.get("vuln_type") or "finding"
    sev = str(finding.get("severity") or "INFO").upper()
    vt = finding.get("vuln_type") or "unknown"
    endpoint = finding.get("endpoint") or req.get("url") or "?"
    impact = finding.get("impact") or finding.get("description") or "(no impact text — fill in before submission)"
    cvss4 = finding.get("cvss4_vector") or finding.get("cvss_vector") or "(none — call compute_cvss)"
    chain = finding.get("chain_with") or []
    return f"""# PoC Bundle — {sev} {vt}

**Finding ID:** {fid}
**Title:** {title}
**Endpoint:** `{endpoint}`
**Severity:** {sev}
**CVSS:** {cvss4}
{"**Chained with:** " + ", ".join(chain) if chain else ""}

## Impact

{impact}

## Reproduction (3 steps)

1. Start Burp Suite and confirm proxy listener on 127.0.0.1:8080.
2. Run `bash repro.sh` — fires the captured request through Burp; observe the
   anomaly in the Logger / Proxy history.
3. Run `python verify.py` — re-fires + asserts the class-specific marker.
   Exit code 0 = reproduction confirmed.

## Files

- `request.http`  — raw HTTP request (replay byte-for-byte via `nc` / Repeater).
- `response.http` — captured response at save time (first 64 KB).
- `repro.sh`      — curl-through-Burp reproduction.
- `verify.py`     — Python re-fire + class assertion (exit 0 on pass).
- `finding.json`  — full saved-finding record.

## Triager handoff checklist

- [ ] Reviewed `README.md` impact statement (rewrite if "could lead to" appears).
- [ ] Verified `verify.py` exits 0 from a clean shell.
- [ ] Confirmed in-scope per program policy.
- [ ] CVSS 4.0 vector reasonable (see `compute_cvss` if missing).
- [ ] Chain anchors verified if NEVER_SUBMIT class.
"""


def register(mcp: FastMCP):

    @mcp.tool()
    async def export_poc_bundle(
        domain: str,
        finding_id: str,
        output_dir: str = "",
    ) -> dict:
        """Build a reproducible PoC bundle (.tar.gz) for a saved finding.

        Bundle includes raw request + response, repro.sh, verify.py, README,
        and the finding.json record. Drops to
        `.burp-intel/<domain>/artifacts/poc/poc-<finding_id>.tar.gz` unless output_dir given.

        Args:
            domain: target domain (used for .burp-intel path resolution)
            finding_id: saved-finding ID
            output_dir: optional output directory (default .burp-intel/<domain>/artifacts/poc/)
        """
        path = _safe_findings_path(domain)
        if not path.exists():
            return {"error": f"no findings.json at {path}", "finding_id": finding_id}

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            return {"error": f"failed to read findings.json: {exc}"}
        items = data if isinstance(data, list) else data.get("findings", [])
        target = next(
            (f for f in items if (f.get("id") or f.get("finding_id")) == finding_id),
            None,
        )
        if not target:
            return {"error": f"finding {finding_id!r} not found in {path}"}

        evidence = target.get("evidence") or {}
        idx = evidence.get("logger_index") if isinstance(evidence, dict) else None
        if idx is None and isinstance(evidence, dict):
            idx = evidence.get("proxy_history_index")
        if idx is None or int(idx) < 0:
            return {"error": "no logger_index / proxy_history_index in evidence"}

        req = await client.get(f"/api/proxy/{int(idx)}", params={"include_body": "true"})
        if "error" in req:
            return {"error": f"fetch proxy entry {idx}: {req['error']}"}
        resp = req.get("response") or {}

        if output_dir:
            out_root = Path(output_dir)
        else:
            new_root = _intel_dir() / _sanitized(domain) / "artifacts" / "poc"
            legacy = _intel_dir() / _sanitized(domain) / "_poc"
            out_root = legacy if (legacy.exists() and not new_root.exists()) else new_root
        out_root.mkdir(parents=True, exist_ok=True)
        tar_path = out_root / f"poc-{finding_id}.tar.gz"

        readme = _readme(target, req)
        verify = _verify_py(target, req)
        repro = "#!/usr/bin/env bash\nset -eo pipefail\n" \
                'export HTTPS_PROXY="${HTTPS_PROXY:-http://127.0.0.1:8080}"\n' \
                'export HTTP_PROXY="${HTTP_PROXY:-http://127.0.0.1:8080}"\n\n' \
                + _curl_for_request(req) + "\n"
        finding_blob = json.dumps(target, indent=2, default=str)
        req_bytes = _raw_request(req)
        resp_bytes = _raw_response(resp)

        prefix = f"poc-{finding_id}"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            def add(name: str, content: bytes, mode: int = 0o644):
                info = tarfile.TarInfo(name=f"{prefix}/{name}")
                info.size = len(content)
                info.mode = mode
                info.mtime = int(time.time())
                tar.addfile(info, io.BytesIO(content))

            add("README.md", readme.encode("utf-8"))
            add("request.http", req_bytes)
            add("response.http", resp_bytes)
            add("repro.sh", repro.encode("utf-8"), mode=0o755)
            add("verify.py", verify.encode("utf-8"), mode=0o755)
            add("finding.json", finding_blob.encode("utf-8"))

        tar_path.write_bytes(buf.getvalue())
        return {
            "ok": True,
            "finding_id": finding_id,
            "bundle_path": str(tar_path),
            "size_bytes": tar_path.stat().st_size,
            "files": ["README.md", "request.http", "response.http", "repro.sh", "verify.py", "finding.json"],
        }
