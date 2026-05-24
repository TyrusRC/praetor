"""Software-composition analysis wrappers — osv-scanner, trivy, grype.

All three are MIT/Apache OSS scanners. Each falls back to install-hint when
binary absent. SBOM-driven (syft optional upstream).
"""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd


def _hint(tool: str, hint: str) -> str:
    return f"Error: {tool} not installed.\nInstall: {hint}"


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_osv_scanner(path: str, timeout: int = 600) -> str:
        """Scan a path (lockfile / dir / SBOM) against OSV.dev via osv-scanner.

        Args:
            path: lockfile, directory, container image, or SBOM file.
            timeout: seconds.
        """
        if not _check_tool("osv-scanner"):
            return _hint("osv-scanner",
                         "go install github.com/google/osv-scanner/cmd/osv-scanner@v2")
        out, err, rc = await _run_cmd(
            ["osv-scanner", "--format", "json", path],
            timeout=timeout, bypass_proxy=True,
        )
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            data = {}
        vulns: list[dict] = []
        for r in data.get("results", []):
            src = r.get("source", {}).get("path", path)
            for pkg in r.get("packages", []):
                name = pkg.get("package", {}).get("name", "?")
                version = pkg.get("package", {}).get("version", "?")
                for v in pkg.get("vulnerabilities", []):
                    vulns.append({
                        "id": v.get("id", "?"),
                        "summary": (v.get("summary") or "")[:120],
                        "package": f"{name}@{version}",
                        "source": src,
                    })
        lines = [f"osv-scanner: {len(vulns)} vulns in {path}"]
        for v in vulns[:50]:
            lines.append(f"  [{v['id']}] {v['package']} -- {v['summary']}")
        if rc != 0 and not vulns:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_trivy(
        target: str,
        mode: str = "fs",
        severity: str = "HIGH,CRITICAL",
        timeout: int = 600,
    ) -> str:
        """Scan a target via trivy (Aqua).

        Args:
            target: path | image | git-url | k8s-cluster.
            mode: fs | image | repo | k8s | sbom | config (IaC).
            severity: comma list (LOW,MEDIUM,HIGH,CRITICAL,UNKNOWN).
            timeout: seconds.
        """
        if not _check_tool("trivy"):
            return _hint("trivy",
                         "brew install aquasecurity/trivy/trivy  |  "
                         "https://github.com/aquasecurity/trivy/releases")
        if mode not in {"fs", "image", "repo", "k8s", "sbom", "config"}:
            return f"Error: mode must be fs|image|repo|k8s|sbom|config (got {mode!r})."
        cmd = ["trivy", mode, "--severity", severity, "--format", "json", "--quiet", target]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            data = {}
        rows: list[dict] = []
        for r in data.get("Results", []) or []:
            for v in r.get("Vulnerabilities", []) or []:
                rows.append({
                    "id": v.get("VulnerabilityID", "?"),
                    "sev": v.get("Severity", "?"),
                    "pkg": f"{v.get('PkgName','?')}@{v.get('InstalledVersion','?')}",
                    "title": (v.get("Title") or v.get("Description") or "")[:120],
                })
        lines = [f"trivy [{mode}]: {len(rows)} findings in {target} (severity={severity})"]
        for r in rows[:50]:
            lines.append(f"  [{r['sev']:<8}] {r['id']}  {r['pkg']} -- {r['title']}")
        if rc != 0 and not rows:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_grype(target: str, timeout: int = 600) -> str:
        """Scan an image / dir / SBOM via grype (Anchore).

        Args:
            target: image:tag | dir:./path | sbom:./bom.json.
            timeout: seconds.
        """
        if not _check_tool("grype"):
            return _hint("grype",
                         "brew install grype  |  https://github.com/anchore/grype#installation")
        out, err, rc = await _run_cmd(
            ["grype", target, "-o", "json", "-q"],
            timeout=timeout, bypass_proxy=True,
        )
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            data = {}
        rows: list[dict] = []
        for m in data.get("matches", []) or []:
            v = m.get("vulnerability", {})
            a = m.get("artifact", {})
            rows.append({
                "id": v.get("id", "?"),
                "sev": v.get("severity", "?"),
                "pkg": f"{a.get('name','?')}@{a.get('version','?')}",
            })
        lines = [f"grype: {len(rows)} findings in {target}"]
        for r in rows[:50]:
            lines.append(f"  [{r['sev']:<8}] {r['id']}  {r['pkg']}")
        if rc != 0 and not rows:
            lines.append(f"[rc={rc}] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_syft(
        target: str,
        output_format: str = "cyclonedx-json",
        timeout: int = 600,
    ) -> str:
        """Generate SBOM via syft (Anchore).

        Args:
            target: image:tag | dir:./path | file:./binary.
            output_format: cyclonedx-json | spdx-json | syft-json | table.
            timeout: seconds.
        """
        if not _check_tool("syft"):
            return _hint("syft",
                         "brew install syft  |  https://github.com/anchore/syft#installation")
        out, err, rc = await _run_cmd(
            ["syft", target, "-o", output_format, "-q"],
            timeout=timeout, bypass_proxy=True,
        )
        if output_format.endswith("json") and out.strip():
            try:
                data = json.loads(out)
                comps = data.get("components") or data.get("artifacts") or []
                lines = [f"syft: {len(comps)} components in {target} ({output_format})"]
                for c in comps[:40]:
                    name = c.get("name") or "?"
                    ver = c.get("version") or "?"
                    typ = c.get("type") or "?"
                    lines.append(f"  {typ:<12} {name}@{ver}")
                lines.append("")
                lines.append("Full SBOM in stdout above; pipe to file with --output-file.")
                if rc != 0 and not comps:
                    lines.append(f"[rc={rc}] {err[:200]}")
                return "\n".join(lines)
            except json.JSONDecodeError:
                pass
        tail = "\n".join(out.splitlines()[:60])
        lines = [f"syft [{output_format}] rc={rc}", tail]
        if rc != 0:
            lines.append(f"[stderr] {err[:200]}")
        return "\n".join(lines)

    @mcp.tool()
    async def run_cosign_verify(
        image: str,
        public_key: str = "",
        certificate_identity: str = "",
        certificate_issuer: str = "",
        timeout: int = 120,
    ) -> str:
        """Verify a container signature via cosign (Sigstore).

        Args:
            image: image:tag or image@sha256:...
            public_key: path to public key (--key); empty -> keyless via Fulcio.
            certificate_identity: required for keyless mode (Fulcio cert SAN).
            certificate_issuer: required for keyless mode (Fulcio OIDC issuer).
            timeout: seconds.
        """
        if not _check_tool("cosign"):
            return _hint("cosign",
                         "brew install cosign  |  https://github.com/sigstore/cosign/releases")
        cmd = ["cosign", "verify", image]
        if public_key:
            cmd += ["--key", public_key]
        else:
            if not (certificate_identity and certificate_issuer):
                return ("Error: keyless mode needs --certificate-identity and "
                        "--certificate-issuer. Provide both or supply public_key.")
            cmd += ["--certificate-identity", certificate_identity,
                    "--certificate-oidc-issuer", certificate_issuer]
        out, err, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        status = "VERIFIED" if rc == 0 else "FAILED"
        lines = [f"cosign verify [{image}]: {status}"]
        if rc == 0:
            lines.append(out.strip()[:600])
        else:
            lines.append(f"[rc={rc}] {(err or out)[:600]}")
        return "\n".join(lines)
