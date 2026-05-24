"""trufflehog wrapper — 800+ secret detectors, live-verification flag.

https://github.com/trufflesecurity/trufflehog — AGPL-3.0.

The differentiator vs gitleaks: --only-verified actively checks each
candidate credential against the issuer API to confirm it's live. A verified
finding is HIGH-floor (operator-confirmable) by default. Unverified findings
are MEDIUM by default — still report-worthy but not severity-locked.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp.tools.recon._common import _check_tool, _run_cmd


_VALID_SCAN_TYPES = {"git", "github", "gitlab", "filesystem", "s3", "gcs", "docker", "stdin"}


def _normalize(line: str) -> dict | None:
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def _summarize(findings: list[dict]) -> str:
    if not findings:
        return "trufflehog: 0 findings."

    verified = [f for f in findings if f.get("Verified") is True]
    by_detector: dict[str, int] = {}
    for f in findings:
        d = (f.get("DetectorName") or f.get("detector_name") or "?")
        by_detector[d] = by_detector.get(d, 0) + 1

    lines = [
        f"trufflehog: {len(findings)} findings ({len(verified)} VERIFIED, "
        f"{len(findings) - len(verified)} unverified)"
    ]
    for d, c in sorted(by_detector.items(), key=lambda kv: -kv[1])[:25]:
        lines.append(f"  {c}x {d}")

    if verified:
        lines.append("")
        lines.append("VERIFIED findings (severity floor = HIGH):")
        for f in verified[:10]:
            d = f.get("DetectorName") or "?"
            sm = f.get("SourceMetadata") or {}
            data = sm.get("Data") or {}
            location = (
                data.get("Filesystem", {}).get("file")
                or data.get("Git", {}).get("file")
                or "?"
            )
            redacted = (f.get("Redacted") or "")[:80]
            lines.append(f"  [VERIFIED] {d}  {location}  {redacted}")
    return "\n".join(lines)


def register(mcp: FastMCP) -> None:

    @mcp.tool()
    async def run_trufflehog(
        target: str,
        scan_type: str = "filesystem",
        verify: bool = True,
        timeout: int = 600,
    ) -> str:
        """Run trufflehog against a path / git history / cloud bucket / Docker image.

        Args:
            target: Path, git URL, GitHub org, S3 bucket, etc.
            scan_type: One of git, github, gitlab, filesystem, s3, gcs, docker, stdin
            verify: If True, actively confirm each candidate via issuer API (slower, fewer FPs).
                    Verified findings get severity floor HIGH on save.
            timeout: Max seconds (default 600).
        """
        if not _check_tool("trufflehog"):
            return (
                "Error: trufflehog not installed.\n"
                "Install: brew install trufflehog  |  "
                "https://github.com/trufflesecurity/trufflehog#installation"
            )

        scan_type = scan_type.lower().strip()
        if scan_type not in _VALID_SCAN_TYPES:
            return f"Error: scan_type must be one of {sorted(_VALID_SCAN_TYPES)}"

        if scan_type in {"filesystem"} and not Path(target).exists():
            return f"Error: filesystem path not found: {target}"

        cmd = [
            "trufflehog",
            scan_type,
            "--json",
            "--no-update",
        ]
        if verify:
            cmd.append("--only-verified")
        else:
            cmd.append("--no-verification")
        cmd.append(target)

        stdout, stderr, rc = await _run_cmd(cmd, timeout=timeout, bypass_proxy=True)
        findings: list[dict] = []
        for line in stdout.splitlines():
            f = _normalize(line)
            if f and f.get("DetectorName"):
                findings.append(f)

        summary = _summarize(findings)
        if rc != 0 and not findings:
            summary += f"\n[trufflehog-rc={rc}]\n{stderr[:500]}"
        return f"# trufflehog {scan_type} (verify={verify}) — {shlex.quote(target)}\n\n{summary}"
