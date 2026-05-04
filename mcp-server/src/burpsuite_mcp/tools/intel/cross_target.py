"""lookup_cross_target_patterns — surface attack patterns from other targets."""

import asyncio
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from ._internals import _intel_root


def register(mcp: FastMCP):

    @mcp.tool()
    async def lookup_cross_target_patterns(
        tech_stack: list[str],
        vuln_class: str = "",
    ) -> str:
        """Find attack patterns from other targets with overlapping tech stack.

        Args:
            tech_stack: Current target's tech stack
            vuln_class: Optional filter by vulnerability class
        """
        intel_root = _intel_root()
        if not intel_root.exists():
            return "No target intel stored yet."

        tech_lower = {t.lower() for t in tech_stack}

        def _scan() -> list[tuple[Path, dict, dict]]:
            """Return (domain_dir, profile, patterns) for every overlapping target."""
            out: list[tuple[Path, dict, dict]] = []
            for domain_dir in intel_root.iterdir():
                if not domain_dir.is_dir():
                    continue
                profile_path = domain_dir / "profile.json"
                if not profile_path.exists():
                    continue
                try:
                    profile = json.loads(profile_path.read_text())
                except (json.JSONDecodeError, OSError):
                    continue
                other_tech = profile.get("tech_stack", []) + profile.get("frameworks", [])
                if not (tech_lower & {t.lower() for t in other_tech}):
                    continue
                patterns_path = domain_dir / "patterns.json"
                patterns: dict = {}
                if patterns_path.exists():
                    try:
                        patterns = json.loads(patterns_path.read_text())
                    except (json.JSONDecodeError, OSError):
                        patterns = {}
                out.append((domain_dir, profile, patterns))
            return out

        scanned = await asyncio.to_thread(_scan)
        matches = []

        for domain_dir, profile, patterns_data in scanned:
            other_tech = profile.get("tech_stack", []) + profile.get("frameworks", [])
            overlap = tech_lower & {t.lower() for t in other_tech}
            for pattern in patterns_data.get("patterns", []):
                if vuln_class and pattern.get("vuln_class", "").lower() != vuln_class.lower():
                    continue
                matches.append({
                    "source_domain": domain_dir.name,
                    "tech_overlap": list(overlap),
                    **pattern,
                })

        if not matches:
            msg = f"No matching patterns found for tech: {', '.join(tech_stack)}"
            if vuln_class:
                msg += f" (filtered by: {vuln_class})"
            return msg

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        matches.sort(key=lambda m: (
            sev_order.get(m.get("severity", "low").lower(), 4),
            m.get("timestamp", ""),
        ))

        lines = [f"Cross-target patterns ({len(matches)} matches):", ""]
        for m in matches[:20]:
            lines.append(f"  [{m.get('severity', '?').upper()}] {m.get('vuln_class', '?')}: {m.get('technique', '?')}")
            lines.append(f"    Source: {m['source_domain']} (overlap: {', '.join(m['tech_overlap'])})")
            if m.get("payload"):
                lines.append(f"    Payload: {m['payload'][:100]}")
            if m.get("endpoint_pattern"):
                lines.append(f"    Endpoint: {m['endpoint_pattern']}")
            if m.get("notes"):
                lines.append(f"    Notes: {m['notes'][:150]}")
            lines.append("")

        if len(matches) > 20:
            lines.append(f"  ... and {len(matches) - 20} more patterns")

        return "\n".join(lines)
