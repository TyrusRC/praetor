"""Recon inventory tools: check installed tools and probe live hosts."""

import asyncio
import socket

from mcp.server.fastmcp import FastMCP

from ._common import _check_tool
from .scanning import detect_seclists


def register(mcp: FastMCP):

    @mcp.tool()
    async def check_recon_tools() -> str:
        """Check which external recon tools are installed on this system."""
        # Web-focused recon tools only. Network-layer tools like nmap are excluded —
        # their traffic can't route through Burp's HTTP proxy.
        tools = {
            "subfinder": "Subdomain enumeration (passive)",
            "nuclei": "Template-based vulnerability scanner",
            "katana": "Web crawler / URL discovery",
            "ffuf": "Directory/parameter brute-forcing",
            "dalfox": "XSS scanner",
            "sqlmap": "SQL injection automation",
            "gau": "URL extraction from web archives",
            "waybackurls": "Wayback Machine URL extraction",
            "amass": "Subdomain enumeration (active + passive)",
            "wpscan": "WordPress vulnerability scanner",
            "opengrep": "SAST engine (Semgrep fork) — audit_crawled_artifacts / run_opengrep_source",
            "gitleaks": "Git history secret detection",
            "trufflehog": "Secret detection + live verification (800+ detectors)",
            "git-dumper": "Reconstruct .git from exposed dir listing (chains with discover_common_files)",
            "noir": "Source-tree attack-surface extractor (Crystal binary) — import_scope --noir-json",
        }

        # Check DNS resolution off the event loop — getaddrinfo is blocking.
        def _dns_check() -> bool:
            try:
                socket.getaddrinfo("example.com", 443, proto=socket.IPPROTO_TCP)
                return True
            except socket.gaierror:
                return False

        dns_ok = await asyncio.to_thread(_dns_check)

        lines = ["External Recon Tools:", ""]
        if not dns_ok:
            lines.append("WARNING: DNS resolution is broken. Go-based tools (katana, nuclei, subfinder)")
            lines.append("will fail. Fix: ensure /etc/resolv.conf has a reachable nameserver.")
            lines.append("For WSL: sudo bash -c 'echo nameserver $(ip route show default | awk \"{print \\$3}\") > /etc/resolv.conf'")
            lines.append("")

        available = []
        missing = []

        for tool, desc in tools.items():
            if _check_tool(tool):
                available.append(f"  [installed] {tool} — {desc}")
            else:
                missing.append(f"  [missing]   {tool} — {desc}")

        if available:
            lines.append(f"Available ({len(available)}):")
            lines.extend(available)
        if missing:
            lines.append(f"\nNot installed ({len(missing)}):")
            lines.extend(missing)

        lines.append(f"\nTotal: {len(available)}/{len(tools)} tools available")

        sl = detect_seclists()
        lines.append("")
        lines.append("Wordlists:")
        if sl:
            lines.append(f"  SecLists: {sl}")
        else:
            lines.append("  SecLists: NOT FOUND")
            lines.append("    Install: git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/SecLists")
            lines.append("    Then: export SECLISTS_PATH=/opt/SecLists")

        if missing:
            lines.append("\nInstall commands:")
            lines.append("  # ProjectDiscovery tools")
            lines.append("  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            lines.append("  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            lines.append("  CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest")
            lines.append("  # Other Go tools")
            lines.append("  go install -v github.com/hahwul/dalfox/v2@latest")
            lines.append("  go install -v github.com/lc/gau/v2/cmd/gau@latest")
            lines.append("  go install -v github.com/tomnomnom/waybackurls@latest")
            lines.append("  # Praetor v1.0 — SAST + secrets layer")
            lines.append("  brew install opengrep        # or:  curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash")
            lines.append("  brew install gitleaks        # or:  go install github.com/gitleaks/gitleaks/v8@latest")
            lines.append("  brew install trufflehog      # or:  go install github.com/trufflesecurity/trufflehog/v3@latest")
            lines.append("  pip install git-dumper       # or:  pipx install git-dumper")
            lines.append("  # OWASP Noir (Crystal binary)")
            lines.append("  brew install noir-cr/noir/noir  # or build from https://github.com/owasp-noir/noir")

        return "\n".join(lines)

    @mcp.tool()
    async def probe_hosts(
        targets: list[str],
        timeout: int = 30,
    ) -> str:
        """Probe live hosts from a list of URLs/domains via Burp's HTTP client.

        Args:
            targets: List of URLs or domains to probe
            timeout: Max seconds per target (default 30)
        """
        from burpsuite_mcp import client

        results = []
        for target in targets:
            url = target if "://" in target else f"https://{target}"
            data = await client.post("/api/http/curl", json={
                "url": url, "method": "GET",
            })
            if "error" not in data:
                status = data.get("status_code", 0)
                length = len(data.get("response_body", ""))
                headers = data.get("response_headers", [])
                server = next((h["value"] for h in headers if h["name"].lower() == "server"), "")
                tech = next((h["value"] for h in headers if h["name"].lower() == "x-powered-by"), "")
                info = f"[{status}]"
                if server:
                    info += f" [{server}]"
                if tech:
                    info += f" [{tech}]"
                results.append(f"  {url} {info} ({length} bytes)")
            else:
                results.append(f"  {url} [FAILED] {data['error'][:100]}")

        if not results:
            return "No targets provided"

        lines = [f"Live hosts ({len(results)}/{len(targets)}):", ""]
        lines.extend(results)
        return "\n".join(lines)
