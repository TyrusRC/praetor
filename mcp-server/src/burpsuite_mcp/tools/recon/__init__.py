"""External recon tool orchestration — subfinder, nuclei, katana, ffuf, sqlmap, dalfox.

Tools split across submodules by purpose:
  - inventory: check_recon_tools, probe_hosts
  - subdomain: run_subfinder
  - crawling: run_katana
  - scanning: run_nuclei, run_dalfox, run_ffuf, run_sqlmap
  - pipeline: run_recon_pipeline

These are the HTTP-based recon tools: they route through Burp's proxy (where
applicable) so their traffic appears in Proxy history. Network-layer tools
(nmap, netexec, impacket, ...) are first-class too — they live on the network
lane (tools/network, run_network_recon) because they bypass Burp, not because
they are optional. Nothing in this project is an optional tool; the two lanes
are co-equal.
"""

from mcp.server.fastmcp import FastMCP

from . import inventory, subdomain, crawling, scanning, pipeline


def register(mcp: FastMCP):
    inventory.register(mcp)
    subdomain.register(mcp)
    crawling.register(mcp)
    scanning.register(mcp)
    pipeline.register(mcp)
