"""External recon tool orchestration — subfinder, nuclei, katana, ffuf, sqlmap, nmap, dalfox.

Tools split across submodules by purpose:
  - inventory: check_recon_tools, probe_hosts
  - subdomain: run_subfinder
  - crawling: run_katana
  - scanning: run_nuclei, run_dalfox, run_ffuf, run_sqlmap
  - network: run_nmap
  - pipeline: run_recon_pipeline
"""

from mcp.server.fastmcp import FastMCP

from . import inventory, subdomain, crawling, scanning, network, pipeline


def register(mcp: FastMCP):
    inventory.register(mcp)
    subdomain.register(mcp)
    crawling.register(mcp)
    scanning.register(mcp)
    network.register(mcp)
    pipeline.register(mcp)
